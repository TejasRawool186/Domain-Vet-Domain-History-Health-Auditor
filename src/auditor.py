"""
auditor.py - The Brain
Handles forensic analysis: toxic word scanning, safety scoring, tech detection,
DNSBL checks, SSL analysis, and redirect chain detection.
"""
import re
import ssl
import socket
import dns.resolver
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Red Flags that ruin a domain's reputation
TOXIC_KEYWORDS = [
    "casino", "poker", "betting", "viagra", "cialis", "loans", 
    "replica", "watches", "adult", "xxx", "crypto", "giveaway"
]

# Extended toxic keywords for High sensitivity
TOXIC_KEYWORDS_EXTENDED = TOXIC_KEYWORDS + [
    "gambling", "pharma", "pills", "cheap", "discount", "prize",
    "winner", "lottery", "forex", "binary", "trading", "escort",
    "payday", "debt", "weight loss", "diet pills", "miracle"
]

# Tech detection patterns
TECH_PATTERNS = {
    "WordPress": ["wp-content", "wp-includes", "/wp-admin", "wordpress"],
    "Shopify": ["shopify", "cdn.shopify.com", "myshopify"],
    "Wix": ["wix.com", "_wix", "wixsite"],
    "Squarespace": ["squarespace.com", "sqsp.net"],
    "Drupal": ["drupal", "sites/all/", "sites/default/"],
    "Joomla": ["joomla", "/components/com_", "/modules/mod_"],
    "Magento": ["magento", "mage/", "skin/frontend"],
    "Ghost": ["ghost.io", "ghost-url"],
    "Webflow": ["webflow.com", "wf-section"],
    "React": ["react", "_app.js", "__next"],
    "Angular": ["angular", "ng-app", "ng-controller"],
    "Vue.js": ["vue.js", "vue-app", "__vue__"],
    "Next.js": ["_next/static", "__NEXT_DATA__"],
    "Laravel": ["laravel", "csrf-token"],
    "Django": ["csrfmiddlewaretoken", "django"]
}


def calculate_safety_score(whois_data, audit_log):
    """
    Calculate overall safety score based on WHOIS data and audit findings.
    Returns a tuple of (score, list of reasons).
    """
    score = 100
    reasons = []

    # 1. Age Factor
    if whois_data and hasattr(whois_data, 'creation_date') and whois_data.creation_date:
        try:
            now = datetime.now()
            c_date = whois_data.creation_date
            if isinstance(c_date, list):
                c_date = c_date[0]
            
            if hasattr(c_date, 'tzinfo') and c_date.tzinfo is not None:
                from datetime import timezone
                now = datetime.now(timezone.utc)
            
            age_years = (now - c_date).days / 365
            if age_years < 1:
                score -= 10
                reasons.append("⚠️ Domain is very young (< 1 year)")
            elif age_years < 2:
                score -= 5
                reasons.append("⚠️ Domain is relatively new (< 2 years)")
        except Exception:
            pass
    
    # 2. Spam History
    if audit_log.get('toxic_count', 0) > 0:
        penalty = audit_log['toxic_count'] * 15
        score -= penalty
        toxic_words = audit_log.get('toxic_words', [])
        if toxic_words:
            reasons.append(f"🚨 Found {audit_log['toxic_count']} instances of toxic content: {', '.join(toxic_words)}")
        else:
            reasons.append(f"🚨 Found {audit_log['toxic_count']} instances of toxic content.")

    # 3. Volatility (Gaps in history)
    if audit_log.get('volatility') == 'High':
        score -= 20
        reasons.append("⚠️ High Volatility: Domain likely dropped/reset multiple times.")
    elif audit_log.get('volatility') == 'Medium':
        score -= 10
        reasons.append("⚠️ Medium Volatility: Some gaps detected in domain history.")

    # 4. Tech stack changes
    if audit_log.get('tech_changes', 0) > 2:
        score -= 10
        reasons.append("⚠️ Multiple tech stack changes detected - potential compromise indicator.")

    # 5. DNSBL listing
    if audit_log.get('blacklisted', False):
        score -= 30
        blacklist_count = audit_log.get('blacklist_count', 0)
        reasons.append(f"🛑 Domain/IP listed on {blacklist_count} spam blacklist(s).")

    # 6. SSL Issues
    ssl_status = audit_log.get('ssl_status', {})
    if ssl_status.get('error'):
        score -= 10
        reasons.append(f"🔓 SSL Issue: {ssl_status.get('error')}")
    elif ssl_status.get('days_until_expiry', 365) < 30:
        score -= 5
        reasons.append(f"⚠️ SSL certificate expires in {ssl_status.get('days_until_expiry')} days")

    # 7. Domain Expiry Warning
    if audit_log.get('domain_expiring_soon', False):
        score -= 15
        days_left = audit_log.get('days_until_domain_expiry', 0)
        reasons.append(f"⚠️ Domain expires in {days_left} days - potential drop indicator!")

    # 8. Redirect Chain Issues
    if audit_log.get('redirect_count', 0) > 3:
        score -= 10
        reasons.append(f"⚠️ Suspicious redirect chain detected ({audit_log.get('redirect_count')} redirects)")

    # 9. No MX Records
    if audit_log.get('no_mx_records', False):
        score -= 5
        reasons.append("📧 No email (MX) records found - domain may not be actively used")

    return max(0, score), reasons


def scan_text_for_toxins(html_text, sensitivity="Medium"):
    """
    Scan HTML text for toxic keywords.
    Returns list of found bad words based on sensitivity level.
    """
    found = []
    if not html_text:
        return found
    
    if sensitivity == "High":
        keywords = TOXIC_KEYWORDS_EXTENDED
    elif sensitivity == "Low":
        keywords = TOXIC_KEYWORDS[:6]
    else:
        keywords = TOXIC_KEYWORDS
    
    text_lower = html_text.lower()
    for word in keywords:
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, text_lower):
            found.append(word)
    
    return list(set(found))


def detect_tech_stack(html_text):
    """
    Detect the technology stack from HTML content.
    Returns a string indicating the detected technology.
    """
    if not html_text:
        return "Unknown"
    
    text_lower = html_text.lower()
    
    for tech, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in text_lower:
                return tech
    
    return "Static/Custom"


def calculate_volatility(snapshots, creation_date):
    """
    Calculate domain volatility based on archive snapshots and creation date.
    """
    if not snapshots:
        return "Unknown"
    
    if len(snapshots) < 2:
        if creation_date:
            return "High"
        return "Unknown"
    
    gaps = 0
    for i in range(1, len(snapshots)):
        try:
            date1 = datetime.strptime(snapshots[i-1]['date'], '%Y-%m-%d')
            date2 = datetime.strptime(snapshots[i]['date'], '%Y-%m-%d')
            gap_days = abs((date2 - date1).days)
            if gap_days > 730:
                gaps += 1
        except (ValueError, KeyError):
            continue
    
    if gaps >= 2:
        return "High"
    elif gaps == 1:
        return "Medium"
    return "Low"


def check_dnsbl(domain):
    """
    Check if domain/IP is listed on DNS blacklists using pydnsbl.
    Returns dict with blacklist status.
    """
    result = {
        'blacklisted': False,
        'blacklist_count': 0,
        'blacklists': []
    }
    
    try:
        from pydnsbl import DNSBLIpChecker, DNSBLDomainChecker
        
        # Check domain
        domain_checker = DNSBLDomainChecker()
        domain_result = domain_checker.check(domain)
        
        if domain_result.blacklisted:
            result['blacklisted'] = True
            result['blacklist_count'] = len(domain_result.detected_by)
            result['blacklists'] = list(domain_result.detected_by.keys())
        
        # Also try to resolve and check IP
        try:
            ip = socket.gethostbyname(domain)
            ip_checker = DNSBLIpChecker()
            ip_result = ip_checker.check(ip)
            
            if ip_result.blacklisted:
                result['blacklisted'] = True
                result['blacklist_count'] += len(ip_result.detected_by)
                result['blacklists'].extend(list(ip_result.detected_by.keys()))
                result['ip'] = ip
        except socket.gaierror:
            pass
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_ssl_certificate(domain):
    """
    Check SSL certificate validity and expiration.
    Returns dict with SSL status.
    """
    result = {
        'has_ssl': False,
        'valid': False,
        'issuer': None,
        'expires': None,
        'days_until_expiry': None,
        'error': None
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                result['has_ssl'] = True
                result['valid'] = True
                
                # Get issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                result['issuer'] = issuer.get('organizationName', 'Unknown')
                
                # Get expiration
                not_after = cert.get('notAfter')
                if not_after:
                    # Parse SSL date format: 'Mar 15 12:00:00 2025 GMT'
                    expires = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    result['expires'] = expires.strftime('%Y-%m-%d')
                    result['days_until_expiry'] = (expires - datetime.now()).days
                    
    except ssl.SSLCertVerificationError as e:
        result['has_ssl'] = True
        result['valid'] = False
        result['error'] = "Invalid or self-signed certificate"
    except socket.timeout:
        result['error'] = "Connection timeout"
    except ConnectionRefusedError:
        result['error'] = "HTTPS not available (port 443 closed)"
    except socket.gaierror:
        result['error'] = "Domain does not resolve"
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_dns_records(domain):
    """
    Check DNS and MX records for the domain.
    Returns dict with DNS analysis.
    """
    result = {
        'has_a_record': False,
        'has_mx_record': False,
        'has_txt_record': False,
        'a_records': [],
        'mx_records': [],
        'txt_records': [],
        'nameservers': []
    }
    
    try:
        # A Records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            result['has_a_record'] = True
            result['a_records'] = [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        
        # MX Records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result['has_mx_record'] = True
            result['mx_records'] = [str(rdata.exchange) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        
        # TXT Records (SPF, DKIM, etc.)
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            result['has_txt_record'] = True
            result['txt_records'] = [str(rdata) for rdata in answers][:3]  # Limit to 3
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        
        # Nameservers
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            result['nameservers'] = [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_domain_expiry(whois_data):
    """
    Check if domain is expiring soon from WHOIS data.
    Returns dict with expiry analysis.
    """
    result = {
        'expiring_soon': False,
        'expiry_date': None,
        'days_until_expiry': None
    }
    
    try:
        if whois_data and hasattr(whois_data, 'expiration_date') and whois_data.expiration_date:
            exp_date = whois_data.expiration_date
            if isinstance(exp_date, list):
                exp_date = exp_date[0]
            
            now = datetime.now()
            if hasattr(exp_date, 'tzinfo') and exp_date.tzinfo is not None:
                from datetime import timezone
                now = datetime.now(timezone.utc)
            
            days_left = (exp_date - now).days
            result['expiry_date'] = exp_date.strftime('%Y-%m-%d')
            result['days_until_expiry'] = days_left
            
            if days_left < 90:
                result['expiring_soon'] = True
                
    except Exception:
        pass
    
    return result


def check_redirect_chain(domain):
    """
    Check for redirect chains that might indicate malicious behavior.
    Returns dict with redirect analysis.
    """
    import requests
    
    result = {
        'redirect_count': 0,
        'final_url': None,
        'redirect_chain': [],
        'suspicious': False
    }
    
    try:
        # Follow redirects manually to track the chain
        response = requests.get(
            f"https://{domain}",
            timeout=10,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        
        result['redirect_count'] = len(response.history)
        result['final_url'] = response.url
        
        for r in response.history:
            result['redirect_chain'].append({
                'status': r.status_code,
                'url': r.url
            })
        
        # Check for suspicious patterns
        if result['redirect_count'] > 3:
            result['suspicious'] = True
        
        # Check if final domain is completely different
        original_domain = domain.lower().replace('www.', '')
        final_domain = urlparse(response.url).netloc.lower().replace('www.', '')
        
        if original_domain not in final_domain and final_domain not in original_domain:
            result['suspicious'] = True
            result['domain_changed'] = True
            
    except requests.exceptions.SSLError:
        # Try HTTP if HTTPS fails
        try:
            response = requests.get(
                f"http://{domain}",
                timeout=10,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            result['redirect_count'] = len(response.history)
            result['final_url'] = response.url
        except Exception:
            result['error'] = "Could not connect"
    except Exception as e:
        result['error'] = str(e)
    
    return result
