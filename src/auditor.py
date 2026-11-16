"""
auditor.py - Forensic Engine & Health Analysis
Handles forensic analysis: toxic word scanning, safety scoring, tech stack detection,
DNSBL blacklist checks, SSL analysis, DNS & email security (SPF/DMARC/DNSSEC),
PBN/parking footprints, foreign script injection, and historical topic drift.
Zero unicode emojis in audit findings and terminal logs.
"""
import re
import ssl
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse
import dns.resolver

# Core toxic keywords that indicate spam, gambling, or illicit operations
TOXIC_KEYWORDS = [
    "casino", "poker", "betting", "viagra", "cialis", "loans", 
    "replica", "watches", "adult", "xxx", "crypto", "giveaway"
]

# Extended toxic keywords for High sensitivity
TOXIC_KEYWORDS_EXTENDED = TOXIC_KEYWORDS + [
    "gambling", "pharma", "pills", "cheap", "discount", "prize",
    "winner", "lottery", "forex", "binary", "trading", "escort",
    "payday", "debt", "weight loss", "diet pills", "miracle",
    "slots", "roulette", "baccarat", "jackpot", "counterfeit"
]

# Signatures indicating domain parking, broker sale pages, or ad arbitrage
PARKING_SIGNATURES = [
    "bodis.com", "sedoparking", "parkingcrew", "afternic.com",
    "hugedomains.com", "dan.com", "undeveloped.com", "cashparking",
    "domain is for sale", "buy this domain", "inquire about this domain",
    "this domain may be for sale", "parked free, courtesy of", "godaddy domain broker",
    "related searches", "find what you are looking for", "this web page is parked FREE"
]

# Signatures for Private Blog Networks (PBNs) and automated link farms
PBN_PATTERNS = [
    "casino-link", "pbn-theme", "gambling links", "sponsored post directory",
    "article submission directory", "powered by auto-blog", "wpmudev-directory"
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

# Industry / Niche classification definitions
NICHE_RULES = {
    "Technology & SaaS": ["software", "api", "cloud", "developer", "platform", "app", "analytics", "saas", "database", "ai model"],
    "Finance & Web3": ["finance", "banking", "investment", "loan", "fintech", "stock", "portfolio", "wallet", "ledger", "trading"],
    "E-Commerce & Retail": ["cart", "checkout", "shipping", "shop", "store", "product", "catalog", "order", "price", "discount"],
    "Health & Medicine": ["medical", "clinic", "health", "doctor", "therapy", "wellness", "hospital", "patient", "dental", "care"],
    "Media & News": ["news", "magazine", "editorial", "journalism", "article", "author", "podcast", "broadcast", "press"],
    "Real Estate": ["property", "realty", "estate", "realtor", "home", "listing", "mortgage", "apartment", "residential"],
    "Gambling & Casino": ["casino", "slots", "bet", "poker", "roulette", "jackpot", "sportsbook", "wagering", "bonus spin"],
    "Adult Content": ["adult", "xxx", "porn", "escort", "dating", "fetish", "sensual"],
    "Parked & Resale": ["domain is for sale", "buy this domain", "parked free", "inquire about this domain", "afternic", "dan.com"]
}


def get_dns_resolver(timeout=5):
    """
    Get configured DNS resolver with resilient fallback nameservers.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        if not resolver.nameservers:
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    except Exception:
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    return resolver


def scan_text_for_toxins(html_text, sensitivity="Medium"):
    """
    Scan HTML text for toxic keywords.
    Returns unique list of found bad words based on sensitivity level.
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
    
    return sorted(list(set(found)))


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


def detect_foreign_script_injection(html_text, domain):
    """
    Detect foreign language script injections (Japanese, Chinese, Cyrillic)
    typically used in expired domain SEO doorway attacks on Western domains.
    """
    if not html_text:
        return {"injected": False, "scripts": [], "ratio": 0.0}
    
    # Strip HTML tags
    clean_text = re.sub(r'<[^>]+>', ' ', html_text)
    total_len = len(clean_text.strip())
    if total_len < 100:
        return {"injected": False, "scripts": [], "ratio": 0.0}
    
    scripts = []
    cjk_matches = len(re.findall(r'[\u4e00-\u9fff\u3040-\u30ff]', clean_text))
    cyrillic_matches = len(re.findall(r'[\u0400-\u04ff]', clean_text))
    arabic_matches = len(re.findall(r'[\u0600-\u06ff]', clean_text))
    
    ratio = (cjk_matches + cyrillic_matches + arabic_matches) / float(total_len)
    
    if cjk_matches > 40:
        scripts.append("East Asian (Chinese/Japanese)")
    if cyrillic_matches > 40:
        scripts.append("Cyrillic")
    if arabic_matches > 40:
        scripts.append("Arabic")
        
    is_injected = (len(scripts) > 0 and ratio > 0.05)
    return {
        "injected": is_injected,
        "scripts": scripts,
        "ratio": round(ratio, 4)
    }


def classify_content_niche(html_text):
    """
    Classify HTML content into an industry niche based on keyword density.
    """
    if not html_text:
        return "Uncategorized"
    
    clean_text = re.sub(r'<[^>]+>', ' ', html_text).lower()
    scores = {}
    
    for niche, keywords in NICHE_RULES.items():
        score = 0
        for kw in keywords:
            score += len(re.findall(r'\b' + re.escape(kw) + r'\b', clean_text))
        if score > 0:
            scores[niche] = score
            
    if not scores:
        return "General / Portfolio"
    
    best_niche = max(scores.items(), key=lambda x: x[1])
    return best_niche[0] if best_niche[1] >= 2 else "General / Portfolio"


def detect_pbn_and_parking(snapshots, dns_result=None):
    """
    Inspect snapshots and nameservers for domain parking signatures and PBN patterns.
    """
    parking_dates = []
    pbn_indicators = []
    
    # Check DNS nameservers for known parking providers
    nameservers = (dns_result or {}).get('nameservers', [])
    for ns in nameservers:
        ns_lower = ns.lower()
        for p_sig in PARKING_SIGNATURES:
            if p_sig in ns_lower:
                parking_dates.append(f"Current DNS ({ns})")
                break
                
    for snap in snapshots:
        html = snap.get('raw_html', '') or snap.get('text', '') or ''
        html_lower = html.lower()
        date = snap.get('date', 'Unknown')
        
        # Check parking
        for sig in PARKING_SIGNATURES:
            if sig in html_lower:
                parking_dates.append(f"{date} (Signature: {sig})")
                break
                
        # Check PBN
        for pat in PBN_PATTERNS:
            if pat in html_lower:
                pbn_indicators.append(f"{date}: Detected {pat}")
                
    is_parked = len(parking_dates) > 0
    pbn_detected = len(pbn_indicators) > 0
    
    pbn_risk_score = 0
    if is_parked:
        pbn_risk_score += 35
    if pbn_detected:
        pbn_risk_score += 45
        
    return {
        "is_parked": is_parked,
        "parking_events": parking_dates,
        "pbn_detected": pbn_detected,
        "pbn_indicators": pbn_indicators,
        "pbn_risk_score": min(100, pbn_risk_score)
    }


def analyze_topic_drift(snapshots):
    """
    Analyze historical topic drift across snapshots.
    A domain jumping across disparate sectors indicates dropped domain acquisition
    or SEO PBN repurposing.
    """
    if not snapshots or len(snapshots) < 2:
        return {
            "drift_level": "Low",
            "drift_score": 0,
            "niches_detected": ["Single Era / Insufficient Snapshots"],
            "description": "Consistent niche profile or insufficient historical snapshots."
        }
    
    niches = []
    for s in snapshots:
        n = s.get('niche')
        if n and n != "Uncategorized":
            niches.append(n)
            
    unique_niches = list(dict.fromkeys(niches))
    drift_count = len(unique_niches)
    
    if drift_count >= 3:
        drift_level = "High"
        drift_score = 75
        desc = "High topic volatility: Domain shifted across 3+ distinct business sectors over its history."
    elif drift_count == 2:
        drift_level = "Moderate"
        drift_score = 35
        desc = "Moderate topic shift detected across historical snapshots."
    else:
        drift_level = "Low"
        drift_score = 10
        desc = "Stable topical focus maintained across historical records."
        
    return {
        "drift_level": drift_level,
        "drift_score": drift_score,
        "niches_detected": unique_niches or ["General"],
        "description": desc
    }


def calculate_volatility(snapshots, creation_date):
    """
    Calculate domain volatility based on archive snapshot continuity and creation date.
    Long multi-year gaps suggest domain dropping and re-registration cycles.
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
            if gap_days > 730:  # Gap of 2+ years
                gaps += 1
        except (ValueError, KeyError):
            continue
    
    if gaps >= 2:
        return "High"
    elif gaps == 1:
        return "Medium"
    return "Low"


# Query refusal / error return codes from Spamhaus and other RBLs
# 127.255.255.x: Spamhaus query refused or open resolver blocked
# 127.0.1.255: Spamhaus DBL error (IP query to domain list)
# 127.0.0.1: Generic query error / localhost refusal
DNSBL_REFUSED_CODES = {
    '127.255.255.252',
    '127.255.255.254',
    '127.255.255.255',
    '127.0.1.255',
    '127.0.0.1'
}


def _filter_dnsbl_results(checker_result):
    """
    Filter out query refusal and open resolver block codes (such as Spamhaus 127.255.255.254)
    that naive RBL checkers falsely report as active spam listings.
    """
    genuine = []
    if not hasattr(checker_result, '_results') or not checker_result._results:
        return genuine
    for r in checker_result._results:
        if not r.response or r.error:
            continue
        is_genuine = False
        for entry in r.response:
            host_ip = getattr(entry, 'host', str(entry))
            if host_ip not in DNSBL_REFUSED_CODES and not host_ip.startswith('127.255.'):
                is_genuine = True
                break
        if is_genuine:
            genuine.append(r.provider.host)
    return genuine


async def check_dnsbl(domain):
    """
    Check if domain or resolved IP is listed on DNS blacklists using pydnsbl.
    Filters out open-resolver refusal codes to prevent false positive flags on trusted domains.
    """
    result = {
        'blacklisted': False,
        'blacklist_count': 0,
        'blacklists': [],
        'ip': None,
        'error': None
    }
    
    try:
        from pydnsbl import DNSBLIpChecker, DNSBLDomainChecker
        
        domain_checker = DNSBLDomainChecker()
        if hasattr(domain_checker, 'check_async'):
            domain_result = await domain_checker.check_async(domain)
        else:
            domain_result = domain_checker.check(domain)
        
        genuine_domain_hits = _filter_dnsbl_results(domain_result)
        if genuine_domain_hits:
            result['blacklisted'] = True
            result['blacklist_count'] = len(genuine_domain_hits)
            result['blacklists'] = list(set(genuine_domain_hits))
        
        try:
            ip = socket.gethostbyname(domain)
            result['ip'] = ip
            ip_checker = DNSBLIpChecker()
            if hasattr(ip_checker, 'check_async'):
                ip_result = await ip_checker.check_async(ip)
            else:
                ip_result = ip_checker.check(ip)
            
            genuine_ip_hits = _filter_dnsbl_results(ip_result)
            if genuine_ip_hits:
                result['blacklisted'] = True
                result['blacklist_count'] += len(genuine_ip_hits)
                result['blacklists'].extend(genuine_ip_hits)
                result['blacklists'] = list(set(result['blacklists']))
        except socket.gaierror:
            pass
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_ssl_certificate(domain):
    """
    Check SSL certificate validity, issuer, and expiration date.
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
                
                issuer = dict(x[0] for x in cert.get('issuer', []))
                result['issuer'] = issuer.get('organizationName', issuer.get('commonName', 'Unknown Issuer'))
                
                not_after = cert.get('notAfter')
                if not_after:
                    expires = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    result['expires'] = expires.strftime('%Y-%m-%d')
                    result['days_until_expiry'] = (expires - datetime.now()).days
                    
    except ssl.SSLCertVerificationError:
        result['has_ssl'] = True
        result['valid'] = False
        result['error'] = "Invalid or self-signed certificate"
    except socket.timeout:
        result['error'] = "SSL connection timeout"
    except ConnectionRefusedError:
        result['error'] = "Port 443 closed (HTTPS not active)"
    except socket.gaierror:
        result['error'] = "Domain DNS does not resolve"
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_dns_records(domain):
    """
    Check DNS A, MX, TXT, and NS records for the domain.
    """
    result = {
        'has_a_record': False,
        'has_mx_record': False,
        'has_txt_record': False,
        'a_records': [],
        'mx_records': [],
        'txt_records': [],
        'nameservers': [],
        'error': None
    }
    
    resolver = get_dns_resolver(timeout=5)
    
    try:
        # A Records
        try:
            answers = resolver.resolve(domain, 'A')
            result['has_a_record'] = True
            result['a_records'] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # MX Records
        try:
            answers = resolver.resolve(domain, 'MX')
            result['has_mx_record'] = True
            result['mx_records'] = [str(rdata.exchange).rstrip('.') for rdata in answers]
        except Exception:
            pass
        
        # TXT Records
        try:
            answers = resolver.resolve(domain, 'TXT')
            result['has_txt_record'] = True
            result['txt_records'] = [str(rdata) for rdata in answers][:5]
        except Exception:
            pass
        
        # Nameservers
        try:
            answers = resolver.resolve(domain, 'NS')
            result['nameservers'] = [str(rdata).rstrip('.') for rdata in answers]
        except Exception:
            pass
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_email_security(domain):
    """
    Audit SPF, DMARC, and DNSSEC records. Evaluates compliance with modern
    Google/Yahoo sender requirements and email spoofing resilience.
    """
    result = {
        'has_spf': False,
        'spf_record': None,
        'spf_policy': None,
        'has_dmarc': False,
        'dmarc_record': None,
        'dmarc_policy': None,
        'has_dnssec': False,
        'email_security_score': 0,
        'status': 'Vulnerable',
        'details': []
    }
    
    resolver = get_dns_resolver(timeout=5)
    
    # 1. SPF Inspection
    try:
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_str = "".join([b.decode('utf-8', errors='ignore') if isinstance(b, bytes) else str(b) for b in rdata.strings])
            if txt_str.startswith('v=spf1'):
                result['has_spf'] = True
                result['spf_record'] = txt_str
                if '-all' in txt_str:
                    result['spf_policy'] = 'Hard Fail (-all, Strict)'
                elif '~all' in txt_str:
                    result['spf_policy'] = 'Soft Fail (~all, Recommended)'
                elif '?all' in txt_str:
                    result['spf_policy'] = 'Neutral (?all)'
                elif '+all' in txt_str:
                    result['spf_policy'] = 'Permissive (+all, Insecure)'
                break
    except Exception:
        pass

    # 2. DMARC Inspection
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_str = "".join([b.decode('utf-8', errors='ignore') if isinstance(b, bytes) else str(b) for b in rdata.strings])
            if 'v=DMARC1' in txt_str or 'v=dmarc1' in txt_str:
                result['has_dmarc'] = True
                result['dmarc_record'] = txt_str
                match = re.search(r'\bp=([a-zA-Z]+)', txt_str)
                if match:
                    result['dmarc_policy'] = match.group(1).lower()
                break
    except Exception:
        pass

    # 3. DNSSEC Inspection
    try:
        resolver.resolve(domain, 'DNSKEY')
        result['has_dnssec'] = True
    except Exception:
        result['has_dnssec'] = False

    # Score calculation
    score = 0
    if result['has_spf']:
        score += 40
        if result['spf_policy'] in ['Hard Fail (-all, Strict)', 'Soft Fail (~all, Recommended)']:
            score += 10
            result['details'].append("Valid SPF policy detected")
    else:
        result['details'].append("Missing SPF record (email spoofing risk)")
        
    if result['has_dmarc']:
        score += 40
        if result['dmarc_policy'] in ['reject', 'quarantine']:
            score += 10
            result['details'].append(f"Enforced DMARC policy (p={result['dmarc_policy']})")
        else:
            result['details'].append(f"DMARC monitor-only policy (p={result['dmarc_policy']})")
    else:
        result['details'].append("Missing DMARC policy (fails modern sender verification)")
        
    if result['has_dnssec']:
        score = min(100, score + 10)
        result['details'].append("DNSSEC cryptographically active")
    else:
        result['details'].append("DNSSEC not enabled")

    result['email_security_score'] = score
    if score >= 80:
        result['status'] = 'Hardened'
    elif score >= 40:
        result['status'] = 'Basic Protection'
    else:
        result['status'] = 'Vulnerable'

    return result


def check_domain_expiry(whois_data):
    """
    Check if domain is expiring soon from WHOIS data.
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


def check_redirect_chain(domain, proxies=None):
    """
    Check for redirect chains that might indicate cloak redirecting or domain hijacks.
    """
    import requests
    
    result = {
        'redirect_count': 0,
        'final_url': None,
        'redirect_chain': [],
        'suspicious': False,
        'domain_changed': False,
        'error': None
    }
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=10,
            allow_redirects=True,
            headers=headers,
            proxies=proxies
        )
        
        result['redirect_count'] = len(response.history)
        result['final_url'] = response.url
        
        for r in response.history:
            result['redirect_chain'].append({
                'status': r.status_code,
                'url': r.url
            })
        
        if result['redirect_count'] > 3:
            result['suspicious'] = True
        
        # Check brand consistency via tldextract
        import tldextract
        extractor = tldextract.TLDExtract(suffix_list_urls=None)
        orig_ext = extractor(domain)
        final_ext = extractor(response.url)
        
        orig_brand = orig_ext.domain.lower() if orig_ext.domain else ""
        final_brand = final_ext.domain.lower() if final_ext.domain else ""
        
        # If brands match (e.g. apple.in -> apple.com), it is a legitimate brand redirect
        if orig_brand and final_brand and orig_brand == final_brand:
            result['same_brand'] = True
            result['domain_changed'] = False
        else:
            original_domain = domain.lower().replace('www.', '')
            final_domain = urlparse(response.url).netloc.lower().replace('www.', '')
            if original_domain not in final_domain and final_domain not in original_domain:
                result['suspicious'] = True
                result['domain_changed'] = True
            
    except requests.exceptions.SSLError:
        try:
            response = requests.get(
                f"http://{domain}",
                timeout=10,
                allow_redirects=True,
                headers=headers,
                proxies=proxies
            )
            result['redirect_count'] = len(response.history)
            result['final_url'] = response.url
        except Exception as e:
            result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_domain_availability(whois_data, domain):
    """
    Check if the domain is registered or available for purchase.
    """
    result = {
        'is_registered': False,
        'is_available': False,
        'owner': None,
        'registrar': None,
        'status': [],
        'reason': None,
        'error': None
    }
    
    try:
        if whois_data:
            has_creation_date = False
            has_registrar = False
            
            if hasattr(whois_data, 'creation_date') and whois_data.creation_date:
                has_creation_date = True
            
            if hasattr(whois_data, 'registrar') and whois_data.registrar:
                has_registrar = True
                result['registrar'] = whois_data.registrar
            
            if hasattr(whois_data, 'name') and whois_data.name:
                result['owner'] = whois_data.name
            elif hasattr(whois_data, 'org') and whois_data.org:
                result['owner'] = whois_data.org
            elif hasattr(whois_data, 'registrant_name') and whois_data.registrant_name:
                result['owner'] = whois_data.registrant_name
            
            if hasattr(whois_data, 'status') and whois_data.status:
                status = whois_data.status
                if isinstance(status, list):
                    result['status'] = [str(s) for s in status[:3]]
                else:
                    result['status'] = [str(status)]
            
            if has_creation_date or has_registrar:
                result['is_registered'] = True
                result['is_available'] = False
                result['reason'] = "Domain has active WHOIS registration record"
            else:
                result['is_available'] = True
                result['reason'] = "No valid registration record found in WHOIS"
        else:
            result['is_available'] = True
            result['reason'] = "WHOIS query returned no registration data"
        
        try:
            ip = socket.gethostbyname(domain)
            if ip and result['is_available']:
                result['is_registered'] = True
                result['is_available'] = False
                result['reason'] = "Domain actively resolves to IP address"
        except socket.gaierror:
            pass
            
    except Exception as e:
        result['error'] = str(e)
        result['is_registered'] = True
        result['is_available'] = False
        result['reason'] = f"Could not ascertain availability reliably: {e}"
    
    return result


def calculate_safety_score(whois_data, audit_data):
    """
    Calculate comprehensive safety and forensic scores.
    Returns:
    - overall_score (int): 0-100
    - sub_scores (dict): spam_score, infrastructure_score, stability_score
    - findings (list of str): Clean enterprise finding descriptions without unicode emojis
    - structured_findings (list of dict): With severity, category, and message
    """
    score = 100
    findings = []
    structured_findings = []
    
    def add_finding(severity, category, message):
        tag = f"[{severity}]"
        findings.append(f"{tag} {message}")
        structured_findings.append({
            "severity": severity,
            "category": category,
            "message": message
        })

    # Sub-score trackers
    spam_penalty = 0
    infra_penalty = 0
    stability_penalty = 0

    # 1. Domain Age Analysis
    if whois_data and hasattr(whois_data, 'creation_date') and whois_data.creation_date:
        try:
            now = datetime.now()
            c_date = whois_data.creation_date
            if isinstance(c_date, list):
                c_date = c_date[0]
            if hasattr(c_date, 'tzinfo') and c_date.tzinfo is not None:
                from datetime import timezone
                now = datetime.now(timezone.utc)
            
            age_years = (now - c_date).days / 365.0
            if age_years < 1:
                score -= 10
                stability_penalty += 15
                add_finding("WARNING", "Age", "Domain was first registered under 1 year ago (new domain).")
            elif age_years < 2:
                score -= 5
                stability_penalty += 5
                add_finding("INFO", "Age", "Domain was first registered under 2 years ago.")
            else:
                add_finding("INFO", "Age", f"Established domain history: ~{int(age_years)} years on record.")
        except Exception:
            pass
    
    # 2. Toxic Keywords Scan
    toxic_count = audit_data.get('toxic_count', 0)
    toxic_words = audit_data.get('toxic_words', [])
    if toxic_count > 0:
        penalty = min(40, toxic_count * 15)
        score -= penalty
        spam_penalty += penalty * 2
        words_preview = ", ".join(toxic_words[:6])
        add_finding("CRITICAL", "Content Spam", f"Found {toxic_count} toxic content instances in archives: {words_preview}")
    else:
        add_finding("INFO", "Content Spam", "Archive snapshots are clean of toxic keywords.")

    # 3. Foreign Script Injection (Hacked doorway spam)
    foreign_injection = audit_data.get('foreign_injection', {})
    if foreign_injection.get('injected'):
        score -= 20
        spam_penalty += 30
        scripts = ", ".join(foreign_injection.get('scripts', []))
        add_finding("CRITICAL", "Foreign Script Injection", f"Historical doorway injection detected: {scripts} characters found in archive.")

    # 4. PBN & Parking Footprint
    pbn_info = audit_data.get('pbn_info', {})
    if pbn_info.get('pbn_detected'):
        score -= 25
        spam_penalty += 30
        add_finding("CRITICAL", "PBN Risk", "Private Blog Network (PBN) link farm footprint identified in archives.")
    if pbn_info.get('is_parked'):
        score -= 10
        stability_penalty += 15
        add_finding("WARNING", "Domain Parking", "Domain was parked with a holding/arbitrage provider during its history.")

    # 5. Volatility (Drop gaps)
    volatility = audit_data.get('volatility', 'Unknown')
    if volatility == 'High':
        score -= 20
        stability_penalty += 30
        add_finding("WARNING", "Volatility", "High history volatility: Extended multi-year gaps suggest domain dropping and re-registration.")
    elif volatility == 'Medium':
        score -= 10
        stability_penalty += 15
        add_finding("INFO", "Volatility", "Medium volatility: Minor historical record gaps detected.")

    # 6. Topic Drift
    topic_drift = audit_data.get('topic_drift', {})
    drift_level = topic_drift.get('drift_level', 'Low')
    if drift_level == 'High':
        score -= 15
        stability_penalty += 20
        add_finding("WARNING", "Topic Drift", topic_drift.get('description', 'High topic drift across sectors.'))

    # 7. Tech Stack Instability
    if audit_data.get('tech_changes', 0) > 2:
        score -= 10
        stability_penalty += 10
        add_finding("WARNING", "Infrastructure", "Multiple CMS/platform changes detected across historical snapshots.")

    # 8. DNSBL Blacklist
    if audit_data.get('blacklisted', False):
        score -= 30
        infra_penalty += 45
        bl_count = audit_data.get('blacklist_count', 0)
        bl_names = ", ".join(audit_data.get('blacklist_sources', [])[:3])
        add_finding("CRITICAL", "Blacklist", f"Domain or IP actively flagged on {bl_count} spam blacklists ({bl_names}).")
    else:
        add_finding("INFO", "Blacklist", "Clean IP/domain reputation: No DNSBL blacklist listings detected.")

    # 9. SSL Certificate Status
    ssl_status = audit_data.get('ssl_status', {})
    if ssl_status.get('error'):
        score -= 10
        infra_penalty += 15
        add_finding("WARNING", "SSL", f"SSL certificate issue: {ssl_status.get('error')}")
    elif ssl_status.get('days_until_expiry', 365) is not None and ssl_status.get('days_until_expiry', 365) < 7:
        score -= 5
        infra_penalty += 10
        add_finding("WARNING", "SSL", f"SSL certificate expires in {ssl_status.get('days_until_expiry')} days (immediate renewal required).")
    elif ssl_status.get('valid'):
        days_exp = ssl_status.get('days_until_expiry')
        exp_text = f" (renews in {days_exp} days)" if days_exp is not None else ""
        add_finding("INFO", "SSL", f"Valid SSL certificate issued by {ssl_status.get('issuer', 'Trusted CA')}{exp_text}.")

    # 10. Email Security (SPF & DMARC)
    email_sec = audit_data.get('email_security', {})
    if not email_sec.get('has_spf'):
        score -= 10
        infra_penalty += 15
        add_finding("WARNING", "Email Security", "No SPF record found. Domain is vulnerable to sender spoofing.")
    if not email_sec.get('has_dmarc'):
        score -= 10
        infra_penalty += 15
        add_finding("WARNING", "Email Security", "No DMARC policy configured. Emails from this domain may fail modern provider delivery.")

    # 11. Domain Expiry Alert
    if audit_data.get('domain_expiring_soon', False):
        days_left = audit_data.get('days_until_domain_expiry', 0)
        score -= 10
        stability_penalty += 10
        add_finding("WARNING", "Registration", f"Domain registration expires in {days_left} days.")

    # 12. Redirect Chain Status
    if audit_data.get('domain_changed', False):
        score -= 15
        infra_penalty += 20
        add_finding("WARNING", "Redirects", "Suspicious redirect chain detected leading to an alternate destination.")
    elif audit_data.get('redirect_count', 0) > 4:
        score -= 10
        infra_penalty += 10
        add_finding("WARNING", "Redirects", f"Excessive redirect chain detected ({audit_data.get('redirect_count')} hops).")
    elif audit_data.get('redirect_count', 0) > 0:
        add_finding("INFO", "Redirects", f"Normal HTTP redirect chain observed ({audit_data.get('redirect_count')} hop(s)).")

    # 13. MX Records
    if audit_data.get('no_mx_records', False):
        if audit_data.get('redirect_count', 0) == 0:
            score -= 5
            infra_penalty += 5
            add_finding("INFO", "Email Infrastructure", "No MX mail server records detected.")
        else:
            add_finding("INFO", "Email Infrastructure", "No direct MX mail records (expected for primary redirect domains).")

    overall_score = max(0, min(100, score))
    spam_score = max(0, min(100, 100 - spam_penalty))
    infra_score = max(0, min(100, 100 - infra_penalty))
    stability_score = max(0, min(100, 100 - stability_penalty))

    sub_scores = {
        "spam_score": spam_score,
        "infrastructure_score": infra_score,
        "stability_score": stability_score
    }

    return overall_score, sub_scores, findings, structured_findings
