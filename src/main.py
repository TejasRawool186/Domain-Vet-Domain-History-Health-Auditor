"""
main.py - The Orchestrator
Domain Vet: Automated due-diligence agent for domain history investigation.
Zero unicode emojis in terminal logs.
"""
import asyncio
import sys
import os
from datetime import datetime

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apify import Actor
try:
    from apify import Event
except ImportError:
    try:
        from apify.consts import ActorEvent as Event
    except ImportError:
        Event = None

import whois
import waybackpy
from waybackpy.exceptions import WaybackError
import requests
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader

from auditor import (
    scan_text_for_toxins, 
    calculate_safety_score, 
    detect_tech_stack,
    detect_pbn_and_parking,
    detect_foreign_script_injection,
    classify_content_niche,
    analyze_topic_drift,
    calculate_volatility,
    check_dnsbl,
    check_ssl_certificate,
    check_dns_records,
    check_email_security,
    check_domain_expiry,
    check_redirect_chain,
    check_domain_availability
)


async def main():
    async with Actor:
        # Register graceful aborting handler if Event is available
        async def _on_aborting():
            Actor.log.warning("Received ABORTING event from Apify platform. Persisting final state and exiting...")
            await Actor.exit()

        if Event and hasattr(Event, 'ABORTING'):
            Actor.on(Event.ABORTING, _on_aborting)

        inputs = await Actor.get_input() or {}
        domain_raw = inputs.get('domain', 'example.com')
        sensitivity = inputs.get('sensitivity', 'Medium')
        max_snapshots = int(inputs.get('maxSnapshots', 5))
        check_email = inputs.get('checkEmailSecurity', True)
        check_pbn = inputs.get('checkPbnFootprint', True)

        # Sanitize domain input
        domain = domain_raw.replace("https://", "").replace("http://", "").strip("/").strip()
        
        # Setup Proxy Configuration
        proxy_config = await Actor.create_proxy_configuration(actor_proxy_input=inputs.get('proxyConfiguration'))
        proxies = None
        if proxy_config:
            proxy_url = await proxy_config.new_url()
            if proxy_url:
                proxies = {"http": proxy_url, "https": proxy_url}
                Actor.log.info("Apify Proxy configuration active for external requests.")

        # Save an initial dark-fintech loading placeholder under OUTPUT and OUTPUT_REPORT
        loading_html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Vet: {domain}</title>
    <meta http-equiv="refresh" content="5">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #090A07;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #F3F4F6;
        }}
        .container {{
            text-align: center;
            padding: 40px;
            background: #151515;
            border: 1px solid #242424;
            border-radius: 12px;
            max-width: 480px;
            width: 90%;
        }}
        .spinner {{
            width: 48px;
            height: 48px;
            border: 3px solid rgba(184, 255, 99, 0.15);
            border-top-color: #B8FF63;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 24px;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 8px; }}
        .domain {{ color: #B8FF63; font-family: monospace; font-size: 1.3rem; margin-bottom: 12px; }}
        p {{ color: #9CA3AF; font-size: 0.9rem; line-height: 1.5; }}
        .steps {{ margin-top: 24px; text-align: left; font-size: 0.82rem; }}
        .step {{ padding: 6px 0; color: #6B7280; }}
        .step.active {{ color: #B8FF63; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h1>Auditing Domain Intelligence</h1>
        <div class="domain">{domain}</div>
        <p>Analyzing historical Wayback Machine archives, WHOIS ownership, SSL certificates, DNSBL blacklists, and email authentication posture...</p>
        <div class="steps">
            <div class="step active">[1/5] WHOIS & Registration data</div>
            <div class="step">[2/5] DNSBL & SSL Certificate analysis</div>
            <div class="step">[3/5] SPF, DMARC & Email Posture audit</div>
            <div class="step">[4/5] Wayback Machine historical timeline</div>
            <div class="step">[5/5] Generating Due Diligence Dashboard</div>
        </div>
    </div>
</body>
</html>'''
        await Actor.set_value('OUTPUT', loading_html, content_type='text/html')
        await Actor.set_value('OUTPUT_REPORT', loading_html, content_type='text/html')
        
        Actor.log.info(f"Starting domain vetting process for: {domain}")
        Actor.log.info(f"Spam sensitivity level: {sensitivity}")
        
        # --- STEP 1: WHOIS & REGISTRATION ---
        Actor.log.info("Fetching WHOIS registration records...")
        whois_data = None
        creation_date = None
        registrar = "Unknown / Hidden"
        
        try:
            whois_data = whois.whois(domain)
            if whois_data:
                creation_date = whois_data.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                registrar = whois_data.registrar or "Unknown / Hidden"
        except Exception as e:
            Actor.log.warning(f"WHOIS lookup returned error or was protected: {e}")
            creation_date = None
            registrar = "Unknown / Hidden (WHOIS Protected)"

        # --- STEP 2: DOMAIN EXPIRY & AVAILABILITY ---
        Actor.log.info("Checking domain expiration timeline and availability status...")
        expiry_info = check_domain_expiry(whois_data)
        availability_info = check_domain_availability(whois_data, domain)
        is_domain_available = availability_info.get('is_available', False)
        is_domain_registered = availability_info.get('is_registered', True)
        
        if is_domain_registered:
            Actor.log.info("Domain Status: REGISTERED (assigned to an active owner)")
        else:
            Actor.log.info("Domain Status: POTENTIALLY AVAILABLE for registration")
        
        # --- STEP 3: DNSBL BLACKLIST CHECK ---
        Actor.log.info("Querying DNSBL spam blacklists (Spamhaus/Zen)...")
        dnsbl_result = await check_dnsbl(domain)
        
        # --- STEP 4: SSL CERTIFICATE CHECK ---
        Actor.log.info("Analyzing SSL certificate and cryptographic issuer...")
        ssl_result = check_ssl_certificate(domain)
        
        # --- STEP 5: DNS & MX RECORDS ---
        Actor.log.info("Resolving DNS, MX, and TXT records...")
        dns_result = check_dns_records(domain)

        # --- STEP 5.5: EMAIL SECURITY (SPF, DMARC, DNSSEC) ---
        if check_email:
            Actor.log.info("Auditing email security posture (SPF, DMARC, DNSSEC)...")
            email_security = check_email_security(domain)
        else:
            email_security = {
                'has_spf': False, 'spf_policy': 'Skipped', 'has_dmarc': False,
                'dmarc_policy': 'Skipped', 'has_dnssec': False,
                'email_security_score': 50, 'status': 'Audit Skipped', 'details': []
            }
        
        # --- STEP 6: REDIRECT CHAIN DETECTION ---
        Actor.log.info("Checking HTTP/HTTPS redirect chains...")
        redirect_result = check_redirect_chain(domain, proxies=proxies)

        # --- STEP 7: WAYBACK MACHINE HISTORICAL ANALYSIS ---
        Actor.log.info("Querying Internet Archive Wayback Machine historical snapshots...")
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
        snapshots = []
        all_toxic_words = []
        detected_tech = set()
        detected_niches = []
        foreign_injection = {"injected": False, "scripts": [], "ratio": 0.0}
        
        try:
            wb = waybackpy.Url(f"http://{domain}", user_agent)
            archive_points = []
            
            try:
                oldest = wb.oldest()
                if oldest:
                    archive_points.append(oldest)
            except Exception as e:
                Actor.log.debug(f"Could not retrieve oldest snapshot: {e}")
            
            try:
                newest = wb.newest()
                if newest:
                    archive_points.append(newest)
            except Exception as e:
                Actor.log.debug(f"Could not retrieve newest snapshot: {e}")
            
            sample_years = [2016, 2019, 2021, 2023]
            for yr in sample_years[:max(1, max_snapshots - 2)]:
                try:
                    snap_yr = wb.near(year=yr)
                    if snap_yr:
                        archive_points.append(snap_yr)
                except Exception:
                    pass
            
            # Deduplicate by timestamp
            seen_ts = set()
            unique_points = []
            for p in archive_points:
                if p and p.timestamp not in seen_ts:
                    seen_ts.add(p.timestamp)
                    unique_points.append(p)
            
            # Sort chronologically
            unique_points.sort(key=lambda x: x.timestamp)
            
            for snap in unique_points[:max_snapshots]:
                try:
                    snap_date_str = snap.timestamp.strftime('%Y-%m-%d')
                    Actor.log.info(f"Scanning archive snapshot from date: {snap_date_str}")
                    resp = requests.get(snap.archive_url, timeout=15, proxies=proxies, headers={'User-Agent': user_agent})
                    if resp.status_code == 200:
                        toxins = scan_text_for_toxins(resp.text, sensitivity)
                        if toxins:
                            all_toxic_words.extend(toxins)
                        
                        tech = detect_tech_stack(resp.text)
                        detected_tech.add(tech)

                        niche = classify_content_niche(resp.text)
                        detected_niches.append(niche)

                        # Check foreign script injection
                        injection_check = detect_foreign_script_injection(resp.text, domain)
                        if injection_check.get('injected'):
                            foreign_injection = injection_check

                        snapshots.append({
                            "date": snap_date_str,
                            "url": snap.archive_url,
                            "toxins": ", ".join(toxins) if toxins else "Clean",
                            "has_toxins": len(toxins) > 0,
                            "tech": tech,
                            "niche": niche,
                            "raw_html": resp.text[:10000]  # truncate for PBN analysis
                        })
                except requests.RequestException as e:
                    Actor.log.debug(f"Skipping inaccessible snapshot: {e}")
                except Exception as e:
                    Actor.log.debug(f"Error processing archive snapshot: {e}")
                        
        except WaybackError as e:
            Actor.log.warning(f"Wayback Machine API notice: {e}")
        except Exception as e:
            Actor.log.warning(f"Wayback Machine archive query failed or domain unindexed: {e}")

        # Clean snapshots array (remove raw_html after analysis)
        pbn_info = {"is_parked": False, "parking_events": [], "pbn_detected": False, "pbn_indicators": [], "pbn_risk_score": 0}
        if check_pbn:
            pbn_info = detect_pbn_and_parking(snapshots, dns_result)
            
        topic_drift = analyze_topic_drift(snapshots)
        volatility = calculate_volatility(snapshots, creation_date)
        all_toxic_words = sorted(list(set(all_toxic_words)))

        # Determine Primary Sector
        if detected_niches:
            from collections import Counter
            counts = Counter([n for n in detected_niches if n != "Uncategorized"])
            primary_niche = counts.most_common(1)[0][0] if counts else "General / Tech"
        else:
            primary_niche = "Uncategorized"

        # --- STEP 8: CALCULATE HEALTH & FORENSIC SCORES ---
        audit_data = {
            "toxic_count": len(all_toxic_words),
            "toxic_words": all_toxic_words,
            "volatility": volatility,
            "topic_drift": topic_drift,
            "foreign_injection": foreign_injection,
            "pbn_info": pbn_info,
            "tech_changes": len(detected_tech),
            "blacklisted": dnsbl_result.get('blacklisted', False),
            "blacklist_count": dnsbl_result.get('blacklist_count', 0),
            "blacklist_sources": dnsbl_result.get('blacklists', []),
            "ssl_status": ssl_result,
            "email_security": email_security,
            "domain_expiring_soon": expiry_info.get('expiring_soon', False),
            "days_until_domain_expiry": expiry_info.get('days_until_expiry', 365),
            "redirect_count": redirect_result.get('redirect_count', 0),
            "domain_changed": redirect_result.get('domain_changed', False),
            "no_mx_records": not dns_result.get('has_mx_record', True)
        }
        
        score, sub_scores, reasons, structured_findings = calculate_safety_score(whois_data, audit_data)
        
        # Determine verdict based on domain availability & composite score
        if is_domain_registered:
            if score >= 80:
                verdict = "REGISTERED - EXCELLENT HEALTH"
                score_color = "#B8FF63"  # Neon lime
            elif score >= 50:
                verdict = "REGISTERED - MODERATE HEALTH"
                score_color = "#FACC15"  # Amber
            else:
                verdict = "REGISTERED - POOR HEALTH"
                score_color = "#FF4D4D"  # Coral red
            
            reasons.insert(0, "[INFO] DOMAIN REGISTERED - Active WHOIS registration record exists.")
            if availability_info.get('owner'):
                reasons.insert(1, f"[INFO] Current Registrant: {availability_info.get('owner')}")
        else:
            if score >= 80:
                verdict = "AVAILABLE - STRONG BUY (CLEAN RECORD)"
                score_color = "#B8FF63"  # Neon lime
            elif score >= 50:
                verdict = "AVAILABLE - BUY WITH CAUTION"
                score_color = "#FACC15"  # Amber
            else:
                verdict = "AVAILABLE - HIGH RISK (AVOID)"
                score_color = "#FF4D4D"  # Coral red
            
            reasons.insert(0, "[INFO] DOMAIN AVAILABLE - Can be purchased through an accredited registrar.")

        # Strip raw_html from snapshots to conserve memory & bandwidth
        for s in snapshots:
            s.pop('raw_html', None)

        # --- STEP 9: GENERATE VISUAL AUDIT DASHBOARD ---
        Actor.log.info("Rendering dark fintech executive Due Diligence dashboard...")
        
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('report.html')
        
        kvs = await Actor.open_key_value_store()
        kvs_id = kvs.name if kvs.name else 'default'
        report_url = f"https://api.apify.com/v2/key-value-stores/{kvs_id}/records/OUTPUT"
        
        audit_date = datetime.now().strftime('%Y-%m-%d %H:%M UTC')

        html = template.render(
            domain=domain,
            score=score,
            score_color=score_color,
            verdict=verdict,
            sub_scores=sub_scores,
            age=creation_date.strftime('%Y-%m-%d') if creation_date else "N/A",
            registrar=registrar,
            reasons=reasons,
            structured_findings=structured_findings,
            snapshots=snapshots,
            tech_stack=", ".join(detected_tech) if detected_tech else "None Detected",
            volatility=volatility,
            sensitivity=sensitivity,
            ssl_status=ssl_result,
            dns_info=dns_result,
            dnsbl_info=dnsbl_result,
            email_security=email_security,
            pbn_info=pbn_info,
            topic_drift=topic_drift,
            foreign_injection=foreign_injection,
            primary_niche=primary_niche,
            expiry_info=expiry_info,
            redirect_info=redirect_result,
            availability_info=availability_info,
            is_domain_available=is_domain_available,
            is_domain_registered=is_domain_registered,
            audit_date=audit_date
        )
        
        # Save visual dashboard to Key-Value Store under OUTPUT and OUTPUT_REPORT
        await Actor.set_value('OUTPUT', html, content_type='text/html')
        await Actor.set_value('OUTPUT_REPORT', html, content_type='text/html')
        
        # --- STEP 10: PUSH STRUCTURED DATASET ITEM ---
        await Actor.push_data({
            "domain": domain,
            "score": score,
            "verdict": verdict,
            "is_available": is_domain_available,
            "is_registered": is_domain_registered,
            "current_owner": availability_info.get('owner'),
            "registrar": registrar,
            "creation_date": creation_date.strftime('%Y-%m-%d') if creation_date else None,
            "expiry_date": expiry_info.get('expiry_date'),
            "days_until_expiry": expiry_info.get('days_until_expiry'),
            "volatility": volatility,
            "topic_drift": topic_drift.get('drift_level', 'Low'),
            "primary_niche": primary_niche,
            "tech_stack": list(detected_tech),
            "toxic_keywords_found": all_toxic_words,
            "snapshots_analyzed": len(snapshots),
            "risk_reasons": reasons,
            "sub_scores": sub_scores,
            "email_security": {
                "has_spf": email_security.get('has_spf', False),
                "spf_policy": email_security.get('spf_policy'),
                "has_dmarc": email_security.get('has_dmarc', False),
                "dmarc_policy": email_security.get('dmarc_policy'),
                "has_dnssec": email_security.get('has_dnssec', False),
                "score": email_security.get('email_security_score', 0),
                "status": email_security.get('status')
            },
            "pbn_analysis": {
                "is_parked": pbn_info.get('is_parked', False),
                "pbn_detected": pbn_info.get('pbn_detected', False),
                "risk_score": pbn_info.get('pbn_risk_score', 0)
            },
            "foreign_injection": {
                "injected": foreign_injection.get('injected', False),
                "scripts": foreign_injection.get('scripts', [])
            },
            "ssl": {
                "has_ssl": ssl_result.get('has_ssl', False),
                "valid": ssl_result.get('valid', False),
                "issuer": ssl_result.get('issuer'),
                "expires": ssl_result.get('expires'),
                "error": ssl_result.get('error')
            },
            "dns": {
                "has_a_record": dns_result.get('has_a_record', False),
                "has_mx_record": dns_result.get('has_mx_record', False),
                "nameservers": dns_result.get('nameservers', [])
            },
            "blacklist": {
                "listed": dnsbl_result.get('blacklisted', False),
                "count": dnsbl_result.get('blacklist_count', 0),
                "sources": dnsbl_result.get('blacklists', [])
            },
            "redirects": {
                "count": redirect_result.get('redirect_count', 0),
                "suspicious": redirect_result.get('suspicious', False),
                "final_url": redirect_result.get('final_url')
            },
            "report_url": report_url
        })
        
        Actor.log.info("Audit complete successfully.")
        Actor.log.info(f"Health score: {score}/100. Verdict: {verdict}")
        Actor.log.info(f"Report dashboard saved to Key-Value Store key 'OUTPUT'. URL: {report_url}")


if __name__ == '__main__':
    asyncio.run(main())
