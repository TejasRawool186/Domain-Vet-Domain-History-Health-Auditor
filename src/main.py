"""
main.py - The Orchestrator
Domain Vet: Automated due-diligence agent for domain history investigation.
"""
import asyncio
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apify import Actor
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
    calculate_volatility,
    check_dnsbl,
    check_ssl_certificate,
    check_dns_records,
    check_domain_expiry,
    check_redirect_chain,
    check_domain_availability
)


async def main():
    async with Actor:
        inputs = await Actor.get_input() or {}
        domain = inputs.get('domain', 'example.com')
        sensitivity = inputs.get('sensitivity', 'Medium')
        
        # Clean domain input
        domain = domain.replace("https://", "").replace("http://", "").strip("/").strip()
        
        # Save a loading placeholder immediately so the Output tab has something to show
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
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }}
        .container {{
            text-align: center;
            padding: 40px;
        }}
        .spinner {{
            width: 60px;
            height: 60px;
            border: 4px solid rgba(255,255,255,0.2);
            border-top-color: #3B82F6;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 30px;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        h1 {{ font-size: 1.8rem; margin-bottom: 10px; }}
        .domain {{ color: #60A5FA; font-family: monospace; font-size: 1.5rem; }}
        p {{ color: #94A3B8; margin-top: 15px; font-size: 0.95rem; }}
        .steps {{ margin-top: 30px; text-align: left; max-width: 400px; margin-left: auto; margin-right: auto; }}
        .step {{ padding: 10px 0; color: #64748B; display: flex; align-items: center; gap: 10px; }}
        .step.active {{ color: #10B981; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h1>🔍 Auditing Domain</h1>
        <div class="domain">{domain}</div>
        <p>Analyzing domain history, WHOIS, SSL, DNS, and blacklists...</p>
        <p style="font-size: 0.85rem; margin-top: 25px; opacity: 0.7;">This page will auto-refresh when the audit is complete.</p>
        <div class="steps">
            <div class="step active">✓ WHOIS lookup</div>
            <div class="step">⏳ SSL certificate analysis</div>
            <div class="step">⏳ DNS/MX records check</div>
            <div class="step">⏳ Wayback Machine scan</div>
            <div class="step">⏳ Generating report...</div>
        </div>
    </div>
</body>
</html>'''
        await Actor.set_value('OUTPUT_REPORT', loading_html, content_type='text/html')
        
        Actor.log.info(f"🕵️‍♂️ Starting Vetting Process for: {domain}")
        Actor.log.info(f"📊 Sensitivity Level: {sensitivity}")
        
        # --- STEP 1: WHOIS ---
        Actor.log.info("📋 Fetching WHOIS data...")
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
            Actor.log.warning(f"⚠️ WHOIS lookup failed: {e}")
            creation_date = None
            registrar = "Unknown / Hidden (WHOIS Protected)"

        # --- STEP 2: DOMAIN EXPIRY CHECK ---
        Actor.log.info("📅 Checking domain expiration...")
        expiry_info = check_domain_expiry(whois_data)
        
        # --- STEP 2.5: DOMAIN AVAILABILITY CHECK ---
        Actor.log.info("🔎 Checking domain availability...")
        availability_info = check_domain_availability(whois_data, domain)
        is_domain_available = availability_info.get('is_available', False)
        is_domain_registered = availability_info.get('is_registered', True)
        
        if is_domain_registered:
            Actor.log.info(f"📋 Domain Status: REGISTERED (owned by someone)")
        else:
            Actor.log.info(f"📋 Domain Status: POTENTIALLY AVAILABLE")
        
        # --- STEP 3: DNSBL BLACKLIST CHECK ---
        Actor.log.info("🔍 Checking spam blacklists (DNSBL)...")
        dnsbl_result = check_dnsbl(domain)
        
        # --- STEP 4: SSL CERTIFICATE CHECK ---
        Actor.log.info("🔒 Analyzing SSL certificate...")
        ssl_result = check_ssl_certificate(domain)
        
        # --- STEP 5: DNS & MX RECORDS ---
        Actor.log.info("📧 Checking DNS and MX records...")
        dns_result = check_dns_records(domain)
        
        # --- STEP 6: REDIRECT CHAIN DETECTION ---
        Actor.log.info("🔗 Checking for redirect chains...")
        redirect_result = check_redirect_chain(domain)

        # --- STEP 7: TIME TRAVEL (Wayback Machine) ---
        Actor.log.info("⏳ Analyzing historical archives (This may take 10-20s)...")
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        snapshots = []
        all_toxic_words = []
        detected_tech = set()
        
        try:
            wb = waybackpy.Url(f"http://{domain}", user_agent)
            
            archive_points = []
            
            try:
                oldest = wb.oldest()
                if oldest:
                    archive_points.append(oldest)
            except Exception as e:
                Actor.log.debug(f"Could not fetch oldest snapshot: {e}")
            
            try:
                newest = wb.newest()
                if newest:
                    archive_points.append(newest)
            except Exception as e:
                Actor.log.debug(f"Could not fetch newest snapshot: {e}")
            
            try:
                near_2020 = wb.near(year=2020)
                if near_2020:
                    archive_points.append(near_2020)
            except Exception as e:
                Actor.log.debug(f"Could not fetch 2020 snapshot: {e}")
            
            for year in [2018, 2022]:
                try:
                    snap = wb.near(year=year)
                    if snap:
                        archive_points.append(snap)
                except Exception:
                    pass
            
            for snap in archive_points:
                if snap:
                    try:
                        Actor.log.info(f"   📸 Scanning snapshot: {snap.timestamp}")
                        resp = requests.get(snap.archive_url, timeout=15)
                        if resp.status_code == 200:
                            toxins = scan_text_for_toxins(resp.text, sensitivity)
                            if toxins:
                                all_toxic_words.extend(toxins)
                            
                            tech = detect_tech_stack(resp.text)
                            detected_tech.add(tech)

                            snapshots.append({
                                "date": snap.timestamp.strftime('%Y-%m-%d'),
                                "url": snap.archive_url,
                                "toxins": ", ".join(toxins) if toxins else "Clean",
                                "tech": tech
                            })
                    except requests.RequestException as e:
                        Actor.log.debug(f"Skipping broken snapshot: {e}")
                    except Exception as e:
                        Actor.log.debug(f"Error processing snapshot: {e}")
                        
        except WaybackError as e:
            Actor.log.warning(f"⚠️ Wayback Machine error: {e}")
        except Exception as e:
            Actor.log.warning(f"⚠️ Wayback Machine unavailable or no history found: {e}")

        # Sort and deduplicate snapshots
        snapshots.sort(key=lambda x: x['date'])
        seen_dates = set()
        unique_snapshots = []
        for snap in snapshots:
            if snap['date'] not in seen_dates:
                seen_dates.add(snap['date'])
                unique_snapshots.append(snap)
        snapshots = unique_snapshots

        # --- STEP 8: CALCULATE VOLATILITY & SCORE ---
        volatility = calculate_volatility(snapshots, creation_date)
        all_toxic_words = list(set(all_toxic_words))
        
        audit_data = {
            "toxic_count": len(all_toxic_words),
            "toxic_words": all_toxic_words,
            "volatility": volatility,
            "tech_changes": len(detected_tech),
            "blacklisted": dnsbl_result.get('blacklisted', False),
            "blacklist_count": dnsbl_result.get('blacklist_count', 0),
            "ssl_status": ssl_result,
            "domain_expiring_soon": expiry_info.get('expiring_soon', False),
            "days_until_domain_expiry": expiry_info.get('days_until_expiry', 365),
            "redirect_count": redirect_result.get('redirect_count', 0),
            "no_mx_records": not dns_result.get('has_mx_record', True)
        }
        
        score, reasons = calculate_safety_score(whois_data, audit_data)
        
        # Determine verdict based on domain availability
        if is_domain_registered:
            # Domain is already registered - NOT available for purchase
            # But still show health score for research purposes
            if score > 70:
                verdict = "REGISTERED - EXCELLENT HEALTH"
                score_color = "#3B82F6"  # Blue
            elif score > 40:
                verdict = "REGISTERED - MODERATE HEALTH"
                score_color = "#8B5CF6"  # Purple
            else:
                verdict = "REGISTERED - POOR HEALTH"
                score_color = "#6B7280"  # Gray
            
            # Add availability notice to reasons
            reasons.insert(0, "🚫 DOMAIN NOT AVAILABLE - Already registered and owned by someone")
            if availability_info.get('owner'):
                reasons.insert(1, f"👤 Current Owner/Org: {availability_info.get('owner')}")
        else:
            # Domain appears to be available for purchase
            if score > 70:
                verdict = "AVAILABLE - SAFE TO BUY"
                score_color = "#10B981"  # Green
            elif score > 40:
                verdict = "AVAILABLE - PROCEED WITH CAUTION"
                score_color = "#F59E0B"  # Orange
            else:
                verdict = "AVAILABLE - HIGH RISK"
                score_color = "#EF4444"  # Red
            
            reasons.insert(0, "✅ DOMAIN AVAILABLE - Can be purchased from a registrar")

        # --- STEP 9: GET KEY-VALUE STORE INFO ---
        # Get the default key-value store ID from configuration
        kvs = await Actor.open_key_value_store()
        kvs_id = kvs.name if kvs.name else 'default'
        
        # --- STEP 10: GENERATE REPORT ---
        Actor.log.info("📄 Generating comprehensive audit report...")
        
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('report.html')
        
        report_url = f"https://api.apify.com/v2/key-value-stores/{kvs_id}/records/OUTPUT_REPORT"
        
        html = template.render(
            domain=domain,
            score=score,
            score_color=score_color,
            verdict=verdict,
            age=creation_date.strftime('%Y-%m-%d') if creation_date else "N/A",
            registrar=registrar,
            reasons=reasons,
            snapshots=snapshots,
            tech_stack=", ".join(detected_tech) if detected_tech else "None Detected",
            volatility=volatility,
            sensitivity=sensitivity,
            # New data
            ssl_status=ssl_result,
            dns_info=dns_result,
            dnsbl_info=dnsbl_result,
            expiry_info=expiry_info,
            redirect_info=redirect_result,
            # Domain availability
            availability_info=availability_info,
            is_domain_available=is_domain_available,
            is_domain_registered=is_domain_registered
        )
        
        # Save report to Key-Value Store
        await Actor.set_value('OUTPUT_REPORT', html, content_type='text/html')
        
        # Push comprehensive structured data to dataset
        await Actor.push_data({
            "domain": domain,
            "score": score,
            "verdict": verdict,
            # Domain Availability - IMPORTANT FIELD
            "is_available": is_domain_available,
            "is_registered": is_domain_registered,
            "current_owner": availability_info.get('owner'),
            # Registration Info
            "registrar": registrar,
            "creation_date": creation_date.strftime('%Y-%m-%d') if creation_date else None,
            "expiry_date": expiry_info.get('expiry_date'),
            "days_until_expiry": expiry_info.get('days_until_expiry'),
            "tech_stack": list(detected_tech),
            "toxic_keywords_found": all_toxic_words,
            "volatility": volatility,
            "snapshots_analyzed": len(snapshots),
            "risk_reasons": reasons,
            # SSL Info
            "ssl": {
                "valid": ssl_result.get('valid', False),
                "issuer": ssl_result.get('issuer'),
                "expires": ssl_result.get('expires'),
                "error": ssl_result.get('error')
            },
            # DNS/MX Info
            "dns": {
                "has_a_record": dns_result.get('has_a_record', False),
                "has_mx_record": dns_result.get('has_mx_record', False),
                "nameservers": dns_result.get('nameservers', [])
            },
            # Blacklist Info
            "blacklist": {
                "listed": dnsbl_result.get('blacklisted', False),
                "count": dnsbl_result.get('blacklist_count', 0),
                "sources": dnsbl_result.get('blacklists', [])
            },
            # Redirect Info
            "redirects": {
                "count": redirect_result.get('redirect_count', 0),
                "suspicious": redirect_result.get('suspicious', False),
                "final_url": redirect_result.get('final_url')
            },
            "report_url": report_url
        })
        
        Actor.log.info(f"🚀 AUDIT COMPLETE!")
        Actor.log.info(f"📊 Safety Score: {score}/100")
        Actor.log.info(f"📋 Verdict: {verdict}")
        Actor.log.info(f"🔗 Report URL: {report_url}")
        Actor.log.info(f"✅ Dashboard saved to key-value store")


if __name__ == '__main__':
    asyncio.run(main())
