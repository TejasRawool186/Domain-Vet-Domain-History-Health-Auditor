# Domain Vet - Domain History & Health Auditor

[![Apify Actor](https://img.shields.io/badge/Apify-Actor-orange?style=flat-square&logo=apify)](https://apify.com)
[![Actor Specification](https://img.shields.io/badge/Actor%20Spec-v1.1-blue?style=flat-square)](https://docs.apify.com)
[![Zero External Paid APIs](https://img.shields.io/badge/External%20APIs-Zero%20Paid%20Dependencies-brightgreen?style=flat-square)](https://apify.com)
[![License](https://img.shields.io/badge/License-Apache--2.0-green?style=flat-square)](LICENSE)
[![Runtime](https://img.shields.io/badge/Average%20Runtime-15--25s-brightgreen?style=flat-square)](https://apify.com)

**Domain Vet** is an enterprise-grade automated due-diligence agent designed to investigate the complete forensic past of any domain name. By synthesizing chronological archives from the **Wayback Machine (Internet Archive)**, live **WHOIS registration records**, **DNSBL spam blacklists**, **SSL/TLS certificate chains**, **SPF/DMARC email security posture**, and **PBN/parking signatures**, Domain Vet generates a composite **0–100 Health Score** and an executive **"Buy or Pass" Due Diligence Report**.

Whether you are acquiring an expired domain for SEO authority, vetting a high-value domain for your startup brand, auditing a portfolio acquisition, or protecting email deliverability, Domain Vet uncovers toxic spam history, foreign doorway injections, private blog network (PBN) footprints, and multi-year ownership volatility before you invest.

---

## What does Domain Vet do?

When evaluating a domain name, surface-level metrics like registrar availability or raw backlink counts can be dangerously misleading. Millions of expired domains are repurposed for spam, hijacked for Chinese/Japanese casino doorway pages, parked on aggressive ad networks, or blacklisted by major mail providers.

Domain Vet conducts deep, autonomous forensic audits without requiring any paid third-party API keys:

- **Historical Time Travel**: Crawls and scans archive snapshots spanning 10+ years across the [Internet Archive Wayback Machine](https://archive.org).
- **Spam & Toxic Keyword Scanning**: Inspects past HTML snapshots for high-risk niches including online gambling, adult content, counterfeit pharmaceuticals, payday loans, and deceptive trading schemes.
- **PBN & Domain Parking Footprint Detection**: Identifies whether the domain was ever parked on ad arbitrage holding pages (Bodis, Sedo, ParkingCrew, Afternic) or deployed as part of an automated Private Blog Network (PBN).
- **Foreign Script Doorway Detection**: Alerts you if a western domain was hijacked with mass Chinese, Japanese, or Cyrillic doorway content to exploit temporary SEO equity.
- **Modern Email Security & Deliverability Posture**: Audits SPF (`v=spf1`), DMARC (`_dmarc` policy enforcement), and DNSSEC records against modern Google and Yahoo deliverability mandates.
- **DNSBL Blacklist Monitoring**: Cross-references domain names and resolved IPs against Spamhaus, Zen, and premier anti-spam databases.
- **Ownership Continuity & Volatility Index**: Identifies multi-year gaps in archive history that signal dropped registrations, resets, and volatile ownership handoffs.
- **Sector & Topic Drift Analysis**: Classifies historical business categories to evaluate whether the domain experienced extreme topical shifts across its lifespan.
- **Executive Due Diligence Dashboard**: Automatically renders a standalone, printable dark-fintech visual report directly in the Apify Key-Value Store under the `OUTPUT` key.

---

## Why use Domain Vet? (Problem vs. Solution)

| The Expired Domain Trap | Domain Vet Solution |
|---|---|
| **Toxic Spam History**: You buy an aged domain only to find Google manually penalized it for historical casino or pharma spam. | **Deep Content Forensics**: Deep regex-based scanning of Wayback snapshots identifies toxic keywords and historical penalties with adjustable sensitivity. |
| **PBN & Link Farm Penalties**: The domain was previously used as a doorway farm, causing future content to fail indexing. | **PBN & Parking Engine**: Flags parking signatures, holding templates, and PBN footprints across historical snapshots and nameserver changes. |
| **Burned Email Deliverability**: Emails from your new domain land directly in recipient spam folders due to missing SPF/DMARC or active IP blacklisting. | **Automated Email Security Audit**: Tests SPF policies, DMARC alignment, MX records, and DNSBL databases in real-time. |
| **Foreign Doorway Hijacks**: Past website was silently injected with East Asian or Cyrillic doorway spam pages. | **Script Injection Scanner**: Analyzes unicode script distribution in historical text to detect foreign SEO doorway injection attacks. |
| **Manual Hours of Research**: Checking Wayback Machine, WHOIS, DNS records, and blacklists takes 30–45 minutes per domain. | **Instant 20-Second Automated Audit**: Runs fully autonomously in ~20 seconds and delivers both a machine-readable JSON dataset and an executive HTML report. |

---

## What data can Domain Vet extract?

Every run produces a structured dataset record and a visual HTML report. Here are the core data fields provided:

| Field Name | Type | Description |
|---|---|---|
| `domain` | `string` | The sanitized domain name audited. |
| `score` | `integer` | Overall forensic health score from 0 to 100. |
| `verdict` | `string` | Executive recommendation (e.g., `AVAILABLE - STRONG BUY`, `REGISTERED - EXCELLENT HEALTH`, `AVAILABLE - HIGH RISK`). |
| `is_available` | `boolean` | `true` if domain has no active WHOIS registration and is open for purchase. |
| `is_registered` | `boolean` | `true` if domain is currently owned and registered. |
| `current_owner` | `string` | Registrant organization or owner from WHOIS records (or Privacy Protected). |
| `registrar` | `string` | Accredited registrar of record (e.g., NameCheap, GoDaddy, MarkMonitor). |
| `creation_date` | `string` | Earliest known registration date (YYYY-MM-DD). |
| `expiry_date` | `string` | Current domain expiration date. |
| `volatility` | `string` | Historical continuity volatility rating: `Low`, `Medium`, or `High`. |
| `topic_drift` | `string` | Historical topic consistency index: `Low`, `Moderate`, or `High`. |
| `primary_niche` | `string` | Dominant business category (e.g., `Technology & SaaS`, `E-Commerce & Retail`, `Health & Medicine`). |
| `sub_scores` | `object` | Disaggregated category scores for `spam_score`, `infrastructure_score`, and `stability_score`. |
| `email_security` | `object` | Detailed email posture containing SPF policy, DMARC enforcement (`p=reject`), DNSSEC status, and score. |
| `pbn_analysis` | `object` | PBN risk indicators, historical parking signatures, and risk score. |
| `foreign_injection` | `object` | Detection flags and character ratios for non-native script injections. |
| `ssl` | `object` | TLS/SSL certificate status, cryptographic issuer, and expiration date. |
| `dns` | `object` | A record IP, MX mail server presence, and nameserver hosts. |
| `blacklist` | `object` | DNSBL blacklist listing count and flagging authority sources. |
| `redirects` | `object` | HTTP hop count, destination URL, and suspicious redirect indicators. |
| `report_url` | `string` | Direct public URL to the standalone Due Diligence HTML dashboard in Key-Value Store. |

---

## How to audit a domain with Domain Vet

1. **Sign in or create an account**: Open the [Apify Console](https://console.apify.com) and search for **Domain Vet**.
2. **Enter the target domain**: In the **Domain Name** input field, provide the domain you wish to audit (e.g., `star.ai`, `my-new-startup.com`).
3. **Select sensitivity & features**: Keep the default `Medium` sensitivity or choose `High` for strict due diligence. Toggle email security and PBN detection as needed.
4. **Click Start**: Hit **Run**. Domain Vet begins scanning WHOIS, Wayback archives, DNS records, and blacklists in parallel.
5. **Review Results**: View the visual dashboard under the **Output** tab or export structured JSON, CSV, or Excel data from the **Storage / Dataset** tab.

---

## How much will it cost to audit domains?

Domain Vet is optimized for maximum efficiency:

- **Zero API Costs**: No paid third-party API subscriptions (e.g. Ahrefs, Moz, Hunter, or WHOIS APIs) are required. All queries utilize public protocols and free archive sources.
- **Lightweight Compute**: An average audit takes between **15 and 25 seconds** and consumes approximately **0.003 to 0.005 Compute Units (CU)** on 1024 MB memory.
- **Apify Free Tier**: With Apify's monthly free platform credits ($5 USD), you can run approximately **1,000 to 1,500 domain audits per month for free**.

---

## Input configuration

See the **Input** tab in Apify Console for the interactive form editor. The Actor accepts a single JSON input object:

```json
{
    "domain": "star.ai",
    "sensitivity": "Medium",
    "maxSnapshots": 5,
    "checkEmailSecurity": true,
    "checkPbnFootprint": true,
    "proxyConfiguration": {
        "useApifyProxy": false
    }
}
```

### Input parameters

| Parameter | Type | Default | Required | Description |
|---|---|---|---|---|
| `domain` | `string` | `"star.ai"` | **Yes** | Target domain name to audit. Protocol prefixes (`http://`, `https://`) and trailing slashes are automatically sanitized. |
| `sensitivity` | `string` | `"Medium"` | No | Spam keyword detection strictness across archive snapshots (`Low`, `Medium`, `High`). |
| `maxSnapshots` | `integer` | `5` | No | Maximum number of historical Wayback Machine snapshots to chronologically sample and inspect (min: 2, max: 10). |
| `checkEmailSecurity` | `boolean` | `true` | No | Inspects SPF and DMARC DNS policies to assess email spoofing resilience and Google/Yahoo sender compliance. |
| `checkPbnFootprint` | `boolean` | `true` | No | Analyzes historical archive HTML and nameservers for domain parking services, expired holding pages, and PBN networks. |
| `proxyConfiguration` | `object` | `{"useApifyProxy": false}` | No | Proxy settings for unthrottled scraping across Internet Archive rate-limiting endpoints. |

---

## Output example

You can download your audit results in **JSON**, **CSV**, **HTML table**, or **Excel** directly from Apify Console or via the Apify REST API.

### Simplified JSON output record

```json
{
    "domain": "star.ai",
    "score": 92,
    "verdict": "AVAILABLE - STRONG BUY (CLEAN RECORD)",
    "is_available": true,
    "is_registered": false,
    "current_owner": null,
    "registrar": "NameCheap, Inc.",
    "creation_date": "2019-03-14",
    "expiry_date": null,
    "days_until_expiry": null,
    "volatility": "Low",
    "topic_drift": "Low",
    "primary_niche": "Technology & SaaS",
    "tech_stack": [
        "React",
        "Next.js"
    ],
    "toxic_keywords_found": [],
    "snapshots_analyzed": 5,
    "sub_scores": {
        "spam_score": 100,
        "infrastructure_score": 90,
        "stability_score": 85
    },
    "email_security": {
        "has_spf": true,
        "spf_policy": "Soft Fail (~all, Recommended)",
        "has_dmarc": true,
        "dmarc_policy": "reject",
        "has_dnssec": false,
        "score": 90,
        "status": "Hardened"
    },
    "pbn_analysis": {
        "is_parked": false,
        "pbn_detected": false,
        "risk_score": 0
    },
    "foreign_injection": {
        "injected": false,
        "scripts": []
    },
    "ssl": {
        "has_ssl": true,
        "valid": true,
        "issuer": "Let's Encrypt",
        "expires": "2027-02-18",
        "error": null
    },
    "dns": {
        "has_a_record": true,
        "has_mx_record": true,
        "nameservers": [
            "ns1.cloudflare.com",
            "ns2.cloudflare.com"
        ]
    },
    "blacklist": {
        "listed": false,
        "count": 0,
        "sources": []
    },
    "redirects": {
        "count": 1,
        "suspicious": false,
        "final_url": "https://star.ai/"
    },
    "report_url": "https://api.apify.com/v2/key-value-stores/default/records/OUTPUT"
}
```

### Executive visual report

Every run automatically compiles and writes an interactive HTML audit report to Key-Value Store key `OUTPUT`. Designed in a dark fintech aesthetic (`#090A07` obsidian background, `#151515` cards, `#B8FF63` neon-lime accents, and Lucide line icons with zero emojis), it features:

- Circular Safety Confidence Gauge with color-coded risk feedback.
- Category sub-score breakdown (Spam & Content, Infrastructure, Historical Stability).
- Categorized risk findings (`CRITICAL`, `WARNING`, `INFO`).
- Bento grid covering Registration, Email Security, Reputation, Historical Volatility, Tech Stack, and Sector Drift.
- Detailed Wayback Machine chronological timeline with direct snapshot inspection links.
- One-click print / PDF export stylesheet for executive stakeholder presentations.

---

## Integrations (Make, Zapier, Webhooks, Python & Node.js)

Domain Vet integrates into your automation pipelines.

### Node.js (Apify Client)

```javascript
import { ApifyClient } from 'apify-client';

const client = new ApifyClient({
    token: process.env.APIFY_TOKEN,
});

const run = await client.actor('your-username/domain-vet').call({
    domain: 'my-startup.com',
    sensitivity: 'Medium',
    checkEmailSecurity: true,
    checkPbnFootprint: true,
});

const { items } = await client.dataset(run.defaultDatasetId).listItems();
console.log(`Health Score: ${items[0].score}/100 - Verdict: ${items[0].verdict}`);
console.log(`View HTML Report: ${items[0].report_url}`);
```

### Python (Apify Client)

```python
import os
from apify_client import ApifyClient

client = ApifyClient(os.getenv('APIFY_TOKEN'))

run = client.actor('your-username/domain-vet').call(
    run_input={
        'domain': 'my-startup.com',
        'sensitivity': 'Medium',
        'checkEmailSecurity': True,
        'checkPbnFootprint': True,
    }
)

dataset_items = client.dataset(run['defaultDatasetId']).list_items().items
record = dataset_items[0]
print(f"Domain: {record['domain']} | Score: {record['score']} | Verdict: {record['verdict']}")
print(f"Visual Report: {record['report_url']}")
```

### Webhooks & No-Code (Make.com / Zapier)

1. **Trigger on new lead or domain listing**: Configure an Airtable, Notion, or webhook trigger when an expired domain or prospective brand is discovered.
2. **Run Actor**: Use the Apify Make/Zapier integration module to trigger `domain-vet` with the domain name.
3. **Filter & Notify**: If `score < 60`, route to Slack or email with a "Warning: Toxic History Found" notification; if `score >= 80`, proceed with registration or acquisition.

---

## FAQ, Disclaimers, and Support

### Is Domain Vet legal and ethical?
Our Actors are ethical and do not extract private personal data, such as private emails, passwords, or personal identity records. They only query publicly available Internet Archive records, public WHOIS databases, and DNS servers. We therefore believe that our Actors, when used for ethical due diligence by Apify users, are safe and compliant. However, you should be aware that results could contain public registrant information protected by regional data protection regulations (such as GDPR). You should only process domain data for legitimate due diligence and business purposes.

### Why do some Wayback snapshots show as "Clean" when the site was toxic?
The Wayback Machine takes periodic snapshots. If a domain was hijacked for a short window (e.g. 3 weeks) and was never crawled by Archive.org during that specific interval, no snapshot will exist. We recommend testing with `High` sensitivity to inspect all available archive points.

### What should I do if a domain has 0 snapshots in Wayback?
If a domain has no snapshots, it is either brand new or its past owners disallowed web crawlers via `robots.txt`. Domain Vet will still complete the audit using WHOIS age, SSL validation, DNSBL blacklists, and DNS/email security.

### Need help or want to request a feature?
For bug reports, questions, or custom forensic features, open a ticket under the **Issues** tab on the Apify Store page.
