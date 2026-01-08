# 🔍 Domain Vet - Domain History & Health Auditor

Automated due-diligence agent that investigates a domain's past life using the Wayback Machine and public records, generating a "Buy or Pass" Audit Report.

## 🎯 What It Does

Domain Vet answers the critical question: **"Is this domain safe to build a brand on, or does it have a toxic history (spam, gambling, penalties)?"**

### Power Features

| Feature | Description |
|---------|-------------|
| 📉 **Ownership Volatility Score** | Analyzes gaps in Archive.org history to detect dropped/re-registered domains |
| 🎰 **Historical Tech Stack** | Identifies WordPress, Shopify, Drupal, React, and 12+ other platforms |
| 🛑 **Toxic Word Scan** | Scans snapshots for spam keywords (casino, viagra, loans, etc.) |
| 🛡️ **DNSBL Blacklist Check** | Checks domain/IP against Spamhaus and other spam blacklists |
| 🔒 **SSL Certificate Analysis** | Validates SSL certificate and checks expiration |
| 📧 **DNS & MX Records** | Analyzes email configuration and nameservers |
| ⏰ **Domain Expiry Warning** | Alerts if domain is expiring soon (potential drop indicator) |
| 🔗 **Redirect Chain Detection** | Detects suspicious redirect chains |

## 🛠️ Technical Architecture

### Zero-API Approach (100% Challenge Compliant)
- **Historical Data**: Archive.org via `waybackpy`
- **Registration Data**: `python-whois`
- **DNS Analysis**: `dnspython`
- **Reputation Check**: `pydnsbl` (Spamhaus/Zen)
- **Text Analysis**: BeautifulSoup + Regex
- **Visualization**: Jinja2 HTML Dashboard

## 📥 Input

```json
{
    "domain": "my-startup.com",
    "sensitivity": "Medium"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | The domain to audit (required) |
| `sensitivity` | enum | Spam detection strictness: Low, Medium, High |

## 📊 Output

### Safety Score (0-100)
- **70-100**: ✅ SAFE TO BUY
- **40-69**: ⚠️ PROCEED WITH CAUTION
- **0-39**: 🛑 HIGH RISK

### HTML Audit Report
Professional "Legal Audit" style dashboard with:
- 📊 Safety Score visualization
- 📋 WHOIS & registrar information
- 🔒 SSL certificate status
- 🛡️ Blacklist check results
- 📧 DNS/MX record analysis
- ⏰ Domain expiry warning
- 🔗 Redirect chain analysis
- 📈 Visual timeline chart
- 📸 Archive.org snapshot timeline
- 📄 Print-friendly version

## 🎯 Target Audience

- Domain Flippers
- SEO Agencies
- Startup Founders
- Brand Protection Teams
- M&A Due Diligence

## 🏆 Apify 1M Challenge Compliant

This Actor follows all challenge rules:
- ✅ Zero external paid APIs
- ✅ Uses only public data sources
- ✅ Output schema configured
- ✅ Professional HTML dashboard output

## 📜 License

ISC License
