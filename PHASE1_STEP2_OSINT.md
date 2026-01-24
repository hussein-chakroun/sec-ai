# Phase 1 Step 2: OSINT & Deep Analysis - Implementation Complete

## Summary

Successfully implemented Phase 1 Step 2 with comprehensive OSINT (Open Source Intelligence) capabilities:

✅ **Website Crawling & Information Gathering**
✅ **Multiple OSINT Tool Integration**
✅ **Have I Been Pwned Breach Checking**
✅ **LLM-Powered Analysis**
✅ **All Tools Optional/Configurable**

---

## What Was Implemented

### 1. Web Crawler & Information Gatherer
**File:** `modules/web_crawler.py`

Comprehensive website crawling that extracts:

#### Information Gathered:
- **Emails** - All email addresses found on pages
- **Phone Numbers** - Contact numbers in various formats
- **Social Media Links** - Facebook, Twitter, LinkedIn, Instagram, GitHub, etc.
- **Forms** - All forms with input types, methods, CSRF status
- **Technologies** - Web servers, frameworks, CMS, JavaScript libraries
- **Metadata** - Title tags, meta descriptions, generators
- **HTML Comments** - Potentially sensitive information
- **Resources** - JavaScript files, CSS, images, documents (PDFs, docs, etc.)
- **Links** - Internal, external, and subdomain links
- **Potential Vulnerabilities** - Missing CSRF tokens, mixed content, XSS risks

#### Features:
- **Configurable Depth** - Control how many levels deep to crawl
- **Page Limit** - Set maximum pages to prevent runaway crawling
- **Intelligent Parsing** - BeautifulSoup for robust HTML parsing
- **Polite Crawling** - Delays between requests
- **Automatic Categorization** - Internal vs external links, subdomain discovery

### 2. OSINT Tools Suite
**File:** `modules/osint_tools.py`

Integration of major OSINT tools and services:

#### Have I Been Pwned Checker
- Email breach verification
- Paste database checking (with API key)
- Batch email checking
- Breach details and dates
- Compromised data types identification

#### SpiderFoot Scanner
- Automated OSINT gathering
- Multiple module support
- DNS, email, name, social media, WHOIS modules
- JSON output format
- Configurable scan depth

#### Intelligence X API
- Deep web and dark web searches
- Domain, email, IP, URL searches
- Historical data access
- Breach database integration
- Requires API key

#### Maltego Integration
- Transform execution framework
- Visual link analysis preparation
- Entity relationship mapping
- Integration ready (GUI required for full features)

#### OSINT Framework
- Tool recommendations by category
- Manual check URLs generation
- Resource categorization
- Best practices guidance

### 3. LLM-Powered Analysis
**File:** `core/osint_prompts.py`

Specialized AI prompts for intelligent analysis:

#### Analysis Types:
1. **Web Crawler Analysis** - Identifies information exposure, vulnerabilities, attack surface
2. **Email Breach Analysis** - Assesses breach severity, password reuse risks
3. **OSINT Correlation** - Connects data from multiple sources
4. **Vulnerability Analysis** - Prioritizes findings, suggests exploitation paths
5. **Social Media Analysis** - Maps personnel, identifies risks
6. **Technology Stack Analysis** - CVE mapping, configuration issues
7. **Next Steps Recommendation** - Suggests testing priorities

#### Prompt Features:
- Context-specific analysis
- Structured output format
- Risk ratings (High/Medium/Low)
- Actionable recommendations
- Executive summaries

### 4. GUI Integration
**File:** `gui/main_window.py`

Added comprehensive OSINT section to Phase 1 Recon tab:

#### UI Components:

**Web Crawler Configuration:**
- Enable/disable checkbox
- Max depth spinner (1-10 levels)
- Max pages spinner (10-500 pages)

**OSINT Tools Selection (All Optional):**
- ✅ Have I Been Pwned - Email breach checking
- 🕷️ SpiderFoot - Automated OSINT
- 🌐 Intelligence X - Deep/dark web
- 🗺️ Maltego - Visual analysis
- 📚 OSINT Framework - Recommendations
- 🤖 LLM Analysis - AI-powered insights

**API Key Configuration:**
- Have I Been Pwned API key input
- Intelligence X API key input
- Secure password field masking
- Optional for enhanced features

**Control Buttons:**
- 🕵️ Start OSINT Investigation
- ⛔ Stop OSINT
- 📄 Export OSINT Report

**Results Display (5 Tabs):**
1. **📋 Summary** - High-level overview
2. **🌐 Web Crawl** - Detailed crawl results
3. **🔒 Breaches** - Email breach data
4. **🤖 AI Analysis** - LLM insights
5. **{ } JSON** - Raw data export

---

## How to Use

### Step-by-Step Workflow:

#### 1. Basic Reconnaissance First
```
1. Enter target in "Target Configuration"
2. Select reconnaissance mode
3. Choose reconnaissance tools
4. Click "🚀 Start Reconnaissance"
5. Wait for completion
```

#### 2. OSINT Investigation
```
1. Scroll to "Step 2: OSINT & Deep Analysis" section
2. Configure web crawler:
   - Check "Enable Web Crawler"
   - Set Max Depth (3 recommended)
   - Set Max Pages (50 recommended)
3. Select OSINT tools to use
4. (Optional) Enter API keys for enhanced features
5. Click "🕵️ Start OSINT Investigation"
```

#### 3. Review Results
```
1. Check Summary tab for overview
2. Review Web Crawl tab for extracted information
3. Check Breaches tab for compromised emails
4. Read AI Analysis tab for insights
5. Export results as needed
```

---

## Configuration Options

### Web Crawler Settings:

**Max Depth:**
- **1** - Only homepage
- **2** - Homepage + direct links
- **3** - 3 levels deep (recommended)
- **5+** - Deep crawl (time-intensive)

**Max Pages:**
- **10** - Quick scan
- **50** - Balanced (recommended)
- **100+** - Comprehensive analysis

### OSINT Tools:

**Essential (No API Key):**
- Web Crawler - Always available
- OSINT Framework - Recommendations only
- LLM Analysis - Requires LLM configured

**Enhanced (API Key Required):**
- Have I Been Pwned - Free API key available
- Intelligence X - Paid API required
- SpiderFoot - Local installation required

---

## API Keys

### Have I Been Pwned:
```
1. Visit: https://haveibeenpwned.com/API/Key
2. Purchase API key ($3.50/month)
3. Enter in "HIBP API Key" field
4. Enables paste checking and higher rate limits
```

### Intelligence X:
```
1. Visit: https://intelx.io
2. Create account and subscribe
3. Generate API key
4. Enter in "IntelX API Key" field
5. Enables deep/dark web searches
```

### SpiderFoot:
```
1. Install: pip install spiderfoot
2. Or download from: https://spiderfoot.net
3. Tool will auto-detect if installed
4. No API key required
```

---

## Output Examples

### Web Crawl Summary:
```
🌐 WEB CRAWL SUMMARY:
  • Pages Crawled: 42
  • Emails Found: 15
  • Forms Detected: 8
  • Technologies: 12
  • Potential Vulnerabilities: 5
```

### Breach Check Results:
```
🔒 BREACH CHECK SUMMARY:
  • Emails Checked: 15
  • Breached Emails: 8
  • Total Breaches: 23

⚠️ BREACHED EMAILS:
📧 john.doe@example.com
   Breaches: 3
   • LinkedIn (2021-06-22)
   • Adobe (2013-10-04)
   • Collection #1 (2019-01-07)
```

### LLM Analysis Example:
```
📊 WEB CRAWLER ANALYSIS

EXECUTIVE SUMMARY:
The website reveals significant security concerns including exposed email addresses,
missing CSRF protection on forms, and disclosure of outdated software versions.

CRITICAL FINDINGS:
1. [HIGH] Missing CSRF Protection - 5 forms lack CSRF tokens
2. [HIGH] Email Exposure - 15 email addresses publicly visible
3. [MEDIUM] Technology Disclosure - WordPress 5.8 (outdated)
4. [MEDIUM] Mixed Content - HTTPS pages loading HTTP resources

RECOMMENDATIONS:
1. Implement CSRF tokens on all forms immediately
2. Use email obfuscation or contact forms
3. Update WordPress to latest version
4. Fix all mixed content warnings
```

---

## Integration with LLM

### Automatic Analysis:

When "LLM Analysis" is enabled, the system:

1. **Analyzes Web Crawl Data**
   - Identifies security issues
   - Rates vulnerability severity
   - Suggests remediation

2. **Analyzes Breach Data**
   - Assesses password reuse risk
   - Identifies high-value targets
   - Recommends immediate actions

3. **Correlates All Data**
   - Connects emails to roles
   - Maps organizational structure
   - Identifies attack vectors
   - Prioritizes targets

4. **Generates Next Steps**
   - Recommends Phase 2 activities
   - Suggests specific exploits to try
   - Identifies credentials to test

---

## Security & Legal

### Safe Usage:
✅ Only scan systems you own or have written permission to test
✅ Respect robots.txt and crawl delays
✅ Use reasonable page limits to avoid DoS
✅ Review terms of service for API providers

### Never:
❌ Scan websites without authorization
❌ Use for malicious purposes
❌ Violate privacy laws (GDPR, CCPA, etc.)
❌ Exceed API rate limits
❌ Share breach data publicly

### Legal Notice:
```
OSINT gathering must comply with:
- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR)
- Local privacy and hacking laws
- Terms of Service of all tools/APIs used

Unauthorized access or data collection may be illegal.
Always obtain proper authorization.
```

---

## Troubleshooting

### Web Crawler Issues:

**"Failed to crawl target"**
- Ensure URL includes http:// or https://
- Check site is accessible
- Try lower max pages setting
- Verify no WAF blocking

**"Too slow"**
- Reduce max depth
- Lower max pages
- Check network connection
- Site may have rate limiting

### OSINT Tool Issues:

**"HIBP API error"**
- Verify API key is correct
- Check API key is active
- Wait if rate limited (1.5 sec between requests)
- Free tier has limitations

**"Intelligence X no results"**
- Verify API key
- Check subscription is active
- Some searches require premium tier
- Try different search types

**"SpiderFoot not found"**
- Install: `pip install spiderfoot`
- Add to PATH if needed
- Tool is optional, continue without it

### LLM Analysis Issues:

**"Analysis failed"**
- Ensure LLM is configured in Settings
- Check API key is valid
- Verify internet connection
- Try with smaller dataset

---

## Files Created/Modified

### Created:
- ✅ `modules/osint_tools.py` (520+ lines) - OSINT tool wrappers
- ✅ `modules/web_crawler.py` (580+ lines) - Web crawling engine
- ✅ `core/osint_prompts.py` (380+ lines) - LLM analysis prompts

### Modified:
- ✅ `gui/main_window.py` - Added OSINT section and methods
- ✅ `modules/__init__.py` - Exported OSINT classes
- ✅ `requirements.txt` - Added beautifulsoup4, lxml

---

## Example Workflow

### Complete Phase 1 Investigation:

```
┌─────────────────────────────────────┐
│ 1. Basic Reconnaissance             │
│    - Nmap port scan                 │
│    - DNS enumeration                │
│    - WHOIS lookup                   │
│    - Subdomain discovery            │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ 2. OSINT Investigation              │
│    - Crawl website                  │
│    - Extract emails/contacts        │
│    - Identify technologies          │
│    - Find forms and entry points    │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ 3. Breach Analysis                  │
│    - Check emails in HIBP           │
│    - Identify breached accounts     │
│    - Assess password reuse risk     │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ 4. LLM Analysis                     │
│    - Correlate all findings         │
│    - Identify vulnerabilities       │
│    - Prioritize targets             │
│    - Recommend next steps           │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ 5. Export & Proceed                 │
│    - Export full report             │
│    - Review recommendations         │
│    - Move to Phase 2                │
└─────────────────────────────────────┘
```

---

## Performance Considerations

### Web Crawler:
- **Depth 3, Pages 50**: ~2-5 minutes
- **Depth 5, Pages 100**: ~5-15 minutes
- **Depth 10, Pages 500**: ~15-60 minutes

### Breach Checking:
- **Rate Limit**: 1.5 seconds between requests
- **10 emails**: ~15 seconds
- **50 emails**: ~75 seconds
- **100 emails**: ~150 seconds (2.5 minutes)

### LLM Analysis:
- **Per analysis**: 10-30 seconds
- **Full analysis (3 prompts)**: 30-90 seconds
- Depends on LLM provider and model

---

## Next Steps

### After OSINT Investigation:

1. **Review all findings carefully**
2. **Prioritize high-risk issues**
3. **Test credentials if found**
4. **Move to Phase 2**: Advanced Scanning
   - Web application scanning
   - Vulnerability detection
   - Exploit development
5. **Document everything** for final report

---

## Summary

**Phase 1 Step 2 Complete!** ✅

You now have:
- ✅ Comprehensive web crawling
- ✅ Email breach checking (HIBP)
- ✅ Multiple OSINT tool integration
- ✅ AI-powered analysis and correlation
- ✅ Automated vulnerability detection
- ✅ Professional HTML/JSON export
- ✅ All tools optional and configurable
- ✅ LLM prompts for each analysis type

The OSINT suite provides everything needed for deep intelligence gathering in Phase 1!

**Ready for the next phase of penetration testing!** 🎯
