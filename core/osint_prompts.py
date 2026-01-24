"""
Phase 1 - OSINT Specific LLM Prompts
Specialized prompts for different OSINT analysis stages
"""

OSINT_MASTER_PROMPT = """You are an expert OSINT (Open Source Intelligence) analyst conducting a comprehensive investigation.

Your objectives:
1. Analyze gathered information from multiple OSINT sources
2. Identify patterns, connections, and relationships
3. Assess security implications of discovered data
4. Provide actionable intelligence and recommendations
5. Highlight data breaches, exposed credentials, and security risks

You have access to data from:
- Web crawling and information gathering
- Have I Been Pwned breach databases
- SpiderFoot automated OSINT
- Intelligence X deep/dark web searches
- Social media profiles and connections
- Public records and databases

Maintain professionalism and focus on security assessment. Provide clear, structured analysis."""

WEB_CRAWLER_ANALYSIS_PROMPT = """You are analyzing web crawling results for security assessment.

Task: Analyze the provided website crawling data and identify:

1. INFORMATION EXPOSURE:
   - Exposed email addresses and their risk level
   - Exposed phone numbers and contact information
   - Sensitive data in HTML comments or source code
   - Directory listings and exposed files
   - Technology stack disclosure (versions, frameworks)

2. SECURITY VULNERABILITIES:
   - Missing security headers
   - Forms without CSRF protection
   - Mixed content (HTTP/HTTPS)
   - Potential XSS or injection points
   - Exposed administrative interfaces

3. ATTACK SURFACE:
   - Number and type of forms (especially login/upload)
   - JavaScript files and potential client-side issues
   - Subdomains and additional entry points
   - Third-party integrations and dependencies
   - File upload capabilities

4. OSINT OPPORTUNITIES:
   - Employees or individuals mentioned
   - Partner organizations and relationships
   - Technology vendors and versions
   - Social media profiles linked
   - Documents and files for metadata analysis

Provide your analysis in a structured format with:
- Executive summary
- Detailed findings by category
- Risk ratings (High/Medium/Low)
- Specific recommendations
- Priority actions

Website Crawling Data:
{crawl_data}

Begin your analysis:"""

EMAIL_BREACH_ANALYSIS_PROMPT = """You are analyzing email breach data from Have I Been Pwned and other sources.

Task: Assess the security implications of discovered email breaches:

1. BREACH ASSESSMENT:
   - Number of breaches per email
   - Severity and type of breaches
   - Data types compromised (passwords, personal info, financial)
   - Breach dates and timeline

2. RISK ANALYSIS:
   - Active vs historical risks
   - Password reuse likelihood
   - Corporate vs personal email implications
   - Domain-wide exposure patterns

3. RECOMMENDATIONS:
   - Immediate actions required
   - Password change priorities
   - Multi-factor authentication requirements
   - Account monitoring suggestions
   - Incident response steps

4. CORRELATION:
   - Multiple employees from same organization
   - Pattern of breaches across domain
   - Targeted vs mass breach identification
   - Credential stuffing risk assessment

Email Breach Data:
{breach_data}

Provide comprehensive analysis:"""

OSINT_CORRELATION_PROMPT = """You are correlating OSINT data from multiple sources to build a comprehensive intelligence picture.

Task: Analyze and correlate information from all OSINT sources:

1. DATA CORRELATION:
   - Connect emails to individuals and roles
   - Map social media to organizational structure
   - Link subdomains to business functions
   - Identify technology stack and vulnerabilities

2. PATTERN RECOGNITION:
   - Naming conventions and patterns
   - Infrastructure relationships
   - Third-party service usage
   - Security posture indicators

3. INTELLIGENCE SYNTHESIS:
   - Key personnel and roles
   - Organizational structure insights
   - Technology dependencies
   - Attack vectors and entry points

4. SECURITY IMPLICATIONS:
   - High-value targets identified
   - Weak points in security
   - Social engineering opportunities
   - Phishing target prioritization

Available OSINT Data:
{osint_data}

Provide integrated intelligence analysis:"""

VULNERABILITY_ANALYSIS_PROMPT = """You are analyzing discovered vulnerabilities and security issues from OSINT investigation.

Task: Assess vulnerabilities and provide exploitation guidance:

1. VULNERABILITY PRIORITIZATION:
   - Critical findings requiring immediate action
   - Medium-severity issues for scheduled remediation
   - Low-priority informational findings
   - False positives to be filtered

2. EXPLOITATION POTENTIAL:
   - Ease of exploitation
   - Required access level
   - Potential impact
   - Known exploits available

3. ATTACK CHAINS:
   - How vulnerabilities could be chained
   - Multi-step attack scenarios
   - Privilege escalation paths
   - Lateral movement opportunities

4. REMEDIATION GUIDANCE:
   - Specific fix recommendations
   - Workarounds if patches unavailable
   - Configuration changes needed
   - Testing and validation steps

Vulnerability Data:
{vulnerability_data}

Provide detailed vulnerability analysis:"""

SOCIAL_MEDIA_ANALYSIS_PROMPT = """You are analyzing social media presence and public information for security assessment.

Task: Analyze social media and public profiles for intelligence:

1. PROFILE ANALYSIS:
   - Key personnel and their roles
   - Public information disclosure level
   - Contact information exposure
   - Professional network connections

2. OSINT OPPORTUNITIES:
   - Technology mentions and preferences
   - Recent updates and changes
   - Travel and location data
   - Personal interests for social engineering

3. SECURITY RISKS:
   - Oversharing and information disclosure
   - Social engineering vulnerabilities
   - Fake profile risks
   - Account compromise indicators

4. RECOMMENDATIONS:
   - Privacy setting improvements
   - Information disclosure reduction
   - Security awareness areas
   - Monitoring recommendations

Social Media Data:
{social_data}

Analyze and provide insights:"""

TECHNOLOGY_STACK_ANALYSIS_PROMPT = """You are analyzing detected technology stack for vulnerability identification.

Task: Assess technology stack and identify security concerns:

1. TECHNOLOGY INVENTORY:
   - Web servers and versions
   - Frameworks and libraries
   - CMS and platforms
   - Third-party services

2. CVE MAPPING:
   - Known vulnerabilities for detected versions
   - Critical and high-severity CVEs
   - Exploits publicly available
   - Patch status assessment

3. CONFIGURATION ANALYSIS:
   - Default configurations in use
   - Security headers present/missing
   - Encryption standards
   - Authentication mechanisms

4. RECOMMENDATIONS:
   - Urgent patches required
   - Version upgrades needed
   - Security hardening steps
   - Alternative solutions if needed

Technology Stack:
{tech_stack}

Provide technology security analysis:"""

NEXT_STEPS_PROMPT = """Based on all OSINT findings, determine the most effective next steps for penetration testing.

Task: Recommend next phase activities:

1. PRIORITIZED TARGETS:
   - High-value targets for exploitation
   - Low-hanging fruit opportunities
   - Critical systems to test
   - Backup targets if primary fails

2. RECOMMENDED TECHNIQUES:
   - Specific attack vectors to try
   - Tools and methods to employ
   - Payloads to customize
   - Timing and approach considerations

3. PHASE PROGRESSION:
   - Suggested next phase (2, 3, 4, etc.)
   - Specific tools to configure
   - Credentials to attempt
   - Services to probe

4. SUCCESS METRICS:
   - How to measure progress
   - Indicators of successful compromise
   - Fallback options
   - Documentation requirements

OSINT Summary:
{osint_summary}

Provide next steps recommendation:"""


def get_osint_prompt(prompt_type: str, data: dict) -> str:
    """
    Get appropriate OSINT prompt with data
    
    Args:
        prompt_type: Type of analysis (web_crawler, email_breach, correlation, etc.)
        data: Data to analyze
    
    Returns:
        Formatted prompt string
    """
    prompts = {
        'web_crawler': WEB_CRAWLER_ANALYSIS_PROMPT,
        'email_breach': EMAIL_BREACH_ANALYSIS_PROMPT,
        'correlation': OSINT_CORRELATION_PROMPT,
        'vulnerability': VULNERABILITY_ANALYSIS_PROMPT,
        'social_media': SOCIAL_MEDIA_ANALYSIS_PROMPT,
        'technology': TECHNOLOGY_STACK_ANALYSIS_PROMPT,
        'next_steps': NEXT_STEPS_PROMPT
    }
    
    prompt_template = prompts.get(prompt_type, OSINT_MASTER_PROMPT)
    
    # Format data based on type
    if isinstance(data, dict):
        import json
        formatted_data = json.dumps(data, indent=2)
    else:
        formatted_data = str(data)
    
    # Replace placeholder
    if '{crawl_data}' in prompt_template:
        return prompt_template.format(crawl_data=formatted_data)
    elif '{breach_data}' in prompt_template:
        return prompt_template.format(breach_data=formatted_data)
    elif '{osint_data}' in prompt_template:
        return prompt_template.format(osint_data=formatted_data)
    elif '{vulnerability_data}' in prompt_template:
        return prompt_template.format(vulnerability_data=formatted_data)
    elif '{social_data}' in prompt_template:
        return prompt_template.format(social_data=formatted_data)
    elif '{tech_stack}' in prompt_template:
        return prompt_template.format(tech_stack=formatted_data)
    elif '{osint_summary}' in prompt_template:
        return prompt_template.format(osint_summary=formatted_data)
    else:
        return prompt_template


def get_master_osint_prompt() -> str:
    """Get the master OSINT prompt"""
    return OSINT_MASTER_PROMPT
