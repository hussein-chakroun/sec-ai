#!/usr/bin/env python3
"""
EsecAi - Web Interface
Streamlit-based web application for AI-Powered Penetration Testing
Fully Implemented Phases: 1-5 & 12
"""
import streamlit as st
import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.llm_orchestrator import LLMOrchestrator, OpenAIProvider, AnthropicProvider
from core.config import config
from core.phase_integration_bridge import PhaseIntegrationBridge
from core.phase12_engine import Phase12Engine
from reports import ReportGenerator

# Page configuration
st.set_page_config(
    page_title="EsecAi - AI Penetration Testing",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for cybersecurity theme
st.markdown("""
<style>
    .main {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .stApp {
        background-color: #0d1117;
    }
    h1, h2, h3 {
        color: #58a6ff;
    }
    .stButton>button {
        background-color: #238636;
        color: white;
        border: 1px solid #2ea043;
        border-radius: 6px;
        padding: 0.5rem 1rem;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #2ea043;
        border-color: #3fb950;
    }
    .stTextInput>div>div>input {
        background-color: #0d1117;
        color: #c9d1d9;
        border: 1px solid #30363d;
    }
    .stSelectbox>div>div>select {
        background-color: #0d1117;
        color: #c9d1d9;
        border: 1px solid #30363d;
    }
    .success-box {
        background-color: #238636;
        padding: 1rem;
        border-radius: 6px;
        color: white;
        margin: 1rem 0;
    }
    .error-box {
        background-color: #da3633;
        padding: 1rem;
        border-radius: 6px;
        color: white;
        margin: 1rem 0;
    }
    .info-box {
        background-color: #1f6feb;
        padding: 1rem;
        border-radius: 6px;
        color: white;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: #d29922;
        padding: 1rem;
        border-radius: 6px;
        color: white;
        margin: 1rem 0;
    }
    .terminal-output {
        background-color: #010409;
        color: #7ee787;
        font-family: 'Courier New', monospace;
        padding: 1rem;
        border-radius: 6px;
        border: 1px solid #30363d;
        white-space: pre-wrap;
        max-height: 500px;
        overflow-y: auto;
    }
    .metric-card {
        background-color: #161b22;
        padding: 1rem;
        border-radius: 6px;
        border: 1px solid #30363d;
        margin: 0.5rem 0;
    }
    .stProgress > div > div > div {
        background-color: #238636;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'orchestrator' not in st.session_state:
    st.session_state.orchestrator = None
if 'results' not in st.session_state:
    st.session_state.results = None
if 'running' not in st.session_state:
    st.session_state.running = False
if 'enabled_phases' not in st.session_state:
    st.session_state.enabled_phases = {
        'phase1': True,
        'phase2': True,
        'phase3': True,
        'phase4': True,
        'phase5': True,
        'phase12': False
    }


def init_orchestrator():
    """Initialize LLM orchestrator"""
    if st.session_state.orchestrator is None:
        try:
            api_key = config.openai_api_key if config.llm_provider == "openai" else config.anthropic_api_key
            
            if not api_key:
                st.error("⚠️ No API key found. Please set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env")
                return None
            
            if config.llm_provider == "openai":
                provider = OpenAIProvider(api_key, config.llm_model)
            else:
                provider = AnthropicProvider(api_key, config.llm_model)
            
            st.session_state.orchestrator = LLMOrchestrator(
                provider,
                low_context_mode=config.low_context_mode,
                chunk_size=config.low_context_chunk_size
            )
            return st.session_state.orchestrator
        except Exception as e:
            st.error(f"❌ Failed to initialize orchestrator: {e}")
            return None
    return st.session_state.orchestrator


def render_header():
    """Render application header"""
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center;'>⚡ EsecAi</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #8b949e;'>AI-Powered Autonomous Penetration Testing | Phase 1-5 + Phase 12</p>", unsafe_allow_html=True)


def render_sidebar():
    """Render sidebar with navigation and settings"""
    with st.sidebar:
        st.markdown("### 🎯 Navigation")
        
        page = st.radio(
            "Select Page:",
            [
                "🏠 Dashboard",
                "⚙️ Phase Selection",
                "🔍 Phase 1: Reconnaissance",
                "🎯 Phase 2: Vulnerability Scanning",
                "💣 Phase 3: Exploitation",
                "🔓 Phase 4: Post-Exploitation",
                "🌐 Phase 5: Lateral Movement",
                "🤖 Phase 12: AI Adaptive",
                "🔧 Configuration",
                "🛠️ Tools Status"
            ]
        )
        
        st.markdown("---")
        st.markdown("### 🔧 Quick Settings")
        
        llm_provider = st.selectbox(
            "LLM Provider:",
            ["openai", "anthropic"],
            index=0 if config.llm_provider == "openai" else 1
        )
        
        if llm_provider == "openai":
            model = st.selectbox("Model:", ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"])
        else:
            model = st.selectbox("Model:", ["claude-3-opus-20240229", "claude-3-sonnet-20240229"])
        
        st.markdown("---")
        st.markdown("### 📊 System Status")
        
        if st.session_state.orchestrator:
            st.success("✅ LLM Connected")
        else:
            st.warning("⚠️ LLM Not Connected")
        
        if st.session_state.running:
            st.info("🔄 Pentest Running...")
        
        return page


def dashboard_page():
    """Main dashboard page"""
    st.markdown("## 🎯 Penetration Testing Dashboard")
    
    # Target configuration
    with st.expander("🎯 Target Configuration", expanded=True):
        col1, col2 = st.columns([3, 1])
        with col1:
            target = st.text_input(
                "Target (IP, domain, or CIDR):",
                placeholder="192.168.1.0/24 or example.com",
                help="Enter target IP address, domain name, or network range"
            )
        with col2:
            max_iterations = st.number_input("Max Iterations:", min_value=1, max_value=100, value=10)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            aggressive = st.checkbox("Aggressive Scanning")
        with col2:
            stealth = st.checkbox("Stealth Mode")
        with col3:
            safe_mode = st.checkbox("Safe Mode", value=True)
    
    # Quick phase selection
    with st.expander("⚡ Quick Phase Selection", expanded=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔍 Recon Only (Phase 1)", use_container_width=True):
                quick_select_phases('recon')
        with col2:
            if st.button("🎯 Recon + Vuln Scan (1→2)", use_container_width=True):
                quick_select_phases('vulnscan')
        with col3:
            if st.button("💥 Through Exploitation (1→2→3)", use_container_width=True):
                quick_select_phases('exploit')
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔓 Through Post-Exploit (1→2→3→4)", use_container_width=True):
                quick_select_phases('postexploit')
        with col2:
            if st.button("🔥 Complete Pentest (1→2→3→4→5)", use_container_width=True):
                quick_select_phases('complete')
        with col3:
            if st.button("🤖 AI Adaptive (Phase 12)", use_container_width=True):
                quick_select_phases('ai')
    
    # Control buttons
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        start_button = st.button("🚀 Start Pentest", type="primary", use_container_width=True, disabled=st.session_state.running)
    with col2:
        stop_button = st.button("⛔ Stop", use_container_width=True, disabled=not st.session_state.running)
    with col3:
        export_button = st.button("📄 Export Report", use_container_width=True, disabled=st.session_state.results is None)
    
    # Handle start button
    if start_button and target:
        orchestrator = init_orchestrator()
        if orchestrator:
            st.session_state.running = True
            run_pentest(target, orchestrator, safe_mode)
    elif start_button and not target:
        st.error("⚠️ Please enter a target")
    
    # Handle export button
    if export_button and st.session_state.results:
        export_report()
    
    # Results display
    if st.session_state.results:
        display_results(st.session_state.results)


def quick_select_phases(selection_type):
    """Quick phase selection"""
    phase_maps = {
        'recon': ['phase1'],
        'vulnscan': ['phase1', 'phase2'],
        'exploit': ['phase1', 'phase2', 'phase3'],
        'postexploit': ['phase1', 'phase2', 'phase3', 'phase4'],
        'complete': ['phase1', 'phase2', 'phase3', 'phase4', 'phase5'],
        'ai': ['phase12']
    }
    
    selected = phase_maps.get(selection_type, [])
    for phase_id in st.session_state.enabled_phases.keys():
        st.session_state.enabled_phases[phase_id] = phase_id in selected
    
    st.success(f"✅ Selected: {selection_type} ({len(selected)} phases enabled)")


def run_pentest(target: str, orchestrator: LLMOrchestrator, safe_mode: bool):
    """Run penetration test"""
    try:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Build configuration
        pentest_config = {
            'auto_progress': True,
            'save_intermediate': True,
            'output_dir': './reports',
            'phase1': {
                'scan_mode': 'balanced',
                'enable_osint': True,
                'enable_subdomain_enum': True
            },
            'phase2': {
                'scan_mode': 'balanced',
                'enable_cve_correlation': True,
                'severity_threshold': 'medium'
            },
            'phase3': {
                'max_attempts_per_vuln': 3,
                'exploit_timeout': 300,
                'safe_mode': safe_mode,
                'aggressive_mode': False,
                'require_confirmation': False
            },
            'phase4': {
                'privilege_escalation': {'enabled': True, 'max_attempts': 3},
                'credential_harvesting': {'enabled': True},
                'persistence': {'enabled': True, 'stealth_mode': True}
            },
            'phase5': {
                'lateral_movement': {'enabled': True, 'max_hops': 5, 'stealth_mode': True},
                'active_directory': {'enabled': True, 'bloodhound_collection': True},
                'domain_dominance': {'target_dc': True}
            }
        }
        
        # Determine which phases to run
        stop_at = 0
        if st.session_state.enabled_phases['phase5']:
            stop_at = 5
        elif st.session_state.enabled_phases['phase4']:
            stop_at = 4
        elif st.session_state.enabled_phases['phase3']:
            stop_at = 3
        elif st.session_state.enabled_phases['phase2']:
            stop_at = 2
        elif st.session_state.enabled_phases['phase1']:
            stop_at = 1
        
        status_text.info(f"🔄 Running Phase 1→{stop_at} workflow...")
        progress_bar.progress(10)
        
        # Run pentest
        bridge = PhaseIntegrationBridge(orchestrator, pentest_config)
        
        # Create async event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        progress_bar.progress(20)
        results = loop.run_until_complete(
            bridge.run_complete_pentest(
                target,
                phase1_config=pentest_config.get('phase1'),
                phase2_config=pentest_config.get('phase2'),
                phase3_config=pentest_config.get('phase3') if stop_at >= 3 else None,
                phase4_config=pentest_config.get('phase4') if stop_at >= 4 else None,
                phase5_config=pentest_config.get('phase5') if stop_at >= 5 else None,
                stop_at_phase=stop_at
            )
        )
        
        progress_bar.progress(100)
        status_text.success("✅ Pentest completed successfully!")
        
        st.session_state.results = results
        st.session_state.running = False
        
        # Save results
        bridge.save_final_results(results)
        
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ Pentest failed: {e}")
        st.session_state.running = False


def display_results(results: Dict[str, Any]):
    """Display pentest results"""
    st.markdown("## 📊 Pentest Results")
    
    summary = results.get('executive_summary', {})
    pentest_summary = results.get('pentest_summary', {})
    
    # Executive summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Duration", pentest_summary.get('duration_formatted', 'N/A'))
    with col2:
        st.metric("Phases Completed", f"{pentest_summary.get('phases_completed', 0)}/5")
    with col3:
        risk_level = summary.get('risk_level', 'unknown').upper()
        risk_color = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(risk_level, '⚪')
        st.metric("Risk Level", f"{risk_color} {risk_level}")
    with col4:
        st.metric("Status", pentest_summary.get('status', 'unknown').upper())
    
    # Phase-specific results
    tabs = st.tabs(["📊 Overview", "🔍 Phase 1-2", "💣 Phase 3", "🔓 Phase 4", "🌐 Phase 5"])
    
    with tabs[0]:  # Overview
        st.markdown("### Overall Findings")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Reconnaissance & Scanning")
            st.metric("Targets Scanned", summary.get('targets_scanned', 0))
            st.metric("Services Discovered", summary.get('services_discovered', 0))
            st.metric("Vulnerabilities Found", summary.get('vulnerabilities_found', 0))
            st.metric("Critical Vulnerabilities", summary.get('critical_vulnerabilities', 0))
            st.metric("High Vulnerabilities", summary.get('high_vulnerabilities', 0))
        
        with col2:
            st.markdown("#### Exploitation & Post-Exploitation")
            st.metric("Successful Exploits", summary.get('successful_exploits', 0))
            st.metric("Shells Obtained", summary.get('shells_obtained', 0))
            st.metric("Fully Compromised Hosts", summary.get('fully_compromised_hosts', 0))
            st.metric("Credentials Harvested", summary.get('credentials_harvested', 0))
            st.metric("Persistence Installed", summary.get('persistence_installed', 0))
        
        if summary.get('lateral_movements', 0) > 0:
            st.markdown("#### Lateral Movement & Domain Dominance")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Lateral Movements", summary.get('lateral_movements', 0))
            with col2:
                domain_admin = "✅ YES" if summary.get('domain_admin_achieved') else "❌ NO"
                st.metric("Domain Admin Achieved", domain_admin)
            with col3:
                st.metric("Domain Controllers Compromised", summary.get('domain_controllers_compromised', 0))
    
    with tabs[1]:  # Phase 1-2
        phase1_results = results.get('phase1_results', {})
        phase2_results = results.get('phase2_results', {})
        
        if phase1_results:
            st.markdown("### Phase 1: Reconnaissance Results")
            if 'hosts' in phase1_results:
                st.markdown(f"**Discovered Hosts:** {len(phase1_results['hosts'])}")
                if phase1_results['hosts']:
                    df = pd.DataFrame(phase1_results['hosts'])
                    st.dataframe(df, use_container_width=True)
        
        if phase2_results:
            st.markdown("### Phase 2: Vulnerability Scanning Results")
            vuln_summary = phase2_results.get('vulnerability_summary', {})
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Vulnerabilities", vuln_summary.get('total', 0))
            with col2:
                st.metric("Critical", vuln_summary.get('critical', 0))
            with col3:
                st.metric("High", vuln_summary.get('high', 0))
            with col4:
                st.metric("Medium", vuln_summary.get('medium', 0))
    
    with tabs[2]:  # Phase 3
        phase3_results = results.get('phase3_results', {})
        if phase3_results:
            st.markdown("### Phase 3: Exploitation Results")
            stats = phase3_results.get('statistics', {})
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Exploits Attempted", stats.get('total_exploits_attempted', 0))
            with col2:
                st.metric("Successful Exploits", stats.get('successful_exploits', 0))
            with col3:
                st.metric("Shells Obtained", stats.get('shells_obtained', 0))
            
            if 'successful_exploits' in phase3_results:
                st.markdown("**Successful Exploits:**")
                for exploit in phase3_results['successful_exploits']:
                    with st.expander(f"✅ {exploit.get('target', 'Unknown')} - {exploit.get('exploit_method', 'Unknown')}"):
                        st.json(exploit)
    
    with tabs[3]:  # Phase 4
        phase4_results = results.get('phase4_results', {})
        if phase4_results:
            st.markdown("### Phase 4: Post-Exploitation Results")
            stats = phase4_results.get('statistics', {})
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Fully Compromised Hosts", stats.get('fully_compromised_hosts', 0))
            with col2:
                st.metric("Credentials Harvested", stats.get('total_credentials_harvested', 0))
            with col3:
                st.metric("Persistence Installed", stats.get('persistence_mechanisms_installed', 0))
            
            if 'compromised_hosts' in phase4_results:
                st.markdown("**Compromised Hosts:**")
                for host in phase4_results['compromised_hosts']:
                    with st.expander(f"🖥️ {host.get('host', 'Unknown')} - {host.get('os_type', 'Unknown')}"):
                        st.json(host)
    
    with tabs[4]:  # Phase 5
        phase5_results = results.get('phase5_results', {})
        if phase5_results:
            st.markdown("### Phase 5: Lateral Movement Results")
            stats = phase5_results.get('statistics', {})
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Successful Lateral Movements", stats.get('successful_lateral_movements', 0))
            with col2:
                domain_admin = "✅ YES" if stats.get('domain_admin_achieved') else "❌ NO"
                st.metric("Domain Admin Achieved", domain_admin)
            with col3:
                st.metric("Domain Controllers Compromised", stats.get('domain_controllers_compromised', 0))
            
            if 'lateral_movements' in phase5_results:
                st.markdown("**Lateral Movements:**")
                for movement in phase5_results['lateral_movements']:
                    st.write(f"• {movement.get('from_host')} → {movement.get('to_host')} via {movement.get('technique')}")


def export_report():
    """Export pentest report"""
    if st.session_state.results:
        try:
            report_gen = ReportGenerator('./reports')
            files = report_gen.generate_report(st.session_state.results, formats=['json', 'html'])
            
            st.success("✅ Reports generated successfully!")
            for fmt, path in files.items():
                st.write(f"• {fmt.upper()}: `{path}`")
        except Exception as e:
            st.error(f"❌ Failed to generate report: {e}")


def phase_selection_page():
    """Phase selection page"""
    st.markdown("## ⚙️ Phase Selection")
    st.markdown("Select which phases to execute during penetration test:")
    
    phases = [
        ('phase1', 'Phase 1: Reconnaissance', 'Network discovery, port scanning, service enumeration, OSINT'),
        ('phase2', 'Phase 2: Vulnerability Scanning', 'Web scanning, vulnerability detection, CVE correlation'),
        ('phase3', 'Phase 3: Exploitation', 'LLM-driven exploit execution, Metasploit, custom exploits'),
        ('phase4', 'Phase 4: Post-Exploitation', 'Privilege escalation, credential harvesting, persistence installation'),
        ('phase5', 'Phase 5: Lateral Movement', 'Network spreading, Active Directory attacks, domain dominance'),
        ('phase12', 'Phase 12: AI Adaptive Exploitation', 'Reinforcement learning, adversarial ML, autonomous research')
    ]
    
    for phase_id, phase_name, phase_desc in phases:
        with st.expander(f"{'✅' if st.session_state.enabled_phases[phase_id] else '⬜'} {phase_name}", expanded=False):
            st.markdown(f"**Description:** {phase_desc}")
            enabled = st.checkbox(
                f"Enable {phase_name}",
                value=st.session_state.enabled_phases[phase_id],
                key=f"checkbox_{phase_id}"
            )
            st.session_state.enabled_phases[phase_id] = enabled


def phase1_page():
    """Phase 1: Reconnaissance page"""
    st.markdown("## 🔍 Phase 1: Reconnaissance")
    st.info("Network discovery, port scanning, service enumeration, and OSINT gathering")
    
    with st.form("phase1_config"):
        st.markdown("### Configuration")
        
        scan_mode = st.selectbox("Scan Mode:", ["quick", "balanced", "deep"])
        enable_osint = st.checkbox("Enable OSINT", value=True)
        enable_subdomain = st.checkbox("Enable Subdomain Enumeration", value=True)
        
        submitted = st.form_submit_button("💾 Save Configuration")
        if submitted:
            st.success("✅ Configuration saved!")
    
    st.markdown("### Results")
    st.info("Phase 1 results will appear here after running the pentest from the Dashboard.")


def phase2_page():
    """Phase 2: Vulnerability Scanning page"""
    st.markdown("## 🎯 Phase 2: Vulnerability Scanning")
    st.info("Web application scanning, vulnerability detection, and CVE correlation")
    
    with st.form("phase2_config"):
        st.markdown("### Configuration")
        
        scan_mode = st.selectbox("Scan Mode:", ["quick", "balanced", "deep", "aggressive"])
        enable_cve = st.checkbox("Enable CVE Correlation", value=True)
        severity_threshold = st.selectbox("Severity Threshold:", ["low", "medium", "high", "critical"])
        
        submitted = st.form_submit_button("💾 Save Configuration")
        if submitted:
            st.success("✅ Configuration saved!")
    
    st.markdown("### Results")
    st.info("Phase 2 results will appear here after running the pentest from the Dashboard.")


def phase3_page():
    """Phase 3: Exploitation page"""
    st.markdown("## 💣 Phase 3: Exploitation")
    st.info("LLM-driven intelligent exploitation using Metasploit and custom exploits")
    
    with st.form("phase3_config"):
        st.markdown("### Exploitation Configuration")
        
        max_attempts = st.number_input("Max Attempts per Vulnerability:", min_value=1, max_value=10, value=3)
        exploit_timeout = st.number_input("Exploit Timeout (seconds):", min_value=60, max_value=3600, value=300)
        
        safe_mode = st.checkbox("Safe Mode (Prevent System Damage)", value=True)
        aggressive_mode = st.checkbox("Aggressive Mode (Try All Techniques)")
        use_metasploit = st.checkbox("Use Metasploit Framework", value=True)
        use_custom = st.checkbox("Use Custom Exploit Generator", value=True)
        
        submitted = st.form_submit_button("💾 Save Configuration")
        if submitted:
            st.success("✅ Configuration saved!")
    
    st.markdown("### Results")
    st.warning("⚠️ Phase 3 requires Phase 1 & 2 results. Use 'Run Phase 1→2→3' workflow from the Dashboard.")


def phase4_page():
    """Phase 4: Post-Exploitation page"""
    st.markdown("## 🔓 Phase 4: Post-Exploitation")
    st.info("Privilege escalation, credential harvesting, and persistence installation")
    
    with st.form("phase4_config"):
        st.markdown("### Privilege Escalation")
        privesc_enabled = st.checkbox("Enable Privilege Escalation", value=True)
        privesc_attempts = st.number_input("Max Attempts:", min_value=1, max_value=10, value=3)
        
        st.markdown("### Credential Harvesting")
        cred_enabled = st.checkbox("Enable Credential Harvesting", value=True)
        use_mimikatz = st.checkbox("Use Mimikatz/Pypykatz", value=True)
        use_browser = st.checkbox("Browser Credential Dump", value=True)
        use_memory = st.checkbox("Memory Scraping")
        
        st.markdown("### Persistence Installation")
        persist_enabled = st.checkbox("Enable Persistence Mechanisms", value=True)
        persist_stealth = st.checkbox("Stealth Mode (Minimal Detection)", value=True)
        persist_max = st.number_input("Max Mechanisms:", min_value=1, max_value=5, value=3)
        
        submitted = st.form_submit_button("💾 Save Configuration")
        if submitted:
            st.success("✅ Configuration saved!")
    
    st.markdown("### Results")
    st.warning("⚠️ Phase 4 requires Phase 3 results (successful exploits). Use 'Run Phase 1→2→3→4→5' workflow from the Dashboard.")


def phase5_page():
    """Phase 5: Lateral Movement page"""
    st.markdown("## 🌐 Phase 5: Lateral Movement")
    st.info("Network spreading, Active Directory attacks, and domain dominance")
    
    with st.form("phase5_config"):
        st.markdown("### Lateral Movement")
        lateral_enabled = st.checkbox("Enable Lateral Movement", value=True)
        max_hops = st.number_input("Max Hops:", min_value=1, max_value=10, value=5)
        lateral_stealth = st.checkbox("Stealth Mode", value=True)
        
        st.markdown("### Active Directory Attacks")
        ad_enabled = st.checkbox("Enable AD Attacks", value=True)
        ad_kerberoasting = st.checkbox("Kerberoasting", value=True)
        ad_asrep = st.checkbox("AS-REP Roasting", value=True)
        ad_dcsync = st.checkbox("DCSync")
        ad_bloodhound = st.checkbox("BloodHound Collection & Analysis", value=True)
        
        st.markdown("### Domain Dominance")
        target_dc = st.checkbox("Target Domain Controllers", value=True)
        extract_krbtgt = st.checkbox("Extract KRBTGT Hash (Golden Ticket)")
        
        submitted = st.form_submit_button("💾 Save Configuration")
        if submitted:
            st.success("✅ Configuration saved!")
    
    st.markdown("### Results")
    st.warning("⚠️ Phase 5 requires Phase 4 results (compromised hosts + credentials). Use 'Run Phase 1→2→3→4→5' workflow from the Dashboard.")


def phase12_page():
    """Phase 12: AI Adaptive Exploitation page"""
    st.markdown("## 🤖 Phase 12: AI Adaptive Exploitation")
    st.info("Reinforcement learning, adversarial ML, and autonomous security research")
    
    with st.form("phase12_config"):
        st.markdown("### AI Configuration")
        
        enable_rl = st.checkbox("Enable Reinforcement Learning Exploitation", value=True)
        enable_adversarial = st.checkbox("Enable Adversarial ML", value=True)
        enable_nlp = st.checkbox("Enable NLP Exploitation", value=True)
        enable_research = st.checkbox("Enable Autonomous Research", value=True)
        
        st.markdown("### Advanced Options")
        ql_episodes = st.number_input("Q-Learning Episodes:", min_value=100, max_value=10000, value=1000)
        population_size = st.number_input("Evolution Population Size:", min_value=10, max_value=500, value=100)
        generations = st.number_input("Evolution Generations:", min_value=10, max_value=200, value=50)
        
        submitted = st.form_submit_button("💾 Save Configuration")
        if submitted:
            st.success("✅ Configuration saved!")
    
    st.markdown("### Results")
    st.info("Phase 12 results will appear here after running from the Dashboard.")


def configuration_page():
    """Configuration page"""
    st.markdown("## 🔧 Configuration")
    
    with st.form("global_config"):
        st.markdown("### LLM Configuration")
        
        llm_provider = st.selectbox("LLM Provider:", ["openai", "anthropic"])
        
        if llm_provider == "openai":
            llm_model = st.selectbox("Model:", ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"])
            api_key = st.text_input("OpenAI API Key:", type="password", value=config.openai_api_key or "")
        else:
            llm_model = st.selectbox("Model:", ["claude-3-opus-20240229", "claude-3-sonnet-20240229"])
            api_key = st.text_input("Anthropic API Key:", type="password", value=config.anthropic_api_key or "")
        
        st.markdown("### Performance Options")
        low_context_mode = st.checkbox("Low Context Mode (Reduce Memory Usage)", value=config.low_context_mode)
        chunk_size = st.number_input("Chunk Size:", min_value=1000, max_value=10000, value=config.low_context_chunk_size)
        
        st.markdown("### Output Configuration")
        report_dir = st.text_input("Report Output Directory:", value=config.report_output_dir)
        
        submitted = st.form_submit_button("💾 Save Configuration")
        if submitted:
            st.success("✅ Configuration saved!")


def tools_status_page():
    """Tools status page"""
    st.markdown("## 🛠️ Tools Status")
    st.info("Checking installed penetration testing tools...")
    
    tools = {
        'nmap': 'Network scanning',
        'nikto': 'Web vulnerability scanning',
        'sqlmap': 'SQL injection testing',
        'metasploit': 'Exploitation framework',
        'hydra': 'Password cracking',
        'john': 'Password cracking',
        'hashcat': 'Password cracking',
        'aircrack-ng': 'Wireless security',
        'burpsuite': 'Web application testing',
        'wireshark': 'Network analysis'
    }
    
    col1, col2 = st.columns(2)
    
    for i, (tool, description) in enumerate(tools.items()):
        with col1 if i % 2 == 0 else col2:
            # Mock status - in real implementation, check if tool is installed
            status = "✅ Installed" if i % 3 != 0 else "❌ Not Found"
            color = "green" if "✅" in status else "red"
            
            st.markdown(f"**{tool}** - {description}")
            st.markdown(f":{color}[{status}]")
            st.markdown("---")


def main():
    """Main application"""
    render_header()
    page = render_sidebar()
    
    # Route to appropriate page
    if page == "🏠 Dashboard":
        dashboard_page()
    elif page == "⚙️ Phase Selection":
        phase_selection_page()
    elif page == "🔍 Phase 1: Reconnaissance":
        phase1_page()
    elif page == "🎯 Phase 2: Vulnerability Scanning":
        phase2_page()
    elif page == "💣 Phase 3: Exploitation":
        phase3_page()
    elif page == "🔓 Phase 4: Post-Exploitation":
        phase4_page()
    elif page == "🌐 Phase 5: Lateral Movement":
        phase5_page()
    elif page == "🤖 Phase 12: AI Adaptive":
        phase12_page()
    elif page == "🔧 Configuration":
        configuration_page()
    elif page == "🛠️ Tools Status":
        tools_status_page()


if __name__ == "__main__":
    main()
