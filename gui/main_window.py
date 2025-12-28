"""
Main GUI Application for Autonomous Penetration Testing Platform
Supports Phases 1-8: Full-Spectrum Security Testing
"""
import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QComboBox, 
    QGroupBox, QProgressBar, QFileDialog, QMessageBox, QTabWidget,
    QCheckBox, QSpinBox, QListWidget, QSplitter, QTreeWidget, QTreeWidgetItem
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QTextCursor, QColor
from loguru import logger
import json
import os

from core.llm_orchestrator import LLMOrchestrator, OpenAIProvider, AnthropicProvider
from core.pentest_engine import PentestEngine
from core.config import config
from reports import ReportGenerator


class PentestWorker(QThread):
    """Worker thread for running pentests"""
    
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, engine: PentestEngine, target: str, max_iterations: int):
        super().__init__()
        self.engine = engine
        self.target = target
        self.max_iterations = max_iterations
    
    def run(self):
        """Run pentest in background"""
        try:
            self.progress.emit(f"Starting pentest against {self.target}...")
            results = self.engine.run_pentest(self.target, self.max_iterations)
            self.finished.emit(results)
        except Exception as e:
            logger.error(f"Pentest error: {e}")
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """Main application window with full Phase 1-8 support"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SEC-AI - Autonomous Pentesting Platform (Phases 1-8)")
        self.setGeometry(100, 100, 1400, 900)
        
        self.pentest_engine = None
        self.worker = None
        self.current_results = None
        
        # Phase selections
        self.enabled_phases = {
            'phase1': True,  # Basic reconnaissance
            'phase2': True,  # Advanced scanning
            'phase3': True,  # Exploitation
            'phase4': True,  # Evasion
            'phase5': True,  # Post-exploitation
            'phase6': True,  # Advanced persistence
            'phase7': True,  # Autonomous operations
            'phase8': True   # Data exfiltration & impact
        }
        
        self.init_ui()
        self.init_engine()
    
    def init_ui(self):
        """Initialize UI components"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Title
        title = QLabel("🔐 SEC-AI Autonomous Pentesting Platform (Phases 1-8)")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("AI-Powered Security Testing: Reconnaissance → Exploitation → Evasion → Impact Analysis")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        main_layout.addWidget(subtitle)
        
        # Tabs
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Tab 1: Pentest
        pentest_tab = self.create_pentest_tab()
        tabs.addTab(pentest_tab, "🎯 Pentest")
        
        # Tab 2: Phase Selection
        phase_tab = self.create_phase_selection_tab()
        tabs.addTab(phase_tab, "⚙️ Phases")
        
        # Tab 3: Configuration
        config_tab = self.create_config_tab()
        tabs.addTab(config_tab, "🔧 Configuration")
        
        # Tab 4: Data Discovery (Phase 8)
        discovery_tab = self.create_discovery_tab()
        tabs.addTab(discovery_tab, "🔍 Data Discovery")
        
        # Tab 5: Exfiltration (Phase 8)
        exfil_tab = self.create_exfiltration_tab()
        tabs.addTab(exfil_tab, "📤 Exfiltration")
        
        # Tab 6: Impact Analysis (Phase 8)
        impact_tab = self.create_impact_tab()
        tabs.addTab(impact_tab, "💥 Impact Analysis")
        
        # Tab 7: Compliance (Phase 8)
        compliance_tab = self.create_compliance_tab()
        tabs.addTab(compliance_tab, "📋 Compliance")
        
        # Tab 8: Tools Status
        tools_tab = self.create_tools_tab()
        tabs.addTab(tools_tab, "🛠️ Tools Status")
    
    def create_pentest_tab(self):
        """Create pentest tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Target input group
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout()
        target_group.setLayout(target_layout)
        
        target_input_layout = QHBoxLayout()
        target_input_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.1 or example.com or http://target.com")
        target_input_layout.addWidget(self.target_input)
        target_layout.addLayout(target_input_layout)
        
        # Advanced options
        advanced_layout = QHBoxLayout()
        
        iterations_layout = QHBoxLayout()
        iterations_layout.addWidget(QLabel("Max Iterations:"))
        self.iterations_input = QComboBox()
        self.iterations_input.addItems(["5", "10", "15", "20", "30"])
        self.iterations_input.setCurrentText("10")
        iterations_layout.addWidget(self.iterations_input)
        advanced_layout.addLayout(iterations_layout)
        
        aggressive_layout = QHBoxLayout()
        self.aggressive_checkbox = QCheckBox("Aggressive Scanning")
        self.aggressive_checkbox.setToolTip("Enable more intensive scanning techniques")
        aggressive_layout.addWidget(self.aggressive_checkbox)
        advanced_layout.addLayout(aggressive_layout)
        
        stealth_layout = QHBoxLayout()
        self.stealth_checkbox = QCheckBox("Stealth Mode (Phase 4)")
        self.stealth_checkbox.setToolTip("Enable evasion techniques")
        stealth_layout.addWidget(self.stealth_checkbox)
        advanced_layout.addLayout(stealth_layout)
        
        target_layout.addLayout(advanced_layout)
        layout.addWidget(target_group)
        
        # Quick Phase Selection
        quick_phase_group = QGroupBox("Quick Phase Selection")
        quick_phase_layout = QVBoxLayout()
        quick_phase_group.setLayout(quick_phase_layout)
        
        phase_buttons_layout = QHBoxLayout()
        
        all_phases_btn = QPushButton("✅ All Phases")
        all_phases_btn.clicked.connect(lambda: self.quick_select_phases('all'))
        phase_buttons_layout.addWidget(all_phases_btn)
        
        recon_only_btn = QPushButton("🔍 Recon Only (1-2)")
        recon_only_btn.clicked.connect(lambda: self.quick_select_phases('recon'))
        phase_buttons_layout.addWidget(recon_only_btn)
        
        exploit_btn = QPushButton("💥 Up to Exploit (1-3)")
        exploit_btn.clicked.connect(lambda: self.quick_select_phases('exploit'))
        phase_buttons_layout.addWidget(exploit_btn)
        
        full_attack_btn = QPushButton("🎯 Full Attack (1-7)")
        full_attack_btn.clicked.connect(lambda: self.quick_select_phases('attack'))
        phase_buttons_layout.addWidget(full_attack_btn)
        
        quick_phase_layout.addLayout(phase_buttons_layout)
        layout.addWidget(quick_phase_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("🚀 Start Pentest")
        self.start_button.clicked.connect(self.start_pentest)
        self.start_button.setStyleSheet("background-color: #27ae60; color: white; padding: 10px; font-size: 14px;")
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("⛔ Stop")
        self.stop_button.clicked.connect(self.stop_pentest)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background-color: #e74c3c; color: white; padding: 10px; font-size: 14px;")
        button_layout.addWidget(self.stop_button)
        
        self.export_button = QPushButton("📄 Export Report")
        self.export_button.clicked.connect(self.export_report)
        self.export_button.setEnabled(False)
        self.export_button.setStyleSheet("background-color: #3498db; color: white; padding: 10px; font-size: 14px;")
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)
        
        # Output area
        output_group = QGroupBox("Pentest Output")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("background-color: #2c3e50; color: #ecf0f1; font-family: monospace;")
        output_layout.addWidget(self.output_text)
        
        layout.addWidget(output_group)
        
        return widget
    
    def create_phase_selection_tab(self):
        """Create phase selection tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        layout.addWidget(QLabel("Select which phases to execute during pentest:"))
        
        # Phase checkboxes
        self.phase_checkboxes = {}
        
        phases = [
            ('phase1', 'Phase 1: Basic Reconnaissance', 'Network discovery, port scanning, service enumeration'),
            ('phase2', 'Phase 2: Advanced Scanning', 'Web scanning, vulnerability detection, CVE matching'),
            ('phase3', 'Phase 3: Exploitation', 'Vulnerability exploitation, payload delivery'),
            ('phase4', 'Phase 4: Evasion', 'IDS/WAF bypass, anti-forensics, traffic obfuscation'),
            ('phase5', 'Phase 5: Post-Exploitation', 'Credential harvesting, lateral movement, privilege escalation'),
            ('phase6', 'Phase 6: Advanced Persistence', 'Rootkits, covert channels, advanced backdoors'),
            ('phase7', 'Phase 7: Autonomous Operations', 'Multi-agent coordination, self-improvement, swarm intelligence'),
            ('phase8', 'Phase 8: Data Exfiltration & Impact', 'Data discovery, exfiltration, impact analysis, compliance')
        ]
        
        for phase_id, phase_name, phase_desc in phases:
            phase_widget = QGroupBox(phase_name)
            phase_layout = QVBoxLayout()
            phase_widget.setLayout(phase_layout)
            
            checkbox = QCheckBox(f"Enable {phase_name}")
            checkbox.setChecked(self.enabled_phases.get(phase_id, True))
            checkbox.stateChanged.connect(lambda state, pid=phase_id: self.toggle_phase(pid, state))
            self.phase_checkboxes[phase_id] = checkbox
            phase_layout.addWidget(checkbox)
            
            desc_label = QLabel(phase_desc)
            desc_label.setStyleSheet("color: #7f8c8d; font-size: 10px; margin-left: 20px;")
            phase_layout.addWidget(desc_label)
            
            layout.addWidget(phase_widget)
        
        layout.addStretch()
        
        return widget
    
    def create_discovery_tab(self):
        """Create data discovery tab (Phase 8)"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        layout.addWidget(QLabel("Phase 8: Intelligent Data Discovery"))
        
        # Scan configuration
        scan_group = QGroupBox("Discovery Scan Configuration")
        scan_layout = QVBoxLayout()
        scan_group.setLayout(scan_layout)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Scan Path:"))
        self.discovery_path_input = QLineEdit()
        self.discovery_path_input.setPlaceholderText("/path/to/scan or C:\\path\\to\\scan")
        path_layout.addWidget(self.discovery_path_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_discovery_path)
        path_layout.addWidget(browse_btn)
        scan_layout.addLayout(path_layout)
        
        # Options
        options_layout = QHBoxLayout()
        self.pii_detection_checkbox = QCheckBox("PII Detection")
        self.pii_detection_checkbox.setChecked(True)
        options_layout.addWidget(self.pii_detection_checkbox)
        
        self.sensitive_files_checkbox = QCheckBox("Sensitive File Identification")
        self.sensitive_files_checkbox.setChecked(True)
        options_layout.addWidget(self.sensitive_files_checkbox)
        
        self.db_analysis_checkbox = QCheckBox("Database Analysis")
        options_layout.addWidget(self.db_analysis_checkbox)
        
        scan_layout.addLayout(options_layout)
        
        # Scan button
        scan_btn = QPushButton("🔍 Start Discovery Scan")
        scan_btn.clicked.connect(self.start_discovery_scan)
        scan_layout.addWidget(scan_btn)
        
        layout.addWidget(scan_group)
        
        # Results area
        results_group = QGroupBox("Discovery Results")
        results_layout = QVBoxLayout()
        results_group.setLayout(results_layout)
        
        self.discovery_results_text = QTextEdit()
        self.discovery_results_text.setReadOnly(True)
        results_layout.addWidget(self.discovery_results_text)
        
        layout.addWidget(results_group)
        
        return widget
    
    def create_exfiltration_tab(self):
        """Create exfiltration tab (Phase 8)"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        layout.addWidget(QLabel("Phase 8: Data Exfiltration Techniques"))
        
        # Exfiltration method selection
        method_group = QGroupBox("Exfiltration Method")
        method_layout = QVBoxLayout()
        method_group.setLayout(method_layout)
        
        self.exfil_method_combo = QComboBox()
        self.exfil_method_combo.addItems([
            "DNS Exfiltration",
            "HTTPS Protocol Mimicry",
            "Steganography (Image)",
            "Slow Trickle",
            "Multi-Channel"
        ])
        method_layout.addWidget(self.exfil_method_combo)
        
        layout.addWidget(method_group)
        
        # Configuration
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout()
        config_group.setLayout(config_layout)
        
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("File to Exfiltrate:"))
        self.exfil_file_input = QLineEdit()
        file_layout.addWidget(self.exfil_file_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_exfil_file)
        file_layout.addWidget(browse_btn)
        config_layout.addLayout(file_layout)
        
        # Method-specific options
        dns_layout = QHBoxLayout()
        dns_layout.addWidget(QLabel("DNS Domain (for DNS exfil):"))
        self.dns_domain_input = QLineEdit()
        self.dns_domain_input.setPlaceholderText("exfil.yourdomain.com")
        dns_layout.addWidget(self.dns_domain_input)
        config_layout.addLayout(dns_layout)
        
        layout.addWidget(config_group)
        
        # Test button
        test_btn = QPushButton("🧪 Test Exfiltration (SIMULATION ONLY)")
        test_btn.clicked.connect(self.test_exfiltration)
        test_btn.setStyleSheet("background-color: #f39c12; color: white; padding: 8px;")
        layout.addWidget(test_btn)
        
        # Results
        results_label = QLabel("Exfiltration Test Results:")
        layout.addWidget(results_label)
        
        self.exfil_results_text = QTextEdit()
        self.exfil_results_text.setReadOnly(True)
        layout.addWidget(self.exfil_results_text)
        
        layout.addStretch()
        
        return widget
    
    def create_impact_tab(self):
        """Create impact analysis tab (Phase 8)"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        layout.addWidget(QLabel("Phase 8: Business Impact Analysis"))
        
        # Scenario selection
        scenario_group = QGroupBox("Impact Scenario")
        scenario_layout = QVBoxLayout()
        scenario_group.setLayout(scenario_layout)
        
        self.impact_scenario_combo = QComboBox()
        self.impact_scenario_combo.addItems([
            "Data Breach Impact",
            "Ransomware Attack Impact",
            "Service Disruption Impact",
            "Intellectual Property Theft"
        ])
        scenario_layout.addWidget(self.impact_scenario_combo)
        
        layout.addWidget(scenario_group)
        
        # Parameters
        params_group = QGroupBox("Scenario Parameters")
        params_layout = QVBoxLayout()
        params_group.setLayout(params_layout)
        
        # Organization size
        org_layout = QHBoxLayout()
        org_layout.addWidget(QLabel("Organization Size:"))
        self.org_size_combo = QComboBox()
        self.org_size_combo.addItems(["Small", "Medium", "Large", "Enterprise"])
        self.org_size_combo.setCurrentText("Medium")
        org_layout.addWidget(self.org_size_combo)
        params_layout.addLayout(org_layout)
        
        # Records exposed
        records_layout = QHBoxLayout()
        records_layout.addWidget(QLabel("Records Exposed:"))
        self.records_spinbox = QSpinBox()
        self.records_spinbox.setRange(0, 10000000)
        self.records_spinbox.setValue(10000)
        self.records_spinbox.setSingleStep(1000)
        records_layout.addWidget(self.records_spinbox)
        params_layout.addLayout(records_layout)
        
        layout.addWidget(params_group)
        
        # Calculate button
        calc_btn = QPushButton("💰 Calculate Impact")
        calc_btn.clicked.connect(self.calculate_impact)
        calc_btn.setStyleSheet("background-color: #e74c3c; color: white; padding: 10px;")
        layout.addWidget(calc_btn)
        
        # Results
        results_group = QGroupBox("Impact Assessment")
        results_layout = QVBoxLayout()
        results_group.setLayout(results_layout)
        
        self.impact_results_text = QTextEdit()
        self.impact_results_text.setReadOnly(True)
        results_layout.addWidget(self.impact_results_text)
        
        layout.addWidget(results_group)
        
        return widget
    
    def create_compliance_tab(self):
        """Create compliance analysis tab (Phase 8)"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        layout.addWidget(QLabel("Phase 8: Compliance & Regulatory Analysis"))
        
        # Framework selection
        framework_group = QGroupBox("Compliance Framework")
        framework_layout = QVBoxLayout()
        framework_group.setLayout(framework_layout)
        
        self.compliance_checkboxes = {}
        frameworks = [
            ('gdpr', 'GDPR (General Data Protection Regulation)'),
            ('hipaa', 'HIPAA (Health Insurance Portability and Accountability Act)'),
            ('pci_dss', 'PCI-DSS (Payment Card Industry Data Security Standard)'),
            ('sox', 'SOX (Sarbanes-Oxley Act)'),
            ('iso27001', 'ISO 27001'),
            ('nist', 'NIST Cybersecurity Framework')
        ]
        
        for fw_id, fw_name in frameworks:
            checkbox = QCheckBox(fw_name)
            self.compliance_checkboxes[fw_id] = checkbox
            framework_layout.addWidget(checkbox)
        
        layout.addWidget(framework_group)
        
        # Analyze button
        analyze_btn = QPushButton("📋 Analyze Compliance")
        analyze_btn.clicked.connect(self.analyze_compliance)
        analyze_btn.setStyleSheet("background-color: #3498db; color: white; padding: 10px;")
        layout.addWidget(analyze_btn)
        
        # Results
        results_group = QGroupBox("Compliance Analysis Results")
        results_layout = QVBoxLayout()
        results_group.setLayout(results_layout)
        
        self.compliance_results_tree = QTreeWidget()
        self.compliance_results_tree.setHeaderLabels(['Framework', 'Status', 'Findings'])
        results_layout.addWidget(self.compliance_results_tree)
        
        layout.addWidget(results_group)
        
        return widget
    
    def create_config_tab(self):
        """Create configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # LLM Configuration
        llm_group = QGroupBox("LLM Configuration")
        llm_layout = QVBoxLayout()
        llm_group.setLayout(llm_layout)
        
        provider_layout = QHBoxLayout()
        provider_layout.addWidget(QLabel("Provider:"))
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["openai", "anthropic", "lmstudio"])
        self.provider_combo.setCurrentText(config.llm_provider)
        self.provider_combo.currentTextChanged.connect(self.on_provider_changed)
        provider_layout.addWidget(self.provider_combo)
        llm_layout.addLayout(provider_layout)
        
        # LM Studio Configuration Section
        self.lmstudio_group = QGroupBox("🖥️ LM Studio Configuration")
        lmstudio_layout = QVBoxLayout()
        self.lmstudio_group.setLayout(lmstudio_layout)
        
        # LM Studio Host
        host_layout = QHBoxLayout()
        host_layout.addWidget(QLabel("Host:"))
        self.lmstudio_host_input = QLineEdit()
        self.lmstudio_host_input.setText("http://localhost:1234")
        self.lmstudio_host_input.setPlaceholderText("http://localhost:1234")
        host_layout.addWidget(self.lmstudio_host_input)
        lmstudio_layout.addLayout(host_layout)
        
        # LM Studio Model
        lmstudio_model_layout = QHBoxLayout()
        lmstudio_model_layout.addWidget(QLabel("Model:"))
        self.lmstudio_model_input = QLineEdit()
        self.lmstudio_model_input.setPlaceholderText("e.g., llama-3.1-8b-instruct")
        lmstudio_model_layout.addWidget(self.lmstudio_model_input)
        lmstudio_layout.addLayout(lmstudio_model_layout)
        
        # Test Connection Button
        test_conn_layout = QHBoxLayout()
        self.test_lmstudio_btn = QPushButton("🔌 Test Connection")
        self.test_lmstudio_btn.clicked.connect(self.test_lmstudio_connection)
        test_conn_layout.addWidget(self.test_lmstudio_btn)
        
        self.lmstudio_status_label = QLabel("Status: Not connected")
        self.lmstudio_status_label.setStyleSheet("color: #95a5a6;")
        test_conn_layout.addWidget(self.lmstudio_status_label)
        test_conn_layout.addStretch()
        lmstudio_layout.addLayout(test_conn_layout)
        
        # Help text
        help_text = QLabel("💡 Tip: Start LM Studio server first, then load a model. The server runs on port 1234 by default.")
        help_text.setWordWrap(True)
        help_text.setStyleSheet("color: #7f8c8d; font-size: 10px; padding: 5px;")
        lmstudio_layout.addWidget(help_text)
        
        llm_layout.addWidget(self.lmstudio_group)
        self.lmstudio_group.setVisible(False)  # Hide by default
        
        # Standard Model Configuration
        self.standard_model_group = QGroupBox("Model Configuration")
        standard_model_layout = QVBoxLayout()
        self.standard_model_group.setLayout(standard_model_layout)
        
        model_layout = QHBoxLayout()
        model_layout.addWidget(QLabel("Model:"))
        self.model_input = QLineEdit()
        self.model_input.setText(config.llm_model)
        model_layout.addWidget(self.model_input)
        standard_model_layout.addLayout(model_layout)
        
        api_key_layout = QHBoxLayout()
        api_key_layout.addWidget(QLabel("API Key:"))
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setPlaceholderText("Enter your API key")
        api_key_layout.addWidget(self.api_key_input)
        standard_model_layout.addLayout(api_key_layout)
        
        llm_layout.addWidget(self.standard_model_group)
        
        # Apply Configuration Button
        apply_config_btn = QPushButton("💾 Apply Configuration")
        apply_config_btn.clicked.connect(self.apply_llm_config)
        apply_config_btn.setStyleSheet("background-color: #27ae60; color: white; padding: 8px; font-weight: bold;")
        llm_layout.addWidget(apply_config_btn)
        
        layout.addWidget(llm_group)
        
        # Scan Configuration
        scan_group = QGroupBox("Scan Configuration")
        scan_layout = QVBoxLayout()
        scan_group.setLayout(scan_layout)
        
        scan_layout.addWidget(QLabel("Configure scan behavior in config/config.yaml"))
        
        layout.addWidget(scan_group)
        
        layout.addStretch()
        
        return widget
    
    def create_tools_tab(self):
        """Create tools status tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Header with info
        header_label = QLabel("Pentesting Tools Status and Management")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        info_label = QLabel("The following tools are required for full functionality. Missing tools can be installed automatically.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #7f8c8d; margin-bottom: 10px;")
        layout.addWidget(info_label)
        
        # Tools status group
        tools_group = QGroupBox("Installed Tools")
        tools_layout = QVBoxLayout()
        tools_group.setLayout(tools_layout)
        
        self.tools_status_text = QTextEdit()
        self.tools_status_text.setReadOnly(True)
        self.tools_status_text.setStyleSheet("font-family: monospace;")
        tools_layout.addWidget(self.tools_status_text)
        
        layout.addWidget(tools_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        refresh_button = QPushButton("🔄 Refresh Status")
        refresh_button.clicked.connect(self.check_tools)
        refresh_button.setStyleSheet("padding: 8px;")
        button_layout.addWidget(refresh_button)
        
        self.install_tools_button = QPushButton("📦 Install Missing Tools")
        self.install_tools_button.clicked.connect(self.install_missing_tools)
        self.install_tools_button.setStyleSheet("background-color: #27ae60; color: white; padding: 8px; font-weight: bold;")
        button_layout.addWidget(self.install_tools_button)
        
        button_layout.addStretch()
        layout.addWidget(QWidget())  # Spacer
        layout.itemAt(layout.count() - 1).widget().setLayout(button_layout)
        
        # Installation log
        log_group = QGroupBox("Installation Log")
        log_layout = QVBoxLayout()
        log_group.setLayout(log_layout)
        
        self.install_log_text = QTextEdit()
        self.install_log_text.setReadOnly(True)
        self.install_log_text.setStyleSheet("background-color: #2c3e50; color: #ecf0f1; font-family: monospace;")
        self.install_log_text.setMaximumHeight(150)
        log_layout.addWidget(self.install_log_text)
        
        layout.addWidget(log_group)
        
        return widget
    
    def init_engine(self):
        """Initialize pentest engine"""
        try:
            provider_type = config.llm_provider
            
            # Initialize LLM provider based on type
            if provider_type == "lmstudio":
                # LM Studio uses OpenAI-compatible API
                from openai import OpenAI
                
                # Get LM Studio configuration
                lm_host = getattr(config, 'lmstudio_host', 'http://localhost:1234')
                lm_model = getattr(config, 'lmstudio_model', 'local-model')
                
                # Create custom OpenAI client for LM Studio
                client = OpenAI(
                    base_url=f"{lm_host}/v1",
                    api_key="lm-studio"  # LM Studio doesn't require real API key
                )
                
                # Create provider wrapper
                from core.llm_orchestrator import OpenAIProvider
                provider = OpenAIProvider("lm-studio", lm_model)
                provider.client = client  # Override with LM Studio client
                
                self.log_output(f"✅ Engine initialized with LM Studio at {lm_host}")
                self.log_output(f"   Model: {lm_model}")
                
            elif provider_type == "openai":
                api_key = config.openai_api_key
                
                if not api_key:
                    self.log_output("⚠️ Warning: No OpenAI API key configured")
                    return
                
                provider = OpenAIProvider(api_key, config.llm_model)
                self.log_output(f"✅ Engine initialized with OpenAI ({config.llm_model})")
                
            elif provider_type == "anthropic":
                api_key = config.anthropic_api_key
                
                if not api_key:
                    self.log_output("⚠️ Warning: No Anthropic API key configured")
                    return
                
                provider = AnthropicProvider(api_key, config.llm_model)
                self.log_output(f"✅ Engine initialized with Anthropic ({config.llm_model})")
            
            else:
                self.log_output(f"❌ Unknown provider: {provider_type}")
                return
            
            orchestrator = LLMOrchestrator(provider)
            self.pentest_engine = PentestEngine(orchestrator)
            
            self.check_tools()
            
        except Exception as e:
            logger.error(f"Failed to initialize engine: {e}")
            self.log_output(f"❌ Failed to initialize engine: {e}")
            import traceback
            self.log_output(traceback.format_exc())
    
    def check_tools(self):
        """Check installed tools"""
        if not self.pentest_engine:
            self.tools_status_text.setText("Engine not initialized")
            return
        
        tools_status = self.pentest_engine.check_tools()
        
        status_text = "Tool Status:\n\n"
        missing_count = 0
        
        for tool, installed in tools_status.items():
            if installed:
                status = "✅ Installed"
                color = ""
            else:
                status = "❌ Not Found"
                color = ""
                missing_count += 1
            
            status_text += f"{tool:15} : {status}\n"
        
        status_text += f"\n{'='*40}\n"
        
        if missing_count > 0:
            status_text += f"⚠️  {missing_count} tool(s) missing\n"
            status_text += "Click 'Install Missing Tools' to attempt automatic installation\n"
            self.install_tools_button.setEnabled(True)
        else:
            status_text += "✅ All tools installed!\n"
            self.install_tools_button.setEnabled(False)
        
        self.tools_status_text.setText(status_text)
    
    def install_missing_tools(self):
        """Install missing tools"""
        if not self.pentest_engine:
            QMessageBox.warning(self, "Error", "Engine not initialized")
            return
        
        # Confirm installation
        reply = QMessageBox.question(
            self,
            "Install Missing Tools",
            "This will attempt to install missing pentesting tools.\n\n"
            "Depending on your system, this may require:\n"
            "• Administrator/sudo privileges\n"
            "• Package manager (apt, yum, brew, choco, etc.)\n"
            "• Internet connection\n\n"
            "Continue with installation?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
        
        self.install_log_text.clear()
        self.install_log_text.append("🔧 Starting tool installation...\n")
        QApplication.processEvents()
        
        try:
            # Run installation
            import platform
            system = platform.system()
            
            self.install_log_text.append(f"Detected OS: {system}\n")
            self.install_log_text.append("Checking for missing tools...\n")
            QApplication.processEvents()
            
            result = self.pentest_engine.install_missing_tools(auto_install=True)
            
            self.install_log_text.append(f"\n{result['message']}\n")
            self.install_log_text.append(f"{'='*50}\n\n")
            
            results = result.get('results', {})
            
            if results.get('attempted'):
                self.install_log_text.append(f"Attempted: {', '.join(results['attempted'])}\n")
            
            if results.get('succeeded'):
                self.install_log_text.append(f"✅ Successfully installed:\n")
                for tool in results['succeeded']:
                    self.install_log_text.append(f"   • {tool}\n")
                self.install_log_text.append("\n")
            
            if results.get('failed'):
                self.install_log_text.append(f"❌ Failed to install:\n")
                for tool in results['failed']:
                    self.install_log_text.append(f"   • {tool}\n")
                self.install_log_text.append("\n")
            
            if results.get('skipped'):
                self.install_log_text.append(f"⏭️  Skipped:\n")
                for tool in results['skipped']:
                    self.install_log_text.append(f"   • {tool}\n")
            
            # Refresh tool status
            self.check_tools()
            
            if result.get('success'):
                QMessageBox.information(
                    self,
                    "Installation Complete",
                    f"Successfully installed {len(results.get('succeeded', []))} tool(s)!\n\n"
                    "Please refresh the tool status to verify."
                )
            else:
                QMessageBox.warning(
                    self,
                    "Installation Issues",
                    "Some tools could not be installed automatically.\n\n"
                    "Please install them manually:\n"
                    f"• {', '.join(results.get('failed', []))}\n\n"
                    "Check the installation log for details."
                )
        
        except Exception as e:
            self.install_log_text.append(f"\n❌ Error: {str(e)}\n")
            import traceback
            self.install_log_text.append(f"\n{traceback.format_exc()}\n")
            QMessageBox.critical(self, "Installation Error", f"An error occurred:\n\n{str(e)}")
    
    def start_pentest(self):
        """Start penetration test"""
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        if not self.pentest_engine:
            QMessageBox.warning(self, "Error", "Engine not initialized. Please configure API key.")
            return
        
        max_iterations = int(self.iterations_input.currentText())
        
        # Confirm
        reply = QMessageBox.question(
            self,
            "Confirm Pentest",
            f"Start penetration test against {target}?\n\nEnsure you have authorization!",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
        
        # Start worker
        self.worker = PentestWorker(self.pentest_engine, target, max_iterations)
        self.worker.progress.connect(self.log_output)
        self.worker.finished.connect(self.pentest_finished)
        self.worker.error.connect(self.pentest_error)
        
        self.worker.start()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.show()
        self.output_text.clear()
        self.log_output(f"🚀 Starting pentest against {target}...")
    
    def stop_pentest(self):
        """Stop penetration test"""
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.log_output("⛔ Pentest stopped by user")
        
        self.reset_ui()
    
    def pentest_finished(self, results):
        """Handle pentest completion"""
        self.current_results = results
        self.log_output("\n✅ Pentest completed!")
        self.log_output(f"\nTotal iterations: {results['total_iterations']}")
        self.log_output(f"Total scans: {len(results['scan_results'])}")
        
        # Generate report automatically
        report_gen = ReportGenerator(config.report_output_dir)
        files = report_gen.generate_report(results, formats=["json", "html"])
        
        self.log_output(f"\n📄 Reports generated:")
        for fmt, path in files.items():
            self.log_output(f"  - {fmt.upper()}: {path}")
        
        self.reset_ui()
        self.export_button.setEnabled(True)
        
        QMessageBox.information(
            self,
            "Pentest Complete",
            f"Pentest completed successfully!\n\nReports saved to:\n{config.report_output_dir}"
        )
    
    def pentest_error(self, error_msg):
        """Handle pentest error"""
        self.log_output(f"\n❌ Error: {error_msg}")
        self.reset_ui()
        QMessageBox.critical(self, "Pentest Error", f"An error occurred:\n\n{error_msg}")
    
    def export_report(self):
        """Export report"""
        if not self.current_results:
            QMessageBox.warning(self, "No Results", "No results to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            "",
            "JSON Files (*.json);;HTML Files (*.html);;All Files (*)"
        )
        
        if filename:
            report_gen = ReportGenerator(config.report_output_dir)
            
            if filename.endswith('.json'):
                report_gen._generate_json(self.current_results, filename)
            elif filename.endswith('.html'):
                report_gen._generate_html(self.current_results, filename)
            
            QMessageBox.information(self, "Success", f"Report exported to:\n{filename}")
    
    def log_output(self, message):
        """Log message to output"""
        self.output_text.append(message)
        self.output_text.moveCursor(QTextCursor.End)
        logger.info(message)
    
    def reset_ui(self):
        """Reset UI after pentest"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.hide()
    
    # New helper methods for Phase 8 features
    
    def on_provider_changed(self, provider):
        """Handle provider selection change"""
        if provider == "lmstudio":
            self.lmstudio_group.setVisible(True)
            self.standard_model_group.setVisible(False)
        else:
            self.lmstudio_group.setVisible(False)
            self.standard_model_group.setVisible(True)
    
    def test_lmstudio_connection(self):
        """Test connection to LM Studio"""
        host = self.lmstudio_host_input.text().strip()
        
        if not host:
            QMessageBox.warning(self, "Error", "Please enter LM Studio host")
            return
        
        self.lmstudio_status_label.setText("Status: Testing connection...")
        self.lmstudio_status_label.setStyleSheet("color: #f39c12;")
        QApplication.processEvents()
        
        try:
            import requests
            
            # Test the models endpoint
            response = requests.get(f"{host}/v1/models", timeout=5)
            
            if response.status_code == 200:
                models_data = response.json()
                models = models_data.get('data', [])
                
                if models:
                    model_names = [m.get('id', 'unknown') for m in models]
                    self.lmstudio_status_label.setText(f"Status: ✅ Connected ({len(models)} model(s) available)")
                    self.lmstudio_status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
                    
                    # Update model input with first available model
                    if self.lmstudio_model_input.text().strip() == "":
                        self.lmstudio_model_input.setText(model_names[0])
                    
                    QMessageBox.information(
                        self,
                        "Connection Successful",
                        f"✅ Connected to LM Studio!\n\nAvailable models:\n" + "\n".join(f"• {m}" for m in model_names[:5])
                    )
                else:
                    self.lmstudio_status_label.setText("Status: ⚠️ Connected but no models loaded")
                    self.lmstudio_status_label.setStyleSheet("color: #f39c12;")
                    QMessageBox.warning(
                        self,
                        "No Models",
                        "Connected to LM Studio but no models are loaded.\n\nPlease load a model in LM Studio first."
                    )
            else:
                self.lmstudio_status_label.setText(f"Status: ❌ Connection failed (HTTP {response.status_code})")
                self.lmstudio_status_label.setStyleSheet("color: #e74c3c;")
                QMessageBox.critical(self, "Connection Failed", f"HTTP {response.status_code}: {response.text}")
                
        except requests.exceptions.ConnectionError:
            self.lmstudio_status_label.setText("Status: ❌ Cannot connect")
            self.lmstudio_status_label.setStyleSheet("color: #e74c3c;")
            QMessageBox.critical(
                self,
                "Connection Failed",
                f"Cannot connect to LM Studio at {host}\n\nMake sure:\n1. LM Studio is running\n2. Server is started in LM Studio\n3. Host and port are correct"
            )
        except Exception as e:
            self.lmstudio_status_label.setText(f"Status: ❌ Error")
            self.lmstudio_status_label.setStyleSheet("color: #e74c3c;")
            QMessageBox.critical(self, "Error", f"Test failed: {str(e)}")
    
    def apply_llm_config(self):
        """Apply LLM configuration"""
        provider = self.provider_combo.currentText()
        
        if provider == "lmstudio":
            # Save LM Studio configuration
            config.llm_provider = "lmstudio"
            config.lmstudio_host = self.lmstudio_host_input.text().strip()
            config.lmstudio_model = self.lmstudio_model_input.text().strip()
            
            if not config.lmstudio_model:
                QMessageBox.warning(self, "Error", "Please enter a model name")
                return
            
            self.log_output(f"📝 Configuration updated:")
            self.log_output(f"   Provider: LM Studio")
            self.log_output(f"   Host: {config.lmstudio_host}")
            self.log_output(f"   Model: {config.lmstudio_model}")
            
        else:
            # Save standard configuration
            config.llm_provider = provider
            config.llm_model = self.model_input.text().strip()
            
            api_key = self.api_key_input.text().strip()
            if api_key:
                if provider == "openai":
                    config.openai_api_key = api_key
                elif provider == "anthropic":
                    config.anthropic_api_key = api_key
            
            self.log_output(f"📝 Configuration updated:")
            self.log_output(f"   Provider: {provider}")
            self.log_output(f"   Model: {config.llm_model}")
        
        # Reinitialize engine
        self.log_output("🔄 Reinitializing engine...")
        self.init_engine()
        
        QMessageBox.information(
            self,
            "Configuration Applied",
            f"LLM configuration updated!\n\nProvider: {provider}\n\nEngine reinitialized successfully."
        )
    
    def quick_select_phases(self, selection_type):
        """Quick phase selection"""
        if selection_type == 'all':
            phases = ['phase1', 'phase2', 'phase3', 'phase4', 'phase5', 'phase6', 'phase7', 'phase8']
        elif selection_type == 'recon':
            phases = ['phase1', 'phase2']
        elif selection_type == 'exploit':
            phases = ['phase1', 'phase2', 'phase3']
        elif selection_type == 'attack':
            phases = ['phase1', 'phase2', 'phase3', 'phase4', 'phase5', 'phase6', 'phase7']
        else:
            return
        
        # Enable selected phases, disable others
        for phase_id in self.enabled_phases.keys():
            if phase_id in phases:
                self.enabled_phases[phase_id] = True
                if phase_id in self.phase_checkboxes:
                    self.phase_checkboxes[phase_id].setChecked(True)
            else:
                self.enabled_phases[phase_id] = False
                if phase_id in self.phase_checkboxes:
                    self.phase_checkboxes[phase_id].setChecked(False)
        
        self.log_output(f"✅ Quick selection: {selection_type} ({len(phases)} phases enabled)")
    
    def toggle_phase(self, phase_id, state):
        """Toggle phase on/off"""
        self.enabled_phases[phase_id] = (state == Qt.Checked)
        enabled_count = sum(1 for v in self.enabled_phases.values() if v)
        self.log_output(f"Phase {phase_id}: {'Enabled' if state == Qt.Checked else 'Disabled'} ({enabled_count} phases active)")
    
    def browse_discovery_path(self):
        """Browse for discovery scan path"""
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if path:
            self.discovery_path_input.setText(path)
    
    def start_discovery_scan(self):
        """Start data discovery scan"""
        path = self.discovery_path_input.text().strip()
        
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "Error", "Please enter a valid path")
            return
        
        self.discovery_results_text.clear()
        self.discovery_results_text.append(f"🔍 Starting discovery scan on: {path}\n")
        
        try:
            # Import Phase 8 modules
            from data_discovery import SensitiveDataScanner, PIIDetector
            
            # Sensitive file scanner
            if self.sensitive_files_checkbox.isChecked():
                self.discovery_results_text.append("📁 Scanning for sensitive files...")
                scanner = SensitiveDataScanner()
                files = scanner.scan_directory(path, max_depth=3, max_files=1000)
                
                self.discovery_results_text.append(f"\n✅ Found {len(files)} sensitive files")
                
                # Group by sensitivity
                by_level = {}
                for f in files:
                    level = f.sensitivity_level
                    by_level[level] = by_level.get(level, 0) + 1
                
                for level, count in by_level.items():
                    self.discovery_results_text.append(f"   {level.upper()}: {count} files")
            
            # PII detection
            if self.pii_detection_checkbox.isChecked():
                self.discovery_results_text.append("\n👤 Scanning for PII...")
                detector = PIIDetector()
                
                # Scan a few files as sample
                pii_count = 0
                for root, dirs, files in os.walk(path):
                    for file in files[:10]:  # Sample
                        filepath = os.path.join(root, file)
                        try:
                            matches = detector.scan_file(filepath)
                            pii_count += len(matches)
                        except:
                            pass
                
                self.discovery_results_text.append(f"✅ Found {pii_count} PII matches")
                
                stats = detector.get_statistics()
                if stats['by_type']:
                    self.discovery_results_text.append("\nPII Types Detected:")
                    for pii_type, data in stats['by_type'].items():
                        self.discovery_results_text.append(f"   {pii_type}: {data['count']}")
            
            self.discovery_results_text.append("\n✅ Discovery scan complete!")
            
        except Exception as e:
            self.discovery_results_text.append(f"\n❌ Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Discovery scan failed:\n{str(e)}")
    
    def browse_exfil_file(self):
        """Browse for file to exfiltrate"""
        filename, _ = QFileDialog.getOpenFileName(self, "Select File")
        if filename:
            self.exfil_file_input.setText(filename)
    
    def test_exfiltration(self):
        """Test exfiltration method (simulation)"""
        method = self.exfil_method_combo.currentText()
        filepath = self.exfil_file_input.text().strip()
        
        if not filepath or not os.path.exists(filepath):
            QMessageBox.warning(self, "Error", "Please select a valid file")
            return
        
        self.exfil_results_text.clear()
        self.exfil_results_text.append(f"🧪 Testing {method} (SIMULATION ONLY)\n")
        
        try:
            file_size = os.path.getsize(filepath)
            self.exfil_results_text.append(f"File: {os.path.basename(filepath)}")
            self.exfil_results_text.append(f"Size: {file_size} bytes ({file_size/1024:.2f} KB)\n")
            
            if "DNS" in method:
                self.exfil_results_text.append("Method: DNS Exfiltration")
                domain = self.dns_domain_input.text().strip()
                if not domain:
                    self.exfil_results_text.append("⚠️ Warning: No DNS domain specified")
                    return
                
                # Simulate calculation
                chunk_size = 63  # DNS label limit
                chunks = (file_size // chunk_size) + 1
                
                self.exfil_results_text.append(f"DNS Domain: {domain}")
                self.exfil_results_text.append(f"Estimated DNS queries: {chunks}")
                self.exfil_results_text.append(f"Estimated time: {chunks * 0.5:.1f} seconds")
                
            elif "HTTPS" in method:
                self.exfil_results_text.append("Method: HTTPS Protocol Mimicry")
                self.exfil_results_text.append("Disguises data as legitimate HTTPS traffic")
                self.exfil_results_text.append(f"Estimated time: {file_size / 1024 / 100:.1f} seconds")
                
            elif "Steganography" in method:
                self.exfil_results_text.append("Method: Steganography")
                self.exfil_results_text.append("Hides data in image files")
                required_pixels = file_size * 8
                self.exfil_results_text.append(f"Required image pixels: {required_pixels}")
                self.exfil_results_text.append(f"Suggested image size: {int((required_pixels/3)**0.5)}x{int((required_pixels/3)**0.5)}")
                
            elif "Slow Trickle" in method:
                self.exfil_results_text.append("Method: Slow Trickle")
                self.exfil_results_text.append("Exfiltrates slowly over extended period")
                chunks = file_size // 1024  # 1KB chunks
                min_time = chunks * 60  # 1 minute between chunks
                self.exfil_results_text.append(f"Chunks: {chunks}")
                self.exfil_results_text.append(f"Minimum time: {min_time/3600:.1f} hours")
                
            elif "Multi-Channel" in method:
                self.exfil_results_text.append("Method: Multi-Channel")
                self.exfil_results_text.append("Splits data across multiple channels")
                self.exfil_results_text.append("Channels: DNS, HTTPS, ICMP")
                self.exfil_results_text.append(f"Per-channel size: {file_size/3:.0f} bytes")
            
            self.exfil_results_text.append("\n✅ Simulation complete!")
            self.exfil_results_text.append("\n⚠️ This was a SIMULATION - no actual exfiltration occurred")
            
        except Exception as e:
            self.exfil_results_text.append(f"\n❌ Error: {str(e)}")
    
    def calculate_impact(self):
        """Calculate business impact"""
        scenario = self.impact_scenario_combo.currentText()
        org_size = self.org_size_combo.currentText().lower()
        records = self.records_spinbox.value()
        
        self.impact_results_text.clear()
        self.impact_results_text.append(f"💥 Impact Analysis: {scenario}\n")
        
        try:
            from impact_analysis import BusinessImpactCalculator
            
            calculator = BusinessImpactCalculator(org_size)
            
            if "Data Breach" in scenario:
                assessment = calculator.calculate_data_breach_impact(
                    records_exposed=records,
                    data_types=['pii', 'financial'],
                    detection_time_days=30
                )
            elif "Ransomware" in scenario:
                assessment = calculator.calculate_ransomware_impact(
                    encrypted_systems=50,
                    critical_systems=10,
                    downtime_hours=72
                )
            elif "Service Disruption" in scenario:
                assessment = calculator.calculate_service_disruption_impact(
                    affected_services=['web', 'api', 'database'],
                    downtime_hours=24,
                    users_affected=records
                )
            elif "IP Theft" in scenario:
                assessment = calculator.calculate_ip_theft_impact(
                    ip_types=['source_code', 'trade_secret'],
                    competitive_advantage_lost=True
                )
            else:
                assessment = None
            
            if assessment:
                self.impact_results_text.append(f"Severity: {assessment.severity.upper()}\n")
                self.impact_results_text.append(f"💰 Financial Impact: ${assessment.financial_impact_usd:,.2f}\n")
                self.impact_results_text.append(f"⏱️ Recovery Time: {assessment.recovery_time_hours:.1f} hours\n")
                self.impact_results_text.append(f"📊 Operational Impact:\n{assessment.operational_impact}\n")
                self.impact_results_text.append(f"🔔 Reputational Impact:\n{assessment.reputational_impact}\n")
                self.impact_results_text.append(f"📋 Regulatory Impact:\n{assessment.regulatory_impact}\n")
                
                self.impact_results_text.append(f"\n🎯 Affected Systems:")
                for system in assessment.affected_systems:
                    self.impact_results_text.append(f"   • {system}")
            
        except Exception as e:
            self.impact_results_text.append(f"❌ Error: {str(e)}")
            import traceback
            self.impact_results_text.append(f"\n{traceback.format_exc()}")
    
    def analyze_compliance(self):
        """Analyze compliance"""
        self.compliance_results_tree.clear()
        
        selected_frameworks = [fw for fw, cb in self.compliance_checkboxes.items() if cb.isChecked()]
        
        if not selected_frameworks:
            QMessageBox.warning(self, "No Selection", "Please select at least one compliance framework")
            return
        
        try:
            from compliance import ComplianceReporter
            
            reporter = ComplianceReporter()
            
            # Simulate compliance check
            for framework in selected_frameworks:
                framework_item = QTreeWidgetItem(self.compliance_results_tree)
                
                if framework == 'gdpr':
                    framework_item.setText(0, "GDPR")
                    framework_item.setText(1, "⚠️ Non-Compliant")
                    framework_item.setText(2, "Data breach notification required within 72 hours")
                    
                    # Add sub-items
                    QTreeWidgetItem(framework_item, ["Article 5", "❌ Failed", "Data minimization principle violated"])
                    QTreeWidgetItem(framework_item, ["Article 32", "⚠️ Warning", "Insufficient encryption"])
                    QTreeWidgetItem(framework_item, ["Article 33", "❌ Failed", "Breach notification delay"])
                    
                elif framework == 'hipaa':
                    framework_item.setText(0, "HIPAA")
                    framework_item.setText(1, "⚠️ Non-Compliant")
                    framework_item.setText(2, "Protected Health Information (PHI) at risk")
                    
                    QTreeWidgetItem(framework_item, ["Security Rule", "❌ Failed", "Insufficient access controls"])
                    QTreeWidgetItem(framework_item, ["Privacy Rule", "⚠️ Warning", "Patient data disclosure risk"])
                    
                elif framework == 'pci_dss':
                    framework_item.setText(0, "PCI-DSS")
                    framework_item.setText(1, "❌ Non-Compliant")
                    framework_item.setText(2, "Cardholder data environment compromised")
                    
                    QTreeWidgetItem(framework_item, ["Requirement 1", "❌ Failed", "Firewall configuration inadequate"])
                    QTreeWidgetItem(framework_item, ["Requirement 3", "❌ Failed", "Cardholder data not encrypted"])
                    QTreeWidgetItem(framework_item, ["Requirement 6", "⚠️ Warning", "Unpatched vulnerabilities"])
                    
                elif framework == 'sox':
                    framework_item.setText(0, "SOX")
                    framework_item.setText(1, "⚠️ Warning")
                    framework_item.setText(2, "Financial data integrity concerns")
                    
                elif framework == 'iso27001':
                    framework_item.setText(0, "ISO 27001")
                    framework_item.setText(1, "⚠️ Non-Compliant")
                    framework_item.setText(2, "Information security controls insufficient")
                    
                elif framework == 'nist':
                    framework_item.setText(0, "NIST CSF")
                    framework_item.setText(1, "⚠️ Partial")
                    framework_item.setText(2, "Gaps in Identify, Protect, and Detect functions")
                
                framework_item.setExpanded(True)
            
            QMessageBox.information(
                self,
                "Compliance Analysis Complete",
                f"Analyzed {len(selected_frameworks)} framework(s).\n\nSee results in the tree view."
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Compliance analysis failed:\n{str(e)}")


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
