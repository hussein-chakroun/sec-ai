"""
Report Generation Module
"""
import json
from typing import Dict, Any
from datetime import datetime
from pathlib import Path
from jinja2 import Template
from loguru import logger


class ReportGenerator:
    """Generate penetration testing reports"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Report generator initialized, output: {self.output_dir}")
    
    def generate_report(self, results: Dict[str, Any], formats: list = None) -> Dict[str, Path]:
        """Generate reports in multiple formats"""
        if formats is None:
            formats = ["json", "html"]
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = results.get("target", "unknown").replace(".", "_").replace("/", "_")
        
        generated_files = {}
        
        for fmt in formats:
            if fmt == "json":
                filepath = self._generate_json(results, f"report_{target}_{timestamp}.json")
                generated_files["json"] = filepath
            elif fmt == "html":
                filepath = self._generate_html(results, f"report_{target}_{timestamp}.html")
                generated_files["html"] = filepath
            elif fmt == "txt":
                filepath = self._generate_text(results, f"report_{target}_{timestamp}.txt")
                generated_files["txt"] = filepath
        
        logger.info(f"Generated {len(generated_files)} report(s)")
        return generated_files
    
    def _generate_json(self, results: Dict[str, Any], filename: str) -> Path:
        """Generate JSON report"""
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"JSON report generated: {filepath}")
        return filepath
    
    def _generate_html(self, results: Dict[str, Any], filename: str) -> Path:
        """Generate HTML report"""
        filepath = self.output_dir / filename
        
        template = """
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {{ target }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        h3 {
            color: #7f8c8d;
        }
        .metadata {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .severity-critical {
            color: #c0392b;
            font-weight: bold;
        }
        .severity-high {
            color: #e74c3c;
            font-weight: bold;
        }
        .severity-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .severity-low {
            color: #f1c40f;
        }
        .scan-result {
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin: 20px 0;
        }
        .tool-badge {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.9em;
        }
        pre {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #bdc3c7;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #34495e;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #ecf0f1;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Penetration Test Report</h1>
        
        <div class="metadata">
            <p><strong>Target:</strong> {{ target }}</p>
            <p><strong>Start Time:</strong> {{ start_time }}</p>
            <p><strong>End Time:</strong> {{ end_time }}</p>
            <p><strong>Total Iterations:</strong> {{ total_iterations }}</p>
        </div>
        
        <h2>Executive Summary</h2>
        {% if recommendations.get('raw_response') %}
        <p>{{ recommendations.raw_response }}</p>
        {% else %}
        <p>{{ recommendations.get('executive_summary', 'No summary available') }}</p>
        {% endif %}
        
        <h2>Scan Results</h2>
        {% for scan in scan_results %}
        <div class="scan-result">
            <h3>
                <span class="tool-badge">{{ scan.tool }}</span>
                {{ scan.phase }}
            </h3>
            <p><strong>Timestamp:</strong> {{ scan.timestamp }}</p>
            
            {% if scan.result.parsed %}
            <h4>Findings:</h4>
            {% if scan.result.parsed.open_ports %}
            <table>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
                {% for port in scan.result.parsed.open_ports %}
                <tr>
                    <td>{{ port.port }}</td>
                    <td>{{ port.protocol }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.version }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}
            
            {% if scan.result.parsed.vulnerable %}
            <p class="severity-critical">⚠️ SQL Injection Vulnerability Detected!</p>
            {% endif %}
            {% endif %}
            
            <details>
                <summary>View Raw Output</summary>
                <pre>{{ scan.result.stdout[:1000] if scan.result.stdout else 'No output' }}</pre>
            </details>
        </div>
        {% endfor %}
        
        <h2>Recommendations</h2>
        {% if recommendations.get('vulnerabilities') %}
        <table>
            <tr>
                <th>Severity</th>
                <th>Vulnerability</th>
                <th>Recommendation</th>
            </tr>
            {% for vuln in recommendations.vulnerabilities %}
            <tr>
                <td class="severity-{{ vuln.severity }}">{{ vuln.severity }}</td>
                <td>{{ vuln.name }}</td>
                <td>{{ vuln.recommendation }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>See AI-generated recommendations above.</p>
        {% endif %}
        
        <hr>
        <p style="text-align: center; color: #7f8c8d; font-size: 0.9em;">
            Generated by SEC-AI Autonomous Pentesting Platform
        </p>
    </div>
</body>
</html>
        """
        
        t = Template(template)
        html_content = t.render(
            target=results.get("target"),
            start_time=results.get("start_time"),
            end_time=results.get("end_time"),
            total_iterations=results.get("total_iterations"),
            scan_results=results.get("scan_results", []),
            recommendations=results.get("recommendations", {}),
            context=results.get("context", {})
        )
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {filepath}")
        return filepath
    
    def _generate_text(self, results: Dict[str, Any], filename: str) -> Path:
        """Generate plain text report"""
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("PENETRATION TEST REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Target: {results.get('target')}\n")
            f.write(f"Start Time: {results.get('start_time')}\n")
            f.write(f"End Time: {results.get('end_time')}\n")
            f.write(f"Total Iterations: {results.get('total_iterations')}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("SCAN RESULTS\n")
            f.write("-" * 80 + "\n\n")
            
            for scan in results.get("scan_results", []):
                f.write(f"[{scan['timestamp']}] {scan['tool']} - {scan['phase']}\n")
                if scan.get('result', {}).get('parsed'):
                    f.write(f"  Findings: {json.dumps(scan['result']['parsed'], indent=2)}\n")
                f.write("\n")
            
            f.write("-" * 80 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("-" * 80 + "\n\n")
            f.write(json.dumps(results.get("recommendations", {}), indent=2))
        
        logger.info(f"Text report generated: {filepath}")
        return filepath
