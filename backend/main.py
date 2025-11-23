from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel
import pandas as pd
import numpy as np
from io import BytesIO
import hashlib
from datetime import datetime
import json
from typing import List, Dict, Tuple, Optional
import joblib
import shap
from enum import IntEnum
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
import io


def sanitize_for_json(obj):
    '''Convert numpy types to Python native types for JSON serialization'''
    import numpy as np
    
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: sanitize_for_json(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [sanitize_for_json(item) for item in obj]
    else:
        return obj

# ==================== SEVERITY ENUM ====================
class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

# ==================== TRIAGE ACTIONS & EXPLANATIONS ====================
TRIAGE_ACTIONS = {
    "DoS": ["BLOCK_IP_PERMANENT", "ALERT_CRITICAL_SOC", "ENABLE_RATE_LIMITING", "ACTIVATE_DDOS_MITIGATION"],
    "Exploits": ["BLOCK_IP_TEMP_24H", "ENABLE_WAF_RULE", "PATCH_VULNERABILITY", "ISOLATE_AFFECTED_SERVICE"],
    "Fuzzers": ["BLOCK_IP_TEMP_1H", "ENHANCED_LOGGING", "ENABLE_INPUT_VALIDATION", "RATE_LIMIT_CONNECTIONS"],
    "Reconnaissance": ["FLAG_SUSPICIOUS", "QUEUE_MANUAL_REVIEW", "TRIGGER_HONEYPOT_REDIRECT", "MONITOR_IP_STEALTH"],
    "Backdoor": ["ISOLATE_HOST", "NOTIFY_INCIDENT_RESPONSE", "QUARANTINE_DEVICE", "SCAN_ALL_ENDPOINTS"],
    "Shellcode": ["QUARANTINE_DEVICE", "ALERT_INCIDENT_TEAM", "MEMORY_SCAN", "DISABLE_SCRIPTING_ENGINES"],
    "Worms": ["BLOCK_IP_PERMANENT", "ALERT_INCIDENT_TEAM", "NETWORK_SEGMENTATION", "SCAN_MALWARE_ALL"],
    "Analysis": ["FLAG_SUSPICIOUS", "DEEP_PACKET_INSPECTION", "PASSIVE_MONITORING", "LOG_TRAFFIC_PATTERN"],
    "Generic": ["BLOCK_IP_TEMP_12H", "MONITOR_IP_ACTIVITY", "ENHANCED_LOGGING", "REVIEW_REQUIRED"],
    "normal": []
}

FEATURE_EXPLANATIONS = {
    "dbytes": "large data volume transferred to destination",
    "sbytes": "significant bytes sent from source",
    "proto": "suspicious protocol usage",
    "state": "abnormal connection state",
    "service": "targeted application/service",
    "rate": "unusually high packet rate",
    "spkts": "excessive source packets",
    "dpkts": "unusual destination packet count",
    "sload": "high source load indicator",
    "dload": "suspicious destination load",
    "ct_srv_src": "multiple connections to same service",
    "ct_state_ttl": "connection state anomaly",
    "ct_dst_ltm": "unusual destination connection pattern",
    "sinpkt": "abnormal source inter-packet time",
    "dinpkt": "unusual destination inter-packet time",
    "sjit": "source jitter anomaly",
    "djit": "destination jitter anomaly",
    "tcprtt": "suspicious TCP round-trip time",
    "synack": "abnormal SYN-ACK timing",
    "is_ftp_login": "FTP login attempt detected",
    "ct_flw_http_mthd": "suspicious HTTP method usage"
}

# ==================== BLOCKCHAIN IMPLEMENTATION ====================
class Block:
    def __init__(self, data, previous_hash="0" * 64):
        self.timestamp = datetime.now().isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        hash_string = f"{self.timestamp}{self.data}{self.previous_hash}".encode('utf-8')
        return hashlib.sha256(hash_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        genesis = Block("Genesis Block - CYBERSECURE Initialized", "0" * 64)
        self.chain.append(genesis)
    
    def add_block(self, data):
        previous_hash = self.chain[-1].hash if self.chain else "0" * 64
        new_block = Block(data, previous_hash)
        self.chain.append(new_block)
        return new_block
    
    def get_chain(self):
        return [
            {
                "entry": block.data,
                "hash": block.hash,
                "prev_hash": block.previous_hash,
                "timestamp": block.timestamp
            }
            for block in self.chain
        ]

blockchain = Blockchain()

# ==================== EXPORT UTILITIES ====================
class ReportGenerator:
    """Generate PDF and TXT reports from threat logs"""
    
    @staticmethod
    def generate_pdf_report(log_reports: List[Dict], filename: str = "threat_report.pdf") -> bytes:
        """Generate professional PDF threat report"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#FF0000'),
            spaceAfter=12,
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#00CC00'),
            spaceAfter=8,
            spaceBefore=8
        )
        
        # Title
        elements.append(Paragraph("🔒 CYBERSECURE THREAT REPORT", title_style))
        elements.append(Spacer(1, 0.3*inch))
        
        # Summary Section
        elements.append(Paragraph("📊 SUMMARY", heading_style))
        summary_data = [
            ["Total Flows Analyzed", len(log_reports)],
            ["Critical Threats", sum(1 for r in log_reports if r.get('severity') == 'CRITICAL')],
            ["High Severity", sum(1 for r in log_reports if r.get('severity') == 'HIGH')],
            ["Medium Severity", sum(1 for r in log_reports if r.get('severity') == 'MEDIUM')],
            ["Low Severity", sum(1 for r in log_reports if r.get('severity') == 'LOW')],
            ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1a1a1a')),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#0d3d0d')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#00ff00')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#00ff00'))
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Detailed Logs Section
        elements.append(Paragraph("🚨 DETAILED THREAT LOG", heading_style))
        
        # Create detailed table
        log_table_data = [
            ["Flow ID", "Attack Type", "Severity", "Confidence", "Source IP", "Action", "Explanation"]
        ]
        
        for report in log_reports[:50]:  # Limit to 50 rows for readability
            explanation = report.get('explanation', 'N/A')[:80] + "..." if len(report.get('explanation', '')) > 80 else report.get('explanation', 'N/A')
            action = report.get('security_actions', 'N/A')[:30] + "..." if len(report.get('security_actions', '')) > 30 else report.get('security_actions', 'N/A')
            
            log_table_data.append([
                str(report.get('flow_id', 'N/A'))[:12],
                str(report.get('attack_type', 'N/A')),
                str(report.get('severity', 'N/A')),
                str(report.get('confidence', 'N/A')),
                str(report.get('source_ip', 'N/A')),
                action,
                explanation
            ])
        
        log_table = Table(log_table_data, colWidths=[0.8*inch, 0.9*inch, 0.8*inch, 0.8*inch, 1*inch, 1*inch, 1.5*inch])
        log_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00ff00')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00ff00')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#0d0d0d'), colors.HexColor('#1a1a1a')])
        ]))
        elements.append(log_table)
        elements.append(PageBreak())
        
        # Critical Actions Section
        elements.append(Paragraph("⚙️ RECOMMENDED ACTIONS", heading_style))
        
        critical_actions = set()
        for report in log_reports:
            if report.get('severity') in ['CRITICAL', 'HIGH']:
                actions = report.get('all_actions', [])
                critical_actions.update(actions[:5])
        
        actions_text = "<br/>".join([f"• {action}" for action in list(critical_actions)[:15]])
        elements.append(Paragraph(actions_text, styles['BodyText']))
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
    
    @staticmethod
    def generate_txt_report(log_reports: List[Dict], filename: str = "threat_report.txt") -> str:
        """Generate TXT report optimized for RAG chatbot ingestion"""
        report_lines = [
            "=" * 100,
            "CYBERSECURE THREAT ANALYSIS REPORT - RAG KNOWLEDGE BASE",
            "=" * 100,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 100,
            f"Total Threats Detected: {len(log_reports)}",
            f"Critical Severity: {sum(1 for r in log_reports if r.get('severity') == 'CRITICAL')}",
            f"High Severity: {sum(1 for r in log_reports if r.get('severity') == 'HIGH')}",
            f"Medium Severity: {sum(1 for r in log_reports if r.get('severity') == 'MEDIUM')}",
            f"Low Severity: {sum(1 for r in log_reports if r.get('severity') == 'LOW')}",
            "",
            "=" * 100,
            "DETAILED THREAT LOG (RAG-OPTIMIZED FORMAT)",
            "=" * 100,
            ""
        ]
        
        for idx, report in enumerate(log_reports, 1):
            report_lines.extend([
                f"THREAT #{idx}",
                "-" * 100,
                f"Flow ID: {report.get('flow_id', 'N/A')}",
                f"Timestamp: {report.get('timestamp', 'N/A')}",
                f"Source IP: {report.get('source_ip', 'N/A')}",
                f"Destination IP: {report.get('dest_ip', 'N/A')}",
                f"Destination Port: {report.get('dest_port', 'N/A')}",
                f"Attack Type: {report.get('attack_type', 'N/A')}",
                f"Confidence Score: {report.get('confidence', 'N/A')}",
                f"Severity Level: {report.get('severity', 'N/A')}",
                f"Priority: {report.get('priority', 'N/A')}",
                f"SLA Response Time: {report.get('sla', 'N/A')}",
                f"Requires Manual Review: {report.get('requires_review', False)}",
                "",
                "EXPLANATION:",
                f"{report.get('explanation', 'No explanation available')}",
                "",
                "TOP CONTRIBUTING FEATURES (SHAP):",
                ""
            ])
            
            shap_features = report.get('shap_top_features', [])
            if shap_features:
                for feat_name, feat_value in shap_features:
                    report_lines.append(f"  - {feat_name}: {feat_value:.4f}")
            else:
                report_lines.append("  - No feature importance data available")
            
            report_lines.extend([
                "",
                "RECOMMENDED SECURITY ACTIONS:",
                ""
            ])
            
            actions = report.get('all_actions', [])
            for i, action in enumerate(actions[:5], 1):
                report_lines.append(f"  {i}. {action}")
            
            report_lines.extend([
                "",
                "=" * 100,
                ""
            ])
        
        # Add Attack Type Statistics
        report_lines.extend([
            "ATTACK TYPE STATISTICS",
            "-" * 100,
            ""
        ])
        
        attack_counts = {}
        for report in log_reports:
            attack_type = report.get('attack_type', 'Unknown')
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        
        for attack_type, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"  {attack_type}: {count} occurrences")
        
        report_lines.extend([
            "",
            "SEVERITY DISTRIBUTION",
            "-" * 100,
            ""
        ])
        
        severity_counts = {}
        for report in log_reports:
            severity = report.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            percentage = (count / len(log_reports)) * 100 if log_reports else 0
            report_lines.append(f"  {severity}: {count} ({percentage:.1f}%)")
        
        report_lines.extend([
            "",
            "=" * 100,
            "END OF REPORT",
            "=" * 100
        ])
        
        return "\n".join(report_lines)
    
    @staticmethod
    def generate_rag_knowledge_base(log_reports: List[Dict]) -> str:
        """Generate RAG-optimized knowledge base for Q&A chatbot"""
        kb_lines = [
            "# CYBERSECURE THREAT INTELLIGENCE KNOWLEDGE BASE",
            "# Optimized for RAG (Retrieval-Augmented Generation) Q&A System",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## THREAT OVERVIEW",
            f"Total Threats Analyzed: {len(log_reports)}",
            f"Analysis Date: {datetime.now().strftime('%Y-%m-%d')}",
            f"Critical Incidents: {sum(1 for r in log_reports if r.get('severity') == 'CRITICAL')}",
            "",
            "## ATTACK PATTERNS",
            ""
        ]
        
        # Organize by attack type
        attacks_by_type = {}
        for report in log_reports:
            attack_type = report.get('attack_type', 'Unknown')
            if attack_type not in attacks_by_type:
                attacks_by_type[attack_type] = []
            attacks_by_type[attack_type].append(report)
        
        for attack_type, reports in sorted(attacks_by_type.items()):
            # Compute severity distribution safely to avoid nested f-string parsing issues
            severity_counts = {s: sum(1 for r in reports if r.get('severity') == s) for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
            severity_dist_parts = [f"{s}:{count}" for s, count in severity_counts.items() if count > 0]
            severity_dist = ', '.join(severity_dist_parts) if severity_dist_parts else 'None'

            kb_lines.extend([
                f"### {attack_type.upper()} ATTACKS",
                f"Frequency: {len(reports)} occurrences",
                f"Average Confidence: {np.mean([float(r.get('confidence', '0%').strip('%'))/100 for r in reports]):.1%}",
                f"Severity Distribution: {severity_dist}",
                ""
            ])
            
            # Top 3 instances
            top_reports = sorted(reports, key=lambda x: float(x.get('confidence', '0%').strip('%'))/100, reverse=True)[:3]
            for i, report in enumerate(top_reports, 1):
                kb_lines.extend([
                    f"#### Instance {i}:",
                    f"Source IP: {report.get('source_ip', 'N/A')} | Port: {report.get('dest_port', 'N/A')}",
                    f"Confidence: {report.get('confidence', 'N/A')} | Severity: {report.get('severity', 'N/A')}",
                    f"Explanation: {report.get('explanation', 'N/A')}",
                    ""
                ])
        
        # Add threat indicators
        kb_lines.extend([
            "## THREAT INDICATORS & SIGNATURES",
            ""
        ])
        
        all_features = {}
        for report in log_reports:
            for feat_name, feat_value in report.get('shap_top_features', [])[:3]:
                if feat_name not in all_features:
                    all_features[feat_name] = []
                all_features[feat_name].append(feat_value)
        
        for feat_name, values in sorted(all_features.items(), key=lambda x: np.mean(np.abs(x[1])), reverse=True)[:15]:
            avg_impact = np.mean(np.abs(values))
            kb_lines.append(f"- **{feat_name}**: Average impact: {avg_impact:.4f} (High contributor to attack detection)")
        
        kb_lines.extend([
            "",
            "## RESPONSE PLAYBOOKS",
            ""
        ])
        
        # Aggregate actions by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_reports = [r for r in log_reports if r.get('severity') == severity]
            if severity_reports:
                all_actions = set()
                for report in severity_reports:
                    all_actions.update(report.get('all_actions', [])[:3])
                
                kb_lines.extend([
                    f"### {severity} SEVERITY RESPONSE",
                    f"Affected Flows: {len(severity_reports)}",
                    "Recommended Actions:",
                    ""
                ])
                
                for action in list(all_actions)[:8]:
                    kb_lines.append(f"- {action}")
                
                kb_lines.append("")
        
        kb_lines.extend([
            "## FAQ GENERATED FROM THREAT DATA",
            "",
            "Q: What are the most common attack types detected?",
            f"A: {', '.join(sorted(attacks_by_type.keys(), key=lambda x: len(attacks_by_type[x]), reverse=True)[:5])}",
            "",
            f"Q: How many critical threats were detected?",
            f"A: {sum(1 for r in log_reports if r.get('severity') == 'CRITICAL')} critical threats detected.",
            "",
            f"Q: What is the average confidence of threat detection?",
            f"A: {np.mean([float(r.get('confidence', '0%').strip('%'))/100 for r in log_reports]):.1%}",
            ""
        ])
        
        return "\n".join(kb_lines)

report_generator = ReportGenerator()

# ==================== ENHANCED TRIAGE ENGINE ====================
class TriageEngine:
    """Deterministic rule-based security triage system with SHAP explanations"""
    
    def __init__(self):
        self.severity_thresholds = {
            'critical': {'attack_types': ['Backdoor', 'Shellcode', 'Worms', 'Exploits'], 'min_confidence': 0.70},
            'high': {'attack_types': ['DoS', 'Reconnaissance'], 'min_confidence': 0.75},
            'medium': {'attack_types': ['Fuzzers', 'Generic'], 'min_confidence': 0.60},
            'low': {'attack_types': ['Analysis'], 'min_confidence': 0.50}
        }
    
    def calculate_severity(self, attack_type: str, confidence: float) -> Severity:
        """Determine severity based on attack type and confidence"""
        if attack_type in ['Backdoor', 'Shellcode', 'Worms', 'Exploits'] and confidence >= 0.70:
            return Severity.CRITICAL
        if attack_type in ['DoS', 'Reconnaissance'] and confidence >= 0.75:
            return Severity.HIGH
        if attack_type in ['Fuzzers', 'Generic'] and confidence >= 0.60:
            return Severity.MEDIUM
        if attack_type == 'Analysis' and confidence >= 0.50:
            return Severity.LOW
        return Severity.LOW
    
    def generate_commands(self, attack_type: str, severity: Severity, source_ip: str, 
                         dest_port: int, confidence: float) -> List[str]:
        """Generate specific security commands from TRIAGE_ACTIONS"""
        commands = []
        
        # Base logging
        commands.append(f"LOG_INCIDENT: {attack_type} FROM {source_ip}")
        
        # Severity-based IP blocking
        if severity == Severity.CRITICAL:
            commands.append(f"BLOCK_IP_PERMANENT: {source_ip}")
            commands.append("ELEVATE_SECURITY_POSTURE: DEFCON_2")
            commands.append("NOTIFY_SOC_TEAM: IMMEDIATE")
            commands.append("INITIATE_INCIDENT_RESPONSE: LEVEL_1")
        elif severity == Severity.HIGH:
            commands.append(f"BLOCK_IP_TEMP_24H: {source_ip}")
            commands.append("ALERT_SOC_ESCALATE")
            commands.append("ENABLE_RATE_LIMITING")
            commands.append("ENHANCED_MONITORING: TARGET_SUBNET")
        elif severity == Severity.MEDIUM:
            commands.append(f"BLOCK_IP_TEMP_1H: {source_ip}")
            commands.append("ENHANCED_LOGGING")
            commands.append("TRIGGER_WAF_INSPECTION")
        else:
            commands.append(f"FLAG_SUSPICIOUS: {source_ip}")
            commands.append("REVIEW_REQUIRED")
            commands.append("PASSIVE_MONITORING: 48H")
        
        # Attack-specific actions from TRIAGE_ACTIONS
        if attack_type in TRIAGE_ACTIONS:
            attack_specific = TRIAGE_ACTIONS[attack_type]
            for action in attack_specific:
                if action not in commands:  # Avoid duplicates
                    commands.append(action)
        
        # Network-wide actions for critical high-confidence threats
        if severity == Severity.CRITICAL and confidence >= 0.90:
            commands.append("NETWORK_WIDE_SCAN: ALL_ENDPOINTS")
            commands.append("ISOLATE_AFFECTED_SEGMENT")
            commands.append("ENABLE_EMERGENCY_PROTOCOLS")
            commands.append("BACKUP_CRITICAL_DATA: IMMEDIATE")
        
        return commands
    
    def assign_priority(self, severity: Severity) -> Tuple[int, int]:
        """Assign priority level and SLA response time in minutes"""
        priority_map = {
            Severity.CRITICAL: (1, 5),
            Severity.HIGH: (2, 15),
            Severity.MEDIUM: (3, 60),
            Severity.LOW: (4, 240)
        }
        return priority_map[severity]
    
    def needs_human_review(self, severity: Severity, confidence: float) -> bool:
        """Determine if human analyst review is required"""
        if severity == Severity.CRITICAL:
            return True
        if confidence < 0.65:
            return True
        if severity == Severity.HIGH and confidence < 0.80:
            return True
        return False
    
    def generate_explanation(self, attack_type: str, top_features: List[Tuple[str, float]], 
                           confidence: float) -> str:
        """Generate human-readable SHAP explanation"""
        if not top_features:
            return f"This flow was classified as '{attack_type}' with {confidence:.1%} confidence."
        
        reasons = []
        for feat_name, shap_val in top_features[:3]:  # Top 3 features
            # Clean feature name (remove preprocessing prefixes)
            clean_name = feat_name.split('__')[-1] if '__' in feat_name else feat_name
            explanation = FEATURE_EXPLANATIONS.get(clean_name, clean_name)
            direction = "high" if shap_val > 0 else "low"
            reasons.append(f"{direction} {explanation}")
        
        reason_text = (
            f"This flow was flagged as '{attack_type}' (confidence: {confidence:.1%}) "
            f"due to: {', '.join(reasons)}."
        )
        return reason_text
    
    def evaluate(self, attack_type: str, confidence: float, source_ip: str,
                dest_port: int, flow_metadata: Dict, shap_features: Optional[List[Tuple[str, float]]] = None) -> Dict:
        """Apply deterministic triage logic with SHAP explanations"""
        severity = self.calculate_severity(attack_type, confidence)
        commands = self.generate_commands(attack_type, severity, source_ip, dest_port, confidence)
        priority, sla_minutes = self.assign_priority(severity)
        
        # Generate explanation if SHAP values provided
        explanation = ""
        if shap_features:
            explanation = self.generate_explanation(attack_type, shap_features, confidence)
        
        return {
            'commands': commands,
            'severity': severity.name,
            'priority': f"P{priority}",
            'sla_response_time': f"{sla_minutes} minutes",
            'requires_manual_review': self.needs_human_review(severity, confidence),
            'escalation_required': severity in [Severity.CRITICAL, Severity.HIGH],
            'automated_response': severity <= Severity.MEDIUM,
            'attack_category': attack_type,
            'confidence_score': confidence,
            'explanation': explanation
        }

triage_engine = TriageEngine()

# ==================== ML MODEL LOADER ====================
class UNSWModel:
    def __init__(self):
        self.model = None
        self.preprocessor = None
        self.threshold = 0.5
        self.explainer = None
        self.feature_names = []
        self.attack_type_model = None
        self.attack_type_le = None
    
    def load_model(self):
        """Load trained UNSW model, preprocessor, and optional attack classifier"""
        try:
            # Load binary classifier
            bundle = joblib.load('models/unsw_trained_model.pkl')
            self.model = bundle['model']
            self.threshold = bundle.get('threshold', 0.5)
            
            # Load preprocessor
            self.preprocessor = joblib.load('models/unsw_preprocessor.pkl')
            self.feature_names = self.preprocessor.get_feature_names_out().tolist()
            
            # Initialize SHAP explainer
            self.explainer = shap.Explainer(self.model)
            print(f"✓ Binary classifier loaded. Threshold: {self.threshold:.3f}")
            print(f"✓ Features: {len(self.feature_names)}")
            
            # Try to load multi-class attack type model (optional)
            try:
                self.attack_type_model = joblib.load('models/unsw_attack_cat_xgb.pkl')
                self.attack_type_le = joblib.load('models/unsw_attack_cat_le.pkl')
                print("✓ Multi-class attack type model loaded")
            except Exception:
                print("⚠ Multi-class model not found - using confidence-based classification")
                self.attack_type_model = None
            
            return True
        
        except Exception as e:
            print(f"⚠ Model loading failed: {e}")
            return False
    
    def predict(self, X_preprocessed):
        """Predict with loaded model"""
        if self.model is None:
            raise ValueError("Model not loaded")
        probabilities = self.model.predict_proba(X_preprocessed)[:, 1]
        predictions = (probabilities >= self.threshold).astype(int)
        return predictions, probabilities
    
    def get_attack_type(self, X_preprocessed, confidence: float) -> str:
        """Get attack type from multi-class model or confidence heuristic"""
        if self.attack_type_model is not None:
            # Use multi-class model
            attack_int = int(self.attack_type_model.predict(X_preprocessed)[0])
            attack_type = self.attack_type_le.inverse_transform([attack_int])[0]
            return attack_type
        else:
            # Fallback to confidence-based classification
            return self.classify_attack_by_confidence(confidence)
    
    def classify_attack_by_confidence(self, confidence: float) -> str:
        """Classify attack type based on confidence threshold"""
        if confidence >= 0.95:
            return 'Backdoor'
        elif confidence >= 0.90:
            return 'Exploits'
        elif confidence >= 0.85:
            return 'Worms'
        elif confidence >= 0.80:
            return 'Shellcode'
        elif confidence >= 0.75:
            return 'DoS'
        elif confidence >= 0.70:
            return 'Reconnaissance'
        elif confidence >= 0.65:
            return 'Fuzzers'
        else:
            return 'Generic'
    
    def get_shap_explanation(self, X_preprocessed) -> List[Tuple[str, float]]:
        """Generate SHAP explanation with top features"""
        if self.explainer is None:
            return []
        
        shap_values = self.explainer(X_preprocessed)
        
        # Extract SHAP values (handle different formats)
        if hasattr(shap_values, 'values'):
            vals = shap_values.values[0]
        else:
            vals = shap_values[0]
        
        # Get top features by absolute SHAP value
        shap_abs = np.abs(vals)
        top_indices = np.argsort(shap_abs)[-5:][::-1]
        
        top_features = [
            (self.feature_names[i], float(vals[i]))
            for i in top_indices
        ]
        
        return top_features

unsw_model = UNSWModel()

# ==================== PYDANTIC MODELS ====================
class FlowData(BaseModel):
    flow: List[float]

uploaded_data_store = {}

# ==================== HELPER FUNCTIONS ====================
def extract_flow_metadata(row: pd.Series) -> Dict:
    """Extract relevant metadata from flow"""
    metadata = {}
    possible_ip_cols = ['srcip', 'src_ip', 'source_ip', 'saddr']
    possible_dst_cols = ['dstip', 'dst_ip', 'destination_ip', 'daddr']
    possible_port_cols = ['dport', 'dst_port', 'destination_port', 'sport', 'src_port']
    
    for col in possible_ip_cols:
        if col in row.index:
            metadata['source_ip'] = str(row[col])
            break
    for col in possible_dst_cols:
        if col in row.index:
            metadata['dest_ip'] = str(row[col])
            break
    for col in possible_port_cols:
        if col in row.index:
            metadata['dest_port'] = int(row[col]) if pd.notna(row[col]) else 80
            break
    
    metadata.setdefault('source_ip', '0.0.0.0')
    metadata.setdefault('dest_ip', '0.0.0.0')
    metadata.setdefault('dest_port', 0)
    return metadata

def process_flow(flow_dict: Dict, model: UNSWModel, triage: TriageEngine) -> Dict:
    """Process single flow with full SHAP explanation and triage"""
    # Convert to DataFrame
    df = pd.DataFrame([flow_dict])
    
    # Preprocess
    X = model.preprocessor.transform(df)
    
    # Predict
    prob = model.model.predict_proba(X)[0, 1]
    predicted_class = model.model.predict(X)[0]
    
    # Get attack type
    attack_type = "normal" if predicted_class == 0 else model.get_attack_type(X, prob)
    
    # Get SHAP explanation
    shap_features = model.get_shap_explanation(X)
    
    # Apply triage
    if attack_type != "normal":
        triage_result = triage.evaluate(
            attack_type=attack_type,
            confidence=prob,
            source_ip=flow_dict.get('source_ip', '0.0.0.0'),
            dest_port=flow_dict.get('dest_port', 0),
            flow_metadata=flow_dict,
            shap_features=shap_features
        )
        actions = triage_result['commands']
        explanation = triage_result['explanation']
    else:
        actions = []
        explanation = f"This flow is classified as benign with {(1-prob):.1%} confidence."
    
    return {
        "probability": float(prob),
        "predicted_class": str(attack_type),
        "actions": actions,
        "shap_top_features": shap_features,
        "explanation": explanation
    }

# ==================== LIFESPAN EVENT ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 CYBERSECURE API Started")
    print("📊 Blockchain initialized with genesis block")
    model_loaded = unsw_model.load_model()
    if model_loaded:
        print("✅ UNSW-NB15 Model Loaded Successfully")
        print("✅ Triage Engine with SHAP Explanations Initialized")
    else:
        print("⚠️ Running in Demo Mode")
    print("🔗 API running on http://localhost:5000")
    yield
    print("⚠️ CYBERSECURE API Shutting down...")

# ==================== CREATE APP ====================
app = FastAPI(
    title="CYBERSECURE API",
    version="2.1.0",
    description="Real-time Network Intrusion Detection with SHAP Explainability",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== ENDPOINTS ====================
@app.get("/")
async def root():
    return {
        "message": "CYBERSECURE API v2.1 - SHAP-Enabled IDS",
        "endpoints": ["/upload", "/threat_log", "/simulate", "/explain", "/model_info"],
        "features": ["SHAP Explainability", "Triage Engine", "Multi-Class Support", "Blockchain Logging"],
        "version": "2.1.0"
    }

# @app.post("/upload")
# async def upload_file(file: UploadFile = File(...)):
#     """Upload and process network traffic CSV with SHAP explanations"""
#     try:
#         contents = await file.read()
#         df = pd.read_csv(BytesIO(contents))
        
#         if df.empty:
#             raise HTTPException(status_code=400, detail="Uploaded file is empty")
        
#         if unsw_model.model is None:
#             raise HTTPException(status_code=503, detail="Model not loaded")
        
#         print(f"📊 Uploaded CSV shape: {df.shape}")
        
#         # Drop label column if present
#         label_col = None
#         for col in ['label', 'Label', 'attack_cat', 'attackcat', 'attack_type']:
#             if col in df.columns:
#                 label_col = col
#                 break
        
#         if label_col:
#             y_true = df[label_col]
#             X_df = df.drop(columns=[label_col])
#             print(f"✓ Label column '{label_col}' dropped")
#         else:
#             X_df = df
#             y_true = None
        
#         # Preprocess and predict
#         X_preprocessed = unsw_model.preprocessor.transform(X_df)
#         predictions, probabilities = unsw_model.predict(X_preprocessed)
        
#         print(f"✓ Predictions: {sum(predictions)} intrusions, {len(predictions) - sum(predictions)} benign")
        
#         # Generate detailed log reports - INCLUDE ALL PREDICTIONS (benign + intrusion)
#         log_reports = []
#         benign_count = 0
#         intrusion_count = 0
        
#         for idx, (pred, prob) in enumerate(zip(predictions, probabilities)):
#             if idx >= 100:  # Limit for performance
#                 break
            
#             row = df.iloc[idx]
#             metadata = extract_flow_metadata(row)
            
#             # ==================== SHOW ALL PREDICTIONS ====================
#             if pred == 1:  # INTRUSION
#                 intrusion_count += 1
                
#                 # Get attack type for intrusions
#                 X_single = X_preprocessed[idx:idx+1]
#                 attack_type = unsw_model.get_attack_type(X_single, prob)
                
#                 # Get SHAP explanation
#                 shap_features = unsw_model.get_shap_explanation(X_single)
                
#                 # Apply triage with SHAP
#                 triage_result = triage_engine.evaluate(
#                     attack_type=attack_type,
#                     confidence=prob,
#                     source_ip=metadata['source_ip'],
#                     dest_port=metadata['dest_port'],
#                     flow_metadata=metadata,
#                     shap_features=shap_features
#                 )
                
#                 log_entry = {
#                     'flow_id': f"FID-{idx:06d}",
#                     'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#                     'source_ip': metadata['source_ip'],
#                     'dest_ip': metadata['dest_ip'],
#                     'dest_port': metadata['dest_port'],
#                     'attack_type': attack_type,  # Attack type for intrusion
#                     'prediction' : pred,
#                     'confidence': f"{prob:.2%}",
#                     'severity': triage_result['severity'],
#                     'priority': triage_result['priority'],
#                     'sla': triage_result['sla_response_time'],
#                     'security_actions': ', '.join(triage_result['commands'][:3]),
#                     'requires_review': triage_result['requires_manual_review'],
#                     'explanation': triage_result['explanation'],
#                     'shap_top_features': shap_features[:3],
#                     'all_actions': triage_result['commands']
#                 }
                
#                 log_reports.append(log_entry)
                
#                 # Add to blockchain
#                 blockchain.add_block(
#                     f"INTRUSION: {attack_type} | SRC: {metadata['source_ip']} | "
#                     f"Confidence: {prob:.2%} | Severity: {triage_result['severity']}"
#                 )
            
#             else:  # ✅ BENIGN (pred == 0)
#                 benign_count += 1
                
#                 # ✅ ADD BENIGN FLOWS TO TABLE WITH "Benign" LABEL
#                 log_entry = {
#                     'flow_id': f"FID-{idx:06d}",
#                     'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#                     'source_ip': metadata['source_ip'],
#                     'dest_ip': metadata['dest_ip'],
#                     'dest_port': metadata['dest_port'],
#                     'attack_type': 'Benign',  # ✅ Clearly labeled as Benign
#                     'confidence': f"{1-prob:.2%}",  # Confidence in benign classification
#                     'severity': 'NONE',
#                     'priority': 'N/A',
#                     'sla': 'N/A',
#                     'security_actions': 'ALLOW_TRAFFIC',
#                     'requires_review': False,
#                     'explanation': f"This flow is classified as benign with {(1-prob):.1%} confidence.",
#                     'shap_top_features': [],
#                     'all_actions': []
#                 }
                
#                 log_reports.append(log_entry)  # ✅ Include benign in log_reports
        
#         # Count remaining flows if we stopped at 100
#         if len(predictions) > 100:
#             remaining_intrusions = sum(predictions[100:])
#             intrusion_count += remaining_intrusions
#             benign_count += (len(predictions) - 100 - remaining_intrusions)
        
#         # Store for later use
#         uploaded_data_store['dataframe'] = df
#         uploaded_data_store['predictions'] = predictions
#         uploaded_data_store['probabilities'] = probabilities
#         uploaded_data_store['log_reports'] = log_reports
        
#         # Prepare graph data
#         graph_data = {
#             "pie": {
#                 "labels": ["Benign", "Intrusion"],
#                 "values": [int(benign_count), int(intrusion_count)]
#             },
#             "bar": {
#                 "labels": ["Critical", "High", "Medium", "Low"],
#                 "values": [
#                     sum(1 for r in log_reports if r.get('severity') == 'CRITICAL'),
#                     sum(1 for r in log_reports if r.get('severity') == 'HIGH'),
#                     sum(1 for r in log_reports if r.get('severity') == 'MEDIUM'),
#                     sum(1 for r in log_reports if r.get('severity') == 'LOW')
#                 ]
#             },
#             "line": {
#                 "labels": [f"Flow {i}" for i in range(min(20, len(probabilities)))],
#                 "values": probabilities[:20].tolist() if len(probabilities) > 0 else []
#             }
#         }
        
#         # ✅ Show ALL predictions in segregated_data (first 10 rows)
#         segregated_data = log_reports[:10] if log_reports else []
        
#         print(f"✅ Processing complete: {intrusion_count} intrusions, {benign_count} benign")
        
#         return {
#             "message": "File processed with SHAP explainability",
#             "filename": file.filename,
#             "summary": {
#                 "rows": len(df),
#                 "columns": df.columns.tolist()[:10],
#                 "benign_count": int(benign_count),
#                 "intrusion_count": int(intrusion_count),
#                 "segregated_data": segregated_data  # ✅ Contains BOTH benign and intrusion
#             },
#             "graph_data": graph_data,
#             "total_log_entries": len(log_reports)
#         }
    
#     except Exception as e:
#         import traceback
#         print(f"❌ Error: {traceback.format_exc()}")
#         raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

#         raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload and process network traffic CSV with SHAP explanations"""
    try:
        contents = await file.read()
        df = pd.read_csv(BytesIO(contents))
        
        if df.empty:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        
        if unsw_model.model is None:
            raise HTTPException(status_code=503, detail="Model not loaded")
        
        print(f"📊 Uploaded CSV shape: {df.shape}")
        
        # Drop label column if present
        label_col = None
        for col in ['label', 'Label', 'attack_cat', 'attackcat', 'attack_type']:
            if col in df.columns:
                label_col = col
                break
        
        if label_col:
            y_true = df[label_col]
            X_df = df.drop(columns=[label_col])
            print(f"✓ Label column '{label_col}' dropped")
        else:
            X_df = df
            y_true = None
        
        # Preprocess and predict
        X_preprocessed = unsw_model.preprocessor.transform(X_df)
        predictions, probabilities = unsw_model.predict(X_preprocessed)
        
        print(f"✓ Predictions: {sum(predictions)} intrusions, {len(predictions) - sum(predictions)} benign")
        
        # Generate detailed log reports - INCLUDE ALL PREDICTIONS (benign + intrusion)
        log_reports = []
        benign_count = 0
        intrusion_count = 0
        
        for idx, (pred, prob) in enumerate(zip(predictions, probabilities)):
            if idx >= 100:  # Limit for performance
                break
            
            row = df.iloc[idx]
            metadata = extract_flow_metadata(row)
            
            # ==================== SHOW ALL PREDICTIONS ====================
            if pred == 1:  # INTRUSION
                intrusion_count += 1
                
                # Get attack type for intrusions
                X_single = X_preprocessed[idx:idx+1]
                attack_type = unsw_model.get_attack_type(X_single, prob)
                
                # Get SHAP explanation
                shap_features = unsw_model.get_shap_explanation(X_single)
                
                # Apply triage with SHAP
                triage_result = triage_engine.evaluate(
                    attack_type=attack_type,
                    confidence=prob,
                    source_ip=metadata['source_ip'],
                    dest_port=metadata['dest_port'],
                    flow_metadata=metadata,
                    shap_features=shap_features
                )
                
                log_entry = {
                    'flow_id': f"FID-{idx:06d}",
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'source_ip': metadata['source_ip'],
                    'dest_ip': metadata['dest_ip'],
                    'dest_port': metadata['dest_port'],
                    'attack_type': attack_type,
                    'prediction': pred,
                    'confidence': f"{prob:.2%}",
                    'severity': triage_result['severity'],
                    'priority': triage_result['priority'],
                    'sla': triage_result['sla_response_time'],
                    'security_actions': ', '.join(triage_result['commands'][:3]),
                    'requires_review': triage_result['requires_manual_review'],
                    'explanation': triage_result['explanation'],
                    'shap_top_features': shap_features[:3],
                    'all_actions': triage_result['commands']
                }
                
                log_reports.append(log_entry)
                
                # Add to blockchain
                blockchain.add_block(
                    f"INTRUSION: {attack_type} | SRC: {metadata['source_ip']} | "
                    f"Confidence: {prob:.2%} | Severity: {triage_result['severity']}"
                )
            
            else:  # BENIGN (pred == 0)
                benign_count += 1
                
                # ADD BENIGN FLOWS TO TABLE
                log_entry = {
                    'flow_id': f"FID-{idx:06d}",
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'source_ip': metadata['source_ip'],
                    'dest_ip': metadata['dest_ip'],
                    'dest_port': metadata['dest_port'],
                    'attack_type': 'Benign',
                    'prediction': pred,
                    'confidence': f"{1-prob:.2%}",
                    'severity': 'NONE',
                    'priority': 'N/A',
                    'sla': 'N/A',
                    'security_actions': 'ALLOW_TRAFFIC',
                    'requires_review': False,
                    'explanation': f"This flow is classified as benign with {(1-prob):.1%} confidence.",
                    'shap_top_features': [],
                    'all_actions': []
                }
                
                log_reports.append(log_entry)
        
        # Count remaining flows if we stopped at 100
        if len(predictions) > 100:
            remaining_intrusions = sum(predictions[100:])
            intrusion_count += remaining_intrusions
            benign_count += (len(predictions) - 100 - remaining_intrusions)
        
        # Store for later use
        uploaded_data_store['dataframe'] = df
        uploaded_data_store['predictions'] = predictions
        uploaded_data_store['probabilities'] = probabilities
        uploaded_data_store['log_reports'] = log_reports
        
        # Prepare graph data
        graph_data = {
            "pie": {
                "labels": ["Benign", "Intrusion"],
                "values": [int(benign_count), int(intrusion_count)]
            },
            "bar": {
                "labels": ["Critical", "High", "Medium", "Low"],
                "values": [
                    sum(1 for r in log_reports if r.get('severity') == 'CRITICAL'),
                    sum(1 for r in log_reports if r.get('severity') == 'HIGH'),
                    sum(1 for r in log_reports if r.get('severity') == 'MEDIUM'),
                    sum(1 for r in log_reports if r.get('severity') == 'LOW')
                ]
            },
            "line": {
                "labels": [f"Flow {i}" for i in range(min(20, len(probabilities)))],
                "values": probabilities[:20].tolist() if len(probabilities) > 0 else []
            }
        }
        
        # Show ALL predictions in segregated_data (first 10 rows)
        segregated_data = log_reports[:10] if log_reports else []
        
        print(f"✅ Processing complete: {intrusion_count} intrusions, {benign_count} benign")
        
        # Build response
        response = {
            "message": "File processed with SHAP explainability",
            "filename": file.filename,
            "summary": {
                "rows": len(df),
                "columns": df.columns.tolist()[:10],
                "benign_count": benign_count,
                "intrusion_count": intrusion_count,
                "segregated_data": segregated_data
            },
            "graph_data": graph_data,
            "total_log_entries": len(log_reports)
        }
        
        # ✅ SANITIZE ALL NUMPY TYPES BEFORE RETURNING
        return sanitize_for_json(response)
    
    except Exception as e:
        import traceback
        print(f"❌ Error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/threat_log")
async def get_threat_log():
    """Get blockchain threat log"""
    return blockchain.get_chain()

@app.get("/simulate")
async def simulate_flows():
    """Simulate real-time network flow detection with SHAP triage"""
    try:
        if unsw_model.model is None:
            raise HTTPException(status_code=503, detail="Model not loaded")
        
        num_flows = 5
        num_features = len(unsw_model.feature_names)
        
        simulated_df = pd.DataFrame(
            np.random.rand(num_flows, num_features),
            columns=unsw_model.feature_names
        )
        
        X_preprocessed = unsw_model.preprocessor.transform(simulated_df)
        predictions, probabilities = unsw_model.predict(X_preprocessed)
        
        results = []
        attack_types = ['DoS', 'Reconnaissance', 'Fuzzers', 'Backdoor',
                       'Exploits', 'Generic', 'Shellcode', 'Worms', 'Analysis']
        
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            if pred == 1:  # ✅ Only classify attack type if intrusion
                attack_type = np.random.choice(attack_types)
                source_ip = f"192.168.{np.random.randint(0, 255)}.{np.random.randint(1, 255)}"
                
                X_single = X_preprocessed[i:i+1]
                shap_features = unsw_model.get_shap_explanation(X_single)
                
                triage_result = triage_engine.evaluate(
                    attack_type=attack_type,
                    confidence=prob,
                    source_ip=source_ip,
                    dest_port=np.random.choice([80, 443, 22, 3306]),
                    flow_metadata={},
                    shap_features=shap_features
                )
                
                blockchain.add_block(
                    f"SIMULATION: {attack_type} | SRC: {source_ip} | Confidence: {prob:.2%}"
                )
                
                results.append({
                    "flow_id": i,
                    "prediction": "Intrusion",
                    "attack_type": attack_type,
                    "confidence": f"{prob:.2%}",
                    "action": triage_result['commands'][0],
                    "severity": triage_result['severity'],
                    "explanation": triage_result['explanation']
                })
            else:  # ✅ Benign - no attack type
                results.append({
                    "flow_id": i,
                    "prediction": "Benign",
                    "confidence": f"{1-prob:.2%}",
                    "action": "ALLOW_TRAFFIC",
                    "severity": "NONE"
                })
        
        return results
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation error: {str(e)}")

@app.post("/explain")
async def explain_prediction(flow_data: FlowData):
    """Generate SHAP explanation for a network flow"""
    try:
        if unsw_model.model is None:
            raise HTTPException(status_code=503, detail="Model not loaded")
        
        flow = np.array(flow_data.flow).reshape(1, -1)
        expected_features = len(unsw_model.feature_names)
        
        if flow.shape[1] != expected_features:
            raise HTTPException(
                status_code=400,
                detail=f"Expected {expected_features} features, got {flow.shape[1]}"
            )
        
        flow_df = pd.DataFrame(flow, columns=unsw_model.feature_names)
        X_preprocessed = unsw_model.preprocessor.transform(flow_df)
        
        prediction, probability = unsw_model.predict(X_preprocessed)
        pred_label = "Intrusion" if prediction[0] == 1 else "Benign"
        
        # Get SHAP explanation
        shap_features = unsw_model.get_shap_explanation(X_preprocessed)
        
        # Generate human-readable explanation
        if pred_label == "Intrusion":  # ✅ Only get attack type for intrusions
            attack_type = unsw_model.get_attack_type(X_preprocessed, probability[0])
            explanation = triage_engine.generate_explanation(attack_type, shap_features, probability[0])
        else:
            explanation = f"This flow is classified as benign with {(1-probability[0]):.1%} confidence."
        
        blockchain.add_block(
            f"XAI Explanation: {pred_label} | Confidence: {probability[0]:.2%} | "
            f"Top Feature: {shap_features[0][0]}"
        )
        
        return {
            "prediction": pred_label,
            "confidence": f"{float(probability[0]):.2%}",
            "top_features": shap_features,
            "explanation": explanation,
            "feature_count": expected_features
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explanation error: {str(e)}")

@app.get("/model_info")
async def get_model_info():
    """Get information about the loaded model"""
    if unsw_model.model is None:
        return {
            "status": "Model not loaded",
            "message": "Please ensure model files exist in models/ directory"
        }
    
    return {
        "model_type": "XGBoost Classifier (UNSW-NB15)",
        "is_trained": True,
        "threshold": unsw_model.threshold,
        "features": len(unsw_model.feature_names),
        "has_multiclass": unsw_model.attack_type_model is not None,
        "triage_engine": "Enabled with SHAP Explanations",
        "shap_explainer": "Ready",
        "attack_categories": list(TRIAGE_ACTIONS.keys()),
        "note": "SHAP-enabled explainable IDS with deterministic triage"
    }

@app.get("/export/pdf")
async def export_pdf_report():
    """Export threat log as PDF"""
    try:
        if 'log_reports' not in uploaded_data_store:
            raise HTTPException(status_code=400, detail="No threat data available. Upload a file first.")
        
        log_reports = uploaded_data_store.get('log_reports', [])
        pdf_content = ReportGenerator.generate_pdf_report(log_reports)
        
        # Save to file
        with open('exports/threat_report.pdf', 'wb') as f:
            f.write(pdf_content)
        
        return {
            "message": "PDF generated successfully",
            "filename": "threat_report.pdf",
            "size": len(pdf_content),
            "download_url": "/files/threat_report.pdf"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation error: {str(e)}")

@app.get("/export/txt")
async def export_txt_report():
    """Export threat log as TXT (optimized for RAG)"""
    try:
        if 'log_reports' not in uploaded_data_store:
            raise HTTPException(status_code=400, detail="No threat data available. Upload a file first.")
        
        log_reports = uploaded_data_store.get('log_reports', [])
        txt_content = ReportGenerator.generate_txt_report(log_reports)
        
        # Save to file for download
        with open('exports/threat_report.txt', 'w') as f:
            f.write(txt_content)
        
        return {
            "message": "TXT report generated successfully",
            "filename": "threat_report.txt",
            "size": len(txt_content),
            "content_preview": txt_content[:500],
            "download_url": "/files/threat_report.txt"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"TXT generation error: {str(e)}")

@app.get("/export/rag-kb")
async def export_rag_knowledge_base():
    """Export RAG knowledge base for chatbot Q&A"""
    try:
        if 'log_reports' not in uploaded_data_store:
            raise HTTPException(status_code=400, detail="No threat data available. Upload a file first.")
        
        log_reports = uploaded_data_store.get('log_reports', [])
        kb_content = ReportGenerator.generate_rag_knowledge_base(log_reports)
        
        # Save to file
        with open('exports/rag_knowledge_base.md', 'w') as f:
            f.write(kb_content)
        
        return {
            "message": "RAG knowledge base generated successfully",
            "filename": "rag_knowledge_base.md",
            "size": len(kb_content),
            "format": "Markdown optimized for RAG chatbot ingestion",
            "sections": ["Threat Overview", "Attack Patterns", "Threat Indicators", "Response Playbooks", "FAQ"],
            "download_url": "/files/rag_knowledge_base.md"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG KB generation error: {str(e)}")

@app.get("/export/all")
async def export_all_formats():
    """Export all formats at once (PDF + TXT + RAG KB)"""
    try:
        if 'log_reports' not in uploaded_data_store:
            raise HTTPException(status_code=400, detail="No threat data available. Upload a file first.")
        
        log_reports = uploaded_data_store.get('log_reports', [])
        
        # Generate all formats
        pdf_content = ReportGenerator.generate_pdf_report(log_reports)
        txt_content = ReportGenerator.generate_txt_report(log_reports)
        kb_content = ReportGenerator.generate_rag_knowledge_base(log_reports)
        
        # Save to files
        with open('exports/threat_report.pdf', 'wb') as f:
            f.write(pdf_content)
        
        with open('exports/threat_report.txt', 'w') as f:
            f.write(txt_content)
        
        with open('exports/rag_knowledge_base.md', 'w') as f:
            f.write(kb_content)
        
        print("✅ All exports generated successfully")
        
        return {
            "message": "All formats exported successfully",
            "exports": {
                "pdf": {
                    "filename": "threat_report.pdf",
                    "size": len(pdf_content),
                    "url": "/files/threat_report.pdf"
                },
                "txt": {
                    "filename": "threat_report.txt",
                    "size": len(txt_content),
                    "url": "/files/threat_report.txt"
                },
                "rag_kb": {
                    "filename": "rag_knowledge_base.md",
                    "size": len(kb_content),
                    "url": "/files/rag_knowledge_base.md"
                }
            },
            "total_size": len(pdf_content) + len(txt_content) + len(kb_content)
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export error: {str(e)}")

# Add static file serving
from fastapi.staticfiles import StaticFiles
import os

os.makedirs('exports', exist_ok=True)
app.mount("/files", StaticFiles(directory="exports"), name="exports")

# ==================== RUN SERVER ====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
