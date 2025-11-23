from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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
import os

# ==================== SEVERITY ENUM ====================
class Severity(IntEnum):
    """Severity levels for threat classification"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

# ==================== TRIAGE ACTIONS & EXPLANATIONS ====================
TRIAGE_ACTIONS = {
    "DoS": [
        "BLOCK_IP_PERMANENT",
        "ALERT_CRITICAL_SOC",
        "ENABLE_RATE_LIMITING",
        "ACTIVATE_DDOS_MITIGATION",
        "BLACKHOLE_ROUTING"
    ],
    "Exploits": [
        "BLOCK_IP_TEMP_24H",
        "ENABLE_WAF_RULE",
        "PATCH_VULNERABILITY",
        "ISOLATE_AFFECTED_SERVICE",
        "SCAN_FOR_INDICATORS"
    ],
    "Fuzzers": [
        "BLOCK_IP_TEMP_1H",
        "ENHANCED_LOGGING",
        "ENABLE_INPUT_VALIDATION",
        "RATE_LIMIT_CONNECTIONS",
        "MONITOR_PATTERNS"
    ],
    "Reconnaissance": [
        "FLAG_SUSPICIOUS",
        "QUEUE_MANUAL_REVIEW",
        "TRIGGER_HONEYPOT_REDIRECT",
        "MONITOR_IP_STEALTH",
        "LOG_BEHAVIORAL_PATTERNS"
    ],
    "Backdoor": [
        "ISOLATE_HOST",
        "NOTIFY_INCIDENT_RESPONSE",
        "QUARANTINE_DEVICE",
        "SCAN_ALL_ENDPOINTS",
        "FORENSIC_ANALYSIS"
    ],
    "Shellcode": [
        "QUARANTINE_DEVICE",
        "ALERT_INCIDENT_TEAM",
        "MEMORY_SCAN",
        "DISABLE_SCRIPTING_ENGINES",
        "ENDPOINT_ISOLATION"
    ],
    "Worms": [
        "BLOCK_IP_PERMANENT",
        "ALERT_INCIDENT_TEAM",
        "NETWORK_SEGMENTATION",
        "SCAN_MALWARE_ALL",
        "DISCONNECT_INFECTED_HOSTS"
    ],
    "Analysis": [
        "FLAG_SUSPICIOUS",
        "DEEP_PACKET_INSPECTION",
        "PASSIVE_MONITORING",
        "LOG_TRAFFIC_PATTERN",
        "BEHAVIORAL_ANALYSIS"
    ],
    "Generic": [
        "BLOCK_IP_TEMP_12H",
        "MONITOR_IP_ACTIVITY",
        "ENHANCED_LOGGING",
        "REVIEW_REQUIRED",
        "THREAT_INTELLIGENCE_CHECK"
    ],
    "Benign": []
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
    "ct_flw_http_mthd": "suspicious HTTP method usage",
    "swin": "source TCP window size anomaly",
    "dwin": "destination TCP window size anomaly",
    "stcpb": "source TCP base sequence number",
    "dtcpb": "destination TCP base sequence number"
}

# ==================== BLOCKCHAIN IMPLEMENTATION ====================
class Block:
    """Blockchain block for immutable threat logging"""
    
    def __init__(self, data, previous_hash="0" * 64):
        self.timestamp = datetime.now().isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calculate SHA-256 hash of block"""
        hash_string = f"{self.timestamp}{self.data}{self.previous_hash}".encode('utf-8')
        return hashlib.sha256(hash_string).hexdigest()

class Blockchain:
    """Blockchain for tamper-proof threat log storage"""
    
    def __init__(self):
        self.chain = []
        genesis = Block("Genesis Block - CYBERSECURE Initialized", "0" * 64)
        self.chain.append(genesis)
    
    def add_block(self, data):
        """Add new block to chain"""
        previous_hash = self.chain[-1].hash if self.chain else "0" * 64
        new_block = Block(data, previous_hash)
        self.chain.append(new_block)
        return new_block
    
    def get_chain(self):
        """Get complete blockchain"""
        return [
            {
                "entry": block.data,
                "hash": block.hash,
                "prev_hash": block.previous_hash,
                "timestamp": block.timestamp
            }
            for block in self.chain
        ]
    
    def verify_chain(self):
        """Verify blockchain integrity"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            
            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
        
        return True

blockchain = Blockchain()

# # ==================== REPORT GENERATOR ====================
# # class ReportGenerator:
#     """Generate PDF, TXT, and RAG knowledge base reports"""
    
#     @staticmethod
#     def generate_pdf_report(log_reports: List[Dict], filename: str = "threat_report.pdf") -> bytes:
#         """Generate professional PDF report with benign and intrusion analysis"""
#         buffer = io.BytesIO()
#         doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        
#         elements = []
#         styles = getSampleStyleSheet()
        
#         # Custom styles
#         title_style = ParagraphStyle(
#             'CustomTitle',
#             parent=styles['Heading1'],
#             fontSize=24,
#             textColor=colors.HexColor('#FF0000'),
#             spaceAfter=12,
#             alignment=1  # Center
#         )
        
#         heading_style = ParagraphStyle(
#             'CustomHeading',
#             parent=styles['Heading2'],
#             fontSize=14,
#             textColor=colors.HexColor('#00CC00'),
#             spaceAfter=8,
#             spaceBefore=8
#         )
        
#         # Title
#         elements.append(Paragraph("🔒 CYBERSECURE NETWORK ANALYSIS REPORT", title_style))
#         elements.append(Spacer(1, 0.3*inch))
        
#         # Summary Section
#         elements.append(Paragraph("📊 EXECUTIVE SUMMARY", heading_style))
        
#         benign_count = sum(1 for r in log_reports if r.get('attack_type') == 'Benign')
#         intrusion_count = len(log_reports) - benign_count
        
#         summary_data = [
#             ["Total Flows Analyzed", len(log_reports)],
#             ["Benign Flows", benign_count],
#             ["Intrusion Flows", intrusion_count],
#             ["Critical Threats", sum(1 for r in log_reports if r.get('severity') == 'CRITICAL')],
#             ["High Severity", sum(1 for r in log_reports if r.get('severity') == 'HIGH')],
#             ["Medium Severity", sum(1 for r in log_reports if r.get('severity') == 'MEDIUM')],
#             ["Low Severity", sum(1 for r in log_reports if r.get('severity') == 'LOW')],
#             ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
#         ]
        
#         summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
#         summary_table.setStyle(TableStyle([
#             ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1a1a1a')),
#             ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#0d3d0d')),
#             ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#00ff00')),
#             ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
#             ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
#             ('FONTSIZE', (0, 0), (-1, -1), 10),
#             ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
#             ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#00ff00'))
#         ]))
#         elements.append(summary_table)
#         elements.append(Spacer(1, 0.3*inch))
        
#         # Detailed Flow Analysis
#         elements.append(Paragraph("🚨 DETAILED FLOW ANALYSIS", heading_style))
        
#         log_table_data = [
#             ["Flow ID", "Type", "Severity", "Confidence", "Source IP", "Action", "Explanation"]
#         ]
        
#         for report in log_reports[:50]:  # Limit to 50 for PDF size
#             explanation = report.get('explanation', 'N/A')[:80] + "..." if len(report.get('explanation', '')) > 80 else report.get('explanation', 'N/A')
#             action = report.get('security_actions', 'N/A')[:30] + "..." if len(report.get('security_actions', '')) > 30 else report.get('security_actions', 'N/A')
            
#             log_table_data.append([
#                 str(report.get('flow_id', 'N/A'))[:12],
#                 str(report.get('attack_type', 'N/A')),
#                 str(report.get('severity', 'N/A')),
#                 str(report.get('confidence', 'N/A')),
#                 str(report.get('source_ip', 'N/A')),
#                 action,
#                 explanation
#             ])
        
#         log_table = Table(log_table_data, colWidths=[0.8*inch, 0.9*inch, 0.8*inch, 0.8*inch, 1*inch, 1*inch, 1.5*inch])
#         log_table.setStyle(TableStyle([
#             ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a1a')),
#             ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00ff00')),
#             ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
#             ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
#             ('FONTSIZE', (0, 0), (-1, 0), 8),
#             ('FONTSIZE', (0, 1), (-1, -1), 7),
#             ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
#             ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00ff00')),
#             ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#0d0d0d'), colors.HexColor('#1a1a1a')])
#         ]))
#         elements.append(log_table)
#         elements.append(PageBreak())
        
#         # Recommended Actions (Only for Intrusions)
#         intrusion_reports = [r for r in log_reports if r.get('attack_type') != 'Benign']
#         if intrusion_reports:
#             elements.append(Paragraph("⚙️ RECOMMENDED SECURITY ACTIONS", heading_style))
            
#             critical_actions = set()
#             for report in intrusion_reports:
#                 if report.get('severity') in ['CRITICAL', 'HIGH']:
#                     actions = report.get('all_actions', [])
#                     critical_actions.update(actions[:5])
            
#             if critical_actions:
#                 actions_text = "<br/>".join([f"• {action}" for action in list(critical_actions)[:15]])
#                 elements.append(Paragraph(actions_text, styles['BodyText']))
#             else:
#                 elements.append(Paragraph("No critical actions required.", styles['BodyText']))
        
#         # Build PDF
#         doc.build(elements)
#         buffer.seek(0)
#         return buffer.getvalue()
    
#     @staticmethod
#     def generate_txt_report(log_reports: List[Dict], filename: str = "threat_report.txt") -> str:
#         """Generate TXT report optimized for RAG ingestion"""
        
#         benign_count = sum(1 for r in log_reports if r.get('attack_type') == 'Benign')
#         intrusion_count = len(log_reports) - benign_count
#         intrusion_reports = [r for r in log_reports if r.get('attack_type') != 'Benign']
        
#         report_lines = [
#             "=" * 100,
#             "CYBERSECURE NETWORK ANALYSIS REPORT - RAG KNOWLEDGE BASE",
#             "=" * 100,
#             f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
#             "",
#             "EXECUTIVE SUMMARY",
#             "-" * 100,
#             f"Total Flows Analyzed: {len(log_reports)}",
#             f"Benign Flows: {benign_count} ({(benign_count/len(log_reports)*100):.1f}%)" if log_reports else "Benign Flows: 0",
#             f"Intrusion Flows: {intrusion_count} ({(intrusion_count/len(log_reports)*100):.1f}%)" if log_reports else "Intrusion Flows: 0",
#             f"Critical Severity: {sum(1 for r in intrusion_reports if r.get('severity') == 'CRITICAL')}",
#             f"High Severity: {sum(1 for r in intrusion_reports if r.get('severity') == 'HIGH')}",
#             f"Medium Severity: {sum(1 for r in intrusion_reports if r.get('severity') == 'MEDIUM')}",
#             f"Low Severity: {sum(1 for r in intrusion_reports if r.get('severity') == 'LOW')}",
#             "",
#             "=" * 100,
#             "DETAILED FLOW LOG (ALL PREDICTIONS - BENIGN + INTRUSION)",
#             "=" * 100,
#             ""
#         ]
        
#         for idx, report in enumerate(log_reports, 1):
#             is_benign = report.get('attack_type') == 'Benign'
            
#             report_lines.extend([
#                 f"FLOW #{idx} - {report.get('attack_type', 'N/A').upper()}",
#                 "-" * 100,
#                 f"Flow ID: {report.get('flow_id', 'N/A')}",
#                 f"Timestamp: {report.get('timestamp', 'N/A')}",
#                 f"Source IP: {report.get('source_ip', 'N/A')}",
#                 f"Destination IP: {report.get('dest_ip', 'N/A')}",
#                 f"Destination Port: {report.get('dest_port', 'N/A')}",
#                 f"Classification: {report.get('attack_type', 'N/A')}",
#                 f"Confidence Score: {report.get('confidence', 'N/A')}",
#             ])
            
#             if not is_benign:
#                 report_lines.extend([
#                     f"Severity Level: {report.get('severity', 'N/A')}",
#                     f"Priority: {report.get('priority', 'N/A')}",
#                     f"SLA Response Time: {report.get('sla', 'N/A')}",
#                     f"Requires Manual Review: {report.get('requires_review', False)}",
#                 ])
            
#             report_lines.extend([
#                 "",
#                 "EXPLANATION:",
#                 f"{report.get('explanation', 'No explanation available')}",
#                 ""
#             ])
            
#             if not is_benign:
#                 report_lines.extend([
#                     "TOP CONTRIBUTING FEATURES (SHAP):",
#                     ""
#                 ])
                
#                 shap_features = report.get('shap_top_features', [])
#                 if shap_features:
#                     for feat_name, feat_value in shap_features:
#                         report_lines.append(f"  - {feat_name}: {feat_value:.4f}")
#                 else:
#                     report_lines.append("  - No feature importance data available")
                
#                 report_lines.extend([
#                     "",
#                     "RECOMMENDED SECURITY ACTIONS:",
#                     ""
#                 ])
                
#                 actions = report.get('all_actions', [])
#                 for i, action in enumerate(actions[:5], 1):
#                     report_lines.append(f"  {i}. {action}")
#             else:
#                 report_lines.append("SECURITY ACTION: ALLOW_TRAFFIC (Benign flow)")
            
#             report_lines.extend([
#                 "",
#                 "=" * 100,
#                 ""
#             ])
        
#         # Attack Type Statistics
#         if intrusion_reports:
#             report_lines.extend([
#                 "ATTACK TYPE STATISTICS (INTRUSIONS ONLY)",
#                 "-" * 100,
#                 ""
#             ])
            
#             attack_counts = {}
#             for report in intrusion_reports:
#                 attack_type = report.get('attack_type', 'Unknown')
#                 attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
            
#             for attack_type, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
#                 report_lines.append(f"  {attack_type}: {count} occurrences")
        
#         report_lines.extend([
#             "",
#             "CLASSIFICATION DISTRIBUTION",
#             "-" * 100,
#             f"  Benign: {benign_count} ({(benign_count/len(log_reports)*100):.1f}%)" if log_reports else "  Benign: 0 (0.0%)",
#             f"  Intrusion: {intrusion_count} ({(intrusion_count/len(log_reports)*100):.1f}%)" if log_reports else "  Intrusion: 0 (0.0%)",
#             "",
#             "=" * 100,
#             "END OF REPORT",
#             "=" * 100
#         ])
        
#         return "\n".join(report_lines)
    
#     @staticmethod
#     def generate_rag_knowledge_base(log_reports: List[Dict]) -> str:
#         """Generate RAG-optimized knowledge base for chatbot Q&A"""
        
#         benign_count = sum(1 for r in log_reports if r.get('attack_type') == 'Benign')
#         intrusion_reports = [r for r in log_reports if r.get('attack_type') != 'Benign']
        
#         kb_lines = [
#             "# CYBERSECURE NETWORK INTELLIGENCE KNOWLEDGE BASE",
#             "# Optimized for RAG (Retrieval-Augmented Generation) Q&A System",
#             f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
#             "",
#             "## ANALYSIS OVERVIEW",
#             f"Total Flows Analyzed: {len(log_reports)}",
#             f"Benign Flows: {benign_count}",
#             f"Intrusion Flows: {len(intrusion_reports)}",
#             f"Analysis Date: {datetime.now().strftime('%Y-%m-%d')}",
#             f"Critical Incidents: {sum(1 for r in intrusion_reports if r.get('severity') == 'CRITICAL')}",
#             "",
#             "## ATTACK PATTERNS (INTRUSIONS ONLY)",
#             ""
#         ]
        
#         if not intrusion_reports:
#             kb_lines.extend([
#                 "No intrusions detected. All flows classified as benign.",
#                 ""
#             ])
#             return "\n".join(kb_lines)
        
#         # Organize by attack type
#         attacks_by_type = {}
#         for report in intrusion_reports:
#             attack_type = report.get('attack_type', 'Unknown')
#             if attack_type not in attacks_by_type:
#                 attacks_by_type[attack_type] = []
#             attacks_by_type[attack_type].append(report)
        
#         for attack_type, reports in sorted(attacks_by_type.items()):
#             severity_counts = {s: sum(1 for r in reports if r.get('severity') == s) for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
#             severity_dist_parts = [f"{s}:{count}" for s, count in severity_counts.items() if count > 0]
#             severity_dist = ', '.join(severity_dist_parts) if severity_dist_parts else 'None'

#             kb_lines.extend([
#                 f"### {attack_type.upper()} ATTACKS",
#                 f"Frequency: {len(reports)} occurrences",
#                 f"Average Confidence: {np.mean([float(r.get('confidence', '0%').strip('%'))/100 for r in reports]):.1%}",
#                 f"Severity Distribution: {severity_dist}",
#                 ""
#             ])
        
#         kb_lines.extend([
#             "## FAQ GENERATED FROM ANALYSIS DATA",
#             "",
#             "Q: What percentage of traffic is benign vs malicious?",
#             f"A: {(benign_count/len(log_reports)*100):.1f}% benign, {(len(intrusion_reports)/len(log_reports)*100):.1f}% intrusion" if log_reports else "A: N/A",
#             "",
#             "Q: What are the most common attack types detected?",
#             f"A: {', '.join(sorted(attacks_by_type.keys(), key=lambda x: len(attacks_by_type[x]), reverse=True)[:5]) if attacks_by_type else 'None'}",
#             "",
#             f"Q: How many critical threats were detected?",
#             f"A: {sum(1 for r in intrusion_reports if r.get('severity') == 'CRITICAL')} critical threats detected.",
#             "",
#             "Q: What classification method is used?",
#             "A: Binary classification (0=benign, 1=intrusion) with confidence-based attack type assignment.",
#             ""
#         ])
        
#         return "\n".join(kb_lines)

# report_generator = ReportGenerator()

# ==================== TRIAGE ENGINE ====================
class TriageEngine:
    """Rule-based security triage system with SHAP explanations"""
    
    def __init__(self):
        self.severity_thresholds = {
            'critical': {'attack_types': ['Backdoor', 'Shellcode', 'Worms', 'Exploits'], 'min_confidence': 0.70},
            'high': {'attack_types': ['DoS', 'Reconnaissance'], 'min_confidence': 0.75},
            'medium': {'attack_types': ['Fuzzers', 'Generic'], 'min_confidence': 0.60},
            'low': {'attack_types': ['Analysis'], 'min_confidence': 0.50}
        }
    
    def calculate_severity(self, attack_type: str, confidence: float) -> Severity:
        """Calculate severity based on attack type and confidence"""
        if attack_type in ['Backdoor', 'Shellcode', 'Worms', 'Exploits'] and confidence >= 0.70:
            return Severity.CRITICAL
        elif attack_type in ['DoS', 'Reconnaissance'] and confidence >= 0.75:
            return Severity.HIGH
        elif attack_type in ['Fuzzers', 'Generic'] and confidence >= 0.60:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def generate_commands(self, attack_type: str, severity: Severity, source_ip: str, 
                         dest_port: int, confidence: float) -> List[str]:
        """Generate security commands based on attack type and severity"""
        commands = [f"LOG_INCIDENT: {attack_type} FROM {source_ip}"]
        
        # Severity-based actions
        if severity == Severity.CRITICAL:
            commands.extend([
                f"BLOCK_IP_PERMANENT: {source_ip}",
                "ELEVATE_SECURITY_POSTURE: DEFCON_2",
                "NOTIFY_SOC_TEAM: IMMEDIATE",
                "INITIATE_INCIDENT_RESPONSE: LEVEL_1"
            ])
        elif severity == Severity.HIGH:
            commands.extend([
                f"BLOCK_IP_TEMP_24H: {source_ip}",
                "ALERT_SOC_ESCALATE",
                "ENABLE_RATE_LIMITING",
                "ENHANCED_MONITORING: TARGET_SUBNET"
            ])
        elif severity == Severity.MEDIUM:
            commands.extend([
                f"BLOCK_IP_TEMP_1H: {source_ip}",
                "ENHANCED_LOGGING",
                "TRIGGER_WAF_INSPECTION"
            ])
        else:
            commands.extend([
                f"FLAG_SUSPICIOUS: {source_ip}",
                "REVIEW_REQUIRED",
                "PASSIVE_MONITORING: 48H"
            ])
        
        # Add attack-specific actions
        if attack_type in TRIAGE_ACTIONS:
            attack_specific = TRIAGE_ACTIONS[attack_type]
            for action in attack_specific:
                if action not in commands:
                    commands.append(action)
        
        # High-confidence critical threats
        if severity == Severity.CRITICAL and confidence >= 0.90:
            commands.extend([
                "NETWORK_WIDE_SCAN: ALL_ENDPOINTS",
                "ISOLATE_AFFECTED_SEGMENT",
                "ENABLE_EMERGENCY_PROTOCOLS"
            ])
        
        return commands
    
    def assign_priority(self, severity: Severity) -> Tuple[int, int]:
        """Assign priority level and SLA response time"""
        priority_map = {
            Severity.CRITICAL: (1, 5),      # P1 - 5 minutes
            Severity.HIGH: (2, 15),         # P2 - 15 minutes
            Severity.MEDIUM: (3, 60),       # P3 - 1 hour
            Severity.LOW: (4, 240)          # P4 - 4 hours
        }
        return priority_map[severity]
    
    def needs_human_review(self, severity: Severity, confidence: float) -> bool:
        """Determine if manual review is required"""
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
        for feat_name, shap_val in top_features[:3]:
            clean_name = feat_name.split('__')[-1] if '__' in feat_name else feat_name
            explanation = FEATURE_EXPLANATIONS.get(clean_name, clean_name)
            direction = "high" if shap_val > 0 else "low"
            reasons.append(f"{direction} {explanation}")
        
        return f"This flow was flagged as '{attack_type}' (confidence: {confidence:.1%}) due to: {', '.join(reasons)}."
    
    def evaluate(self, attack_type: str, confidence: float, source_ip: str,
                dest_port: int, flow_metadata: Dict, shap_features: Optional[List[Tuple[str, float]]] = None) -> Dict:
        """Apply triage logic with SHAP explanations"""
        severity = self.calculate_severity(attack_type, confidence)
        commands = self.generate_commands(attack_type, severity, source_ip, dest_port, confidence)
        priority, sla_minutes = self.assign_priority(severity)
        
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
            'confidence_score': float(confidence),
            'explanation': explanation
        }

triage_engine = TriageEngine()

# ==================== ML MODEL (BINARY CLASSIFICATION ONLY) ====================
class UNSWModel:
    """Binary classification model with confidence-based attack type assignment"""
    
    def __init__(self):
        self.model = None
        self.preprocessor = None
        self.threshold = 0.5
        self.explainer = None
        self.feature_names = []
    
    def load_model(self):
        """Load binary classifier and preprocessor"""
        try:
            # Load binary classifier
            model_path = r'D:\gitkrishna\SPIT HACK\models\unsw_trained_model.pkl'
            bundle = joblib.load(model_path)
            self.model = bundle['model']
            self.threshold = bundle.get('threshold', 0.5)
            
            # Load preprocessor
            preprocessor_path = r'D:\gitkrishna\SPIT HACK\models\unsw_preprocessor.pkl'
            self.preprocessor = joblib.load(preprocessor_path)
            self.feature_names = self.preprocessor.get_feature_names_out().tolist()
            
            # Initialize SHAP explainer
            self.explainer = shap.Explainer(self.model)
            
            print(f"✓ Binary classifier loaded successfully")
            print(f"✓ Threshold: {self.threshold:.3f}")
            print(f"✓ Features: {len(self.feature_names)}")
            print(f"✓ Attack type assignment: Confidence-based (no multi-class model)")
            
            return True
        
        except Exception as e:
            print(f"⚠ Model loading failed: {e}")
            print(f"⚠ Make sure files exist:")
            print(f"   - models/unsw_trained_model.pkl")
            print(f"   - models/unsw_preprocessor.pkl")
            return False
    
    def predict(self, X_preprocessed):
        """Binary prediction: 0=benign, 1=intrusion"""
        if self.model is None:
            raise ValueError("Model not loaded")
        
        probabilities = self.model.predict_proba(X_preprocessed)[:, 1]
        predictions = (probabilities >= self.threshold).astype(int)
        return predictions, probabilities
    
    def classify_attack_by_confidence(self, confidence: float) -> str:
        """
        Classify attack type based ONLY on confidence score
        No multi-class model used - purely deterministic mapping
        """
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
        elif confidence >= 0.60:
            return 'Analysis'
        else:
            return 'Generic'
    
    def get_shap_explanation(self, X_preprocessed) -> List[Tuple[str, float]]:
        """Generate SHAP explanation for prediction"""
        if self.explainer is None:
            return []
        
        try:
            shap_values = self.explainer(X_preprocessed)
            
            # Extract SHAP values
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
        
        except Exception as e:
            print(f"⚠ SHAP explanation failed: {e}")
            return []

unsw_model = UNSWModel()

# ==================== HELPER FUNCTIONS ====================
def extract_flow_metadata(row: pd.Series) -> Dict:
    """Extract flow metadata with proper type conversion"""
    metadata = {}
    
    # Source IP
    possible_ip_cols = ['srcip', 'src_ip', 'source_ip', 'saddr']
    for col in possible_ip_cols:
        if col in row.index:
            metadata['source_ip'] = str(row[col])
            break
    
    # Destination IP
    possible_dst_cols = ['dstip', 'dst_ip', 'destination_ip', 'daddr']
    for col in possible_dst_cols:
        if col in row.index:
            metadata['dest_ip'] = str(row[col])
            break
    
    # Destination Port
    possible_port_cols = ['dport', 'dst_port', 'destination_port', 'sport', 'src_port']
    for col in possible_port_cols:
        if col in row.index:
            metadata['dest_port'] = int(row[col]) if pd.notna(row[col]) else 80
            break
    
    # Defaults
    metadata.setdefault('source_ip', '0.0.0.0')
    metadata.setdefault('dest_ip', '0.0.0.0')
    metadata.setdefault('dest_port', 0)
    
    return metadata

# ==================== PYDANTIC MODELS ====================
class FlowData(BaseModel):
    """Flow data for prediction"""
    flow: List[float]

# Global storage
uploaded_data_store = {}

# ==================== LIFESPAN ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    print("🚀 CYBERSECURE API Started")
    print("📊 Blockchain initialized with genesis block")
    
    model_loaded = unsw_model.load_model()
    if model_loaded:
        print("✅ UNSW-NB15 Binary Classifier Loaded Successfully")
        print("✅ Triage Engine Initialized (Confidence-Based Attack Classification)")
        print("✅ SHAP Explainer Ready")
    else:
        print("⚠️ Running in Demo Mode - Model Not Loaded")
    
    print("🔗 API running on http://localhost:5000")
    yield
    print("⚠️ CYBERSECURE API Shutting down...")

# ==================== CREATE APP ====================
app = FastAPI(
    title="CYBERSECURE API",
    version="3.0.0",
    description="Binary Network Intrusion Detection with Confidence-Based Attack Classification",
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
    """API root endpoint"""
    return {
        "message": "CYBERSECURE API v3.0 - Binary Classification + Confidence-Based Triage",
        "endpoints": [
            "/upload",
            "/threat_log",
            "/simulate",
            "/explain",
            "/model_info",
            "/export/pdf",
            "/export/txt",
            "/export/rag-kb",
            "/export/all"
        ],
        "features": [
            "Binary Classification (0=benign, 1=intrusion)",
            "Confidence-Based Attack Type Assignment",
            "SHAP Explainability",
            "Triage Engine",
            "Blockchain Logging",
            "PDF/TXT/RAG Export"
        ],
        "version": "3.0.0"
    }

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload and process network traffic CSV"""
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
        
        print(f"✓ Binary predictions: {int(sum(predictions))} intrusions, {int(len(predictions) - sum(predictions))} benign")
        
        # Generate log reports - ALL PREDICTIONS
        log_reports = []
        benign_count = 0
        intrusion_count = 0
        
        for idx, (pred, prob) in enumerate(zip(predictions, probabilities)):
            if idx >= 100:  # Performance limit
                break
            
            row = df.iloc[idx]
            metadata = extract_flow_metadata(row)
            
            if pred == 1:  # INTRUSION
                intrusion_count += 1
                
                # Classify attack type based on confidence
                attack_type = unsw_model.classify_attack_by_confidence(prob)
                
                # Get SHAP explanation
                X_single = X_preprocessed[idx:idx+1]
                shap_features = unsw_model.get_shap_explanation(X_single)
                
                # Apply triage
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
                    'source_ip': str(metadata['source_ip']),
                    'dest_ip': str(metadata['dest_ip']),
                    'dest_port': int(metadata['dest_port']),
                    'attack_type': str(attack_type),
                    'confidence': f"{float(prob):.2%}",
                    'severity': str(triage_result['severity']),
                    'priority': str(triage_result['priority']),
                    'sla': str(triage_result['sla_response_time']),
                    'security_actions': ', '.join(triage_result['commands'][:3]),
                    'requires_review': bool(triage_result['requires_manual_review']),
                    'explanation': str(triage_result['explanation']),
                    'shap_top_features': [(str(f), float(v)) for f, v in shap_features[:3]],
                    'all_actions': triage_result['commands']
                }
                
                log_reports.append(log_entry)
                
                # Add to blockchain
                blockchain.add_block(
                    f"INTRUSION: {attack_type} | SRC: {metadata['source_ip']} | "
                    f"Confidence: {prob:.2%} | Severity: {triage_result['severity']}"
                )
            
            else:  # BENIGN
                benign_count += 1
                
                log_entry = {
                    'flow_id': f"FID-{idx:06d}",
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'source_ip': str(metadata['source_ip']),
                    'dest_ip': str(metadata['dest_ip']),
                    'dest_port': int(metadata['dest_port']),
                    'attack_type': 'Benign',
                    'confidence': f"{float(1-prob):.2%}",
                    'severity': 'NONE',
                    'priority': 'N/A',
                    'sla': 'N/A',
                    'security_actions': 'ALLOW_TRAFFIC',
                    'requires_review': False,
                    'explanation': f"This flow is classified as benign with {float(1-prob):.1%} confidence.",
                    'shap_top_features': [],
                    'all_actions': []
                }
                
                log_reports.append(log_entry)
        
        # Count remaining flows
        if len(predictions) > 100:
            remaining_intrusions = int(sum(predictions[100:]))
            intrusion_count += remaining_intrusions
            benign_count += (len(predictions) - 100 - remaining_intrusions)
        
        # Store data
        uploaded_data_store['dataframe'] = df
        uploaded_data_store['predictions'] = predictions
        uploaded_data_store['probabilities'] = probabilities
        uploaded_data_store['log_reports'] = log_reports
        
        # Graph data
        # graph_data = {
        #     "pie": {
        #         "labels": ["Benign", "Intrusion"],
        #         "values": [int(benign_count), int(intrusion_count)]
        #     },
        #     "bar": {
        #         "labels": ["Critical", "High", "Medium", "Low"],
        #         "values": [
        #             int(sum(1 for r in log_reports if r.get('severity') == 'CRITICAL')),
        #             int(sum(1 for r in log_reports if r.get('severity') == 'HIGH')),
        #             int(sum(1 for r in log_reports if r.get('severity') == 'MEDIUM')),
        #             int(sum(1 for r in log_reports if r.get('severity') == 'LOW'))
        #         ]
        #     },
        #     "line": {
        #         "labels": [f"Flow {i}" for i in range(min(20, len(probabilities)))],
        #         "values": [float(p) for p in probabilities[:20]]
        #     }
        # }
        graph_data = {
            "pie": {
                "labels": ["Benign", "Intrusion"],
                "values": [int(benign_count), int(intrusion_count)]
            },
            "bar": {
                "labels": ["Critical", "High", "Medium", "Low"],
                "values": [
                    sum(1 for r in log_reports if r['severity'] == 'CRITICAL'),
                    sum(1 for r in log_reports if r['severity'] == 'HIGH'),
                    sum(1 for r in log_reports if r['severity'] == 'MEDIUM'),
                    sum(1 for r in log_reports if r['severity'] == 'LOW')
                ]
            },
            "line": {
                "labels": [f"Flow {i}" for i in range(min(20, len(probabilities)))],
                "values": probabilities[:20].tolist() if len(probabilities) > 0 else []
            }
        }
        
        segregated_data = log_reports[:10] if log_reports else []
        
        print(f"✅ Processing complete: {intrusion_count} intrusions, {benign_count} benign")
        
        return {
            "message": "File processed successfully",
            "filename": file.filename,
            "summary": {
                "rows": int(len(df)),
                "columns": [str(col) for col in df.columns.tolist()[:10]],
                "benign_count": int(benign_count),
                "intrusion_count": int(intrusion_count),
                "segregated_data": segregated_data
            },
            "graph_data": graph_data,
            "total_log_entries": int(len(log_reports))
        }
    
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
    """Simulate real-time network flows"""
    try:
        if unsw_model.model is None:
            raise HTTPException(status_code=503, detail="Model not loaded")
        
        num_flows = 5
        num_features = len(unsw_model.feature_names)
        
        # Generate random flows
        simulated_df = pd.DataFrame(
            np.random.rand(num_flows, num_features),
            columns=unsw_model.feature_names
        )
        
        X_preprocessed = unsw_model.preprocessor.transform(simulated_df)
        predictions, probabilities = unsw_model.predict(X_preprocessed)
        
        results = []
        
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            if pred == 1:  # INTRUSION
                attack_type = unsw_model.classify_attack_by_confidence(prob)
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
                    "flow_id": int(i),
                    "prediction": "Intrusion",
                    "attack_type": attack_type,
                    "confidence": f"{float(prob):.2%}",
                    "action": triage_result['commands'][0],
                    "severity": triage_result['severity'],
                    "explanation": triage_result['explanation']
                })
            else:  # BENIGN
                results.append({
                    "flow_id": int(i),
                    "prediction": "Benign",
                    "confidence": f"{float(1-prob):.2%}",
                    "action": "ALLOW_TRAFFIC",
                    "severity": "NONE"
                })
        
        return results
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation error: {str(e)}")

@app.post("/explain")
async def explain_prediction(flow_data: FlowData):
    """Generate SHAP explanation for a flow"""
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
        
        shap_features = unsw_model.get_shap_explanation(X_preprocessed)
        
        if pred_label == "Intrusion":
            attack_type = unsw_model.classify_attack_by_confidence(probability[0])
            explanation = triage_engine.generate_explanation(attack_type, shap_features, probability[0])
        else:
            explanation = f"This flow is classified as benign with {float(1-probability[0]):.1%} confidence."
        
        blockchain.add_block(
            f"XAI: {pred_label} | Confidence: {probability[0]:.2%} | Top: {shap_features[0][0] if shap_features else 'N/A'}"
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
    """Get model information"""
    if unsw_model.model is None:
        return {
            "status": "Model not loaded",
            "message": "Ensure model files exist in models/ directory",
            "required_files": [
                "models/unsw_trained_model.pkl",
                "models/unsw_preprocessor.pkl"
            ]
        }
    
    return {
        "model_type": "XGBoost Binary Classifier",
        "dataset": "UNSW-NB15",
        "classification": "Binary (0=benign, 1=intrusion)",
        "attack_type_method": "Confidence-based mapping",
        "is_trained": True,
        "threshold": float(unsw_model.threshold),
        "features": len(unsw_model.feature_names),
        "triage_engine": "Rule-based with SHAP",
        "shap_explainer": "Enabled",
        "attack_categories": list(TRIAGE_ACTIONS.keys()),
        "version": "3.0.0"
    }

@app.get("/export/pdf")
async def export_pdf_report():
    """Export threat log as PDF"""
    try:
        if 'log_reports' not in uploaded_data_store:
            raise HTTPException(status_code=400, detail="No data. Upload a file first.")
        
        log_reports = uploaded_data_store.get('log_reports', [])
        pdf_content = report_generator.generate_pdf_report(log_reports)
        
        with open('exports/threat_report.pdf', 'wb') as f:
            f.write(pdf_content)
        
        return {
            "message": "PDF generated successfully",
            "filename": "threat_report.pdf",
            "size": len(pdf_content),
            "download_url": "/files/threat_report.pdf"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF error: {str(e)}")

@app.get("/export/txt")
async def export_txt_report():
    """Export threat log as TXT"""
    try:
        if 'log_reports' not in uploaded_data_store:
            raise HTTPException(status_code=400, detail="No data. Upload a file first.")
        
        log_reports = uploaded_data_store.get('log_reports', [])
        txt_content = report_generator.generate_txt_report(log_reports)
        
        with open('exports/threat_report.txt', 'w') as f:
            f.write(txt_content)
        
        return {
            "message": "TXT report generated successfully",
            "filename": "threat_report.txt",
            "size": len(txt_content),
            "download_url": "/files/threat_report.txt"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"TXT error: {str(e)}")

@app.get("/export/rag-kb")
async def export_rag_knowledge_base():
    """Export RAG knowledge base"""
    try:
        if 'log_reports' not in uploaded_data_store:
            raise HTTPException(status_code=400, detail="No data. Upload a file first.")
        
        log_reports = uploaded_data_store.get('log_reports', [])
        kb_content = report_generator.generate_rag_knowledge_base(log_reports)
        
        with open('exports/rag_knowledge_base.md', 'w') as f:
            f.write(kb_content)
        
        return {
            "message": "RAG KB generated successfully",
            "filename": "rag_knowledge_base.md",
            "size": len(kb_content),
            "download_url": "/files/rag_knowledge_base.md"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG KB error: {str(e)}")

@app.get("/export/all")
async def export_all_formats():
    """Export all report formats"""
    try:
        if 'log_reports' not in uploaded_data_store:
            raise HTTPException(status_code=400, detail="No data. Upload a file first.")
        
        log_reports = uploaded_data_store.get('log_reports', [])
        
        # Generate all formats
        pdf_content = report_generator.generate_pdf_report(log_reports)
        txt_content = report_generator.generate_txt_report(log_reports)
        kb_content = report_generator.generate_rag_knowledge_base(log_reports)
        
        # Save all files
        with open('exports/threat_report.pdf', 'wb') as f:
            f.write(pdf_content)
        
        with open('exports/threat_report.txt', 'w') as f:
            f.write(txt_content)
        
        with open('exports/rag_knowledge_base.md', 'w') as f:
            f.write(kb_content)
        
        print("✅ All export formats generated")
        
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

# ==================== STATIC FILES ====================
os.makedirs('exports', exist_ok=True)
app.mount("/files", StaticFiles(directory="exports"), name="exports")

# ==================== RUN SERVER ====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
