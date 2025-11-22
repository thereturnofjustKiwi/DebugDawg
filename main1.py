from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel
import pandas as pd
import numpy as np
from io import BytesIO
from datetime import datetime
from typing import List, Dict, Tuple
import joblib
import shap
from enum import IntEnum
from pathlib import Path

# ========== PATH CONFIG ==========
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = r'D:\SPIT HACK\models\unsw_trained_model.pkl'
PREPROCESSOR_PATH = r'D:\SPIT HACK\models\unsw_preprocessor.pkl'
ATTACK_CLASSIFIER_PATH = r'D:\SPIT HACK\models\unsw_attack_cat_ovr.pkl' 

# ========== SEVERITY ==============
class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

# ========== BLOCKCHAIN ============
class Block:
    def __init__(self, data, previous_hash="0"*64):
        self.timestamp = datetime.now().isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    def calculate_hash(self):
        import hashlib
        return hashlib.sha256((self.timestamp+self.data+self.previous_hash).encode('utf-8')).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [Block("Genesis Block - CYBERSECURE Initialized", "0"*64)]
    def add_block(self, data):
        new = Block(data, self.chain[-1].hash)
        self.chain.append(new)
        return new
    def get_chain(self):
        return [{"entry": b.data, "hash": b.hash, "prev_hash": b.previous_hash, "timestamp": b.timestamp}
                for b in self.chain]

blockchain = Blockchain()

# ========== TRIAGE ENGINE =========
class TriageEngine:
    def __init__(self):
        self.attack_severity_map = {
            'DoS': Severity.CRITICAL, 'Backdoor': Severity.CRITICAL, 'Exploits': Severity.HIGH,
            'Shellcode': Severity.CRITICAL, 'Worms': Severity.CRITICAL, 'Reconnaissance': Severity.MEDIUM,
            'Analysis': Severity.MEDIUM, 'Fuzzers': Severity.MEDIUM, 'Generic': Severity.LOW
        }
    def calculate_severity(self, attack_type: str, confidence: float) -> Severity:
        base = self.attack_severity_map.get(attack_type, Severity.LOW)
        if confidence < 0.60: return Severity.LOW
        if confidence < 0.75 and base == Severity.CRITICAL: return Severity.HIGH
        return base
    def generate_commands(self, attack_type: str, severity: Severity, src_ip: str, dport: int, confidence: float) -> List[str]:
        cmd = [f"LOG_INCIDENT: {attack_type} FROM {src_ip}"]
        rules = {
            'DoS': [f"BLOCK_IP_PERMANENT: {src_ip}", "ACTIVATE_DDOS_MITIGATION"],
            'Backdoor': [f"QUARANTINE_DEVICE: {src_ip}", f"BLOCK_IP_PERMANENT: {src_ip}"],
            'Exploits': [f"BLOCK_IP_TEMP_24H: {src_ip}", "ENABLE_WAF_RULE: EXPLOIT_PROTECTION"],
            'Shellcode': [f"QUARANTINE_DEVICE: {src_ip}", f"BLOCK_IP_PERMANENT: {src_ip}"],
            'Worms': [f"QUARANTINE_DEVICE: {src_ip}", f"BLOCK_IP_PERMANENT: {src_ip}"],
            'Reconnaissance': [f"MONITOR_IP: {src_ip}", f"BLOCK_IP_TEMP_1H: {src_ip}"],
            'Analysis': [f"MONITOR_IP: {src_ip}", f"BLOCK_IP_TEMP_1H: {src_ip}"],
            'Fuzzers': [f"BLOCK_IP_TEMP_6H: {src_ip}", "LOG_REQUEST: FULL_PAYLOAD"],
            'Generic': [f"FLAG_SUSPICIOUS: {src_ip}", "REVIEW_REQUIRED"]
        }
        cmd += rules.get(attack_type, [f"BLOCK_IP_TEMP_1H: {src_ip}", "FLAG_UNKNOWN_ATTACK_TYPE"])
        if severity == Severity.CRITICAL: cmd += ["NOTIFY_SOC_TEAM: IMMEDIATE"]
        elif severity == Severity.HIGH: cmd += ["ALERT_SOC_ESCALATE"]
        return cmd
    def assign_priority(self, severity: Severity) -> Tuple[int, int]:
        return {Severity.CRITICAL:(1,5), Severity.HIGH:(2,15),Severity.MEDIUM:(3,60),Severity.LOW:(4,240)}[severity]
    def needs_human_review(self, severity: Severity, confidence: float) -> bool:
        return severity == Severity.CRITICAL or confidence < 0.65
    def evaluate(self, attack_type: str, confidence: float, source_ip: str, dest_port: int, flow_metadata: Dict) -> Dict:
        sev = self.calculate_severity(attack_type, confidence)
        cmds = self.generate_commands(attack_type, sev, source_ip, dest_port, confidence)
        pri, sla = self.assign_priority(sev)
        return {"commands": cmds, "severity": sev.name, "priority": f"P{pri}", "sla_response_time": f"{sla} minutes",
                "requires_manual_review": self.needs_human_review(sev, confidence)}

triage_engine = TriageEngine()

# ========== OVR WRAPPER ==========
class OvRWrapper:
    def __init__(self, bundle):
        self.heads = {}; self.class_names = list(bundle.get("classes"))
        for k, v in bundle["heads"].items():
            self.heads[int(k)] = {"clf": v["clf"], "thr": float(v["thr"])}
    def predict(self, X):
        preds = []
        for i in range(X.shape[0]):
            best_c, best_margin = None, -1e9
            for c, h in self.heads.items():
                p = float(h["clf"].predict_proba(X[i])[:,1][0])
                margin = p - h["thr"]
                if margin > best_margin:
                    best_margin, best_c = margin, c
            preds.append(best_c if best_c is not None else 0)
        return np.array(preds, dtype=int)
    def predict_proba(self, X):
        P = np.zeros((X.shape[0], len(self.class_names)), dtype=float)
        for c, h in self.heads.items():
            P[:, c] = h["clf"].predict_proba(X)[:,1] - h["thr"] + 0.5
        row_sum = P.sum(axis=1, keepdims=True) + 1e-9
        return np.clip(P/row_sum, 0, 1)

# ========== MODEL ==========
class UNSWModel:
    def __init__(self):
        self.binary_model = None; self.threshold = 0.5
        self.preprocessor = None; self.explainer = None
        self.feature_names = []; self.attack_classifier = None
        self.attack_class_names = ['Analysis','Backdoor','DoS','Exploits','Fuzzers','Generic','Reconnaissance','Shellcode','Worms']
    def load_model(self):
        try:
            bundle = joblib.load(MODEL_PATH)
            self.binary_model = bundle['model']; self.threshold = bundle['threshold']
            self.preprocessor = joblib.load(PREPROCESSOR_PATH)
            self.feature_names = self.preprocessor.get_feature_names_out().tolist()
            attack_bundle = joblib.load(ATTACK_CLASSIFIER_PATH)
            self.attack_classifier = OvRWrapper(attack_bundle)
            self.explainer = shap.Explainer(self.binary_model)
            print("✓ Models loaded. Threshold:", self.threshold)
            return True
        except Exception as e:
            print("Model loading error:", e); return False
    def predict(self, X):
        p = self.binary_model.predict_proba(X)[:,1]
        return (p >= self.threshold).astype(int), p
    def predict_attack_type(self, X):
        if self.attack_classifier is None: return None, None
        idxs = self.attack_classifier.predict(X)
        P = self.attack_classifier.predict_proba(X)
        types = [self.attack_class_names[i] for i in idxs]
        confs = [float(P[r, i]) for r, i in enumerate(idxs)]
        return types, confs
    def get_shap_values(self, X):
        return self.explainer(X).values

unsw_model = UNSWModel()

# ========== FASTAPI ==========
class FlowData(BaseModel):
    flow: List[float]

uploaded_data_store = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    unsw_model.load_model()
    yield

app = FastAPI(title="CYBERSECURE API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def extract_flow_metadata(row: pd.Series) -> Dict:
    md = {}
    for col in ['srcip','src_ip','source_ip','saddr']:
        if col in row.index: md['source_ip'] = str(row[col]); break
    for col in ['dstip','dst_ip','destination_ip','daddr']:
        if col in row.index: md['dest_ip'] = str(row[col]); break
    for col in ['dport','dst_port','destination_port','sport','src_port']:
        if col in row.index and pd.notna(row[col]): md['dest_port'] = int(row[col]); break
    md.setdefault('source_ip','0.0.0.0'); md.setdefault('dest_ip','0.0.0.0'); md.setdefault('dest_port',0)
    return md

@app.get("/")
async def root():
    return {"message":"CYBERSECURE API", "endpoints":["/upload","/threat_log","/simulate","/explain","/model_info"]}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    contents = await file.read()
    df = pd.read_csv(BytesIO(contents))
    if df.empty: raise HTTPException(400, "Uploaded file is empty")
    if unsw_model.binary_model is None: raise HTTPException(503, "Model not loaded")

    # Drop labels if present
    for col in ['label','Label','attack_cat','attackcat','attack_type']:
        if col in df.columns:
            df = df.drop(columns=[col])

    X = unsw_model.preprocessor.transform(df)
    preds, probs = unsw_model.predict(X)

    attack_idx = np.where(preds==1)[0]
    attack_types_out = ['Unknown'] * len(preds)
    attack_conf_out = [0.0] * len(preds)

    if len(attack_idx) > 0 and unsw_model.attack_classifier is not None:
        X_attacks = X[attack_idx]
        types, confs = unsw_model.predict_attack_type(X_attacks)
        for j, ai in enumerate(attack_idx):
            attack_types_out[ai] = types[j]; attack_conf_out[ai] = confs[j]

    reports = []
    benign_count, intrusion_count = int((preds == 0).sum()), int((preds == 1).sum())

    for i in range(min(100, len(df))):
        row = df.iloc[i]
        md = extract_flow_metadata(row)
        if preds[i] == 1:
            tri = triage_engine.evaluate(
                attack_type=attack_types_out[i],
                confidence=float(probs[i]),
                source_ip=md['source_ip'],
                dest_port=md['dest_port'],
                flow_metadata=md
            )
            reports.append({
                "flow_id": f"FID-{i:06d}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": md['source_ip'],
                "dest_ip": md['dest_ip'],
                "dest_port": md['dest_port'],
                "attack_type": attack_types_out[i],
                "attack_confidence": f"{attack_conf_out[i]:.2%}" if attack_conf_out[i] > 0 else "N/A",
                "detection_confidence": f"{float(probs[i]):.2%}",
                "severity": tri['severity'],
                "priority": tri['priority'],
                "sla": tri['sla_response_time'],
                "security_actions": ', '.join(tri['commands'][:3]),
                "requires_review": tri['requires_manual_review'],
                "all_actions": tri['commands']
            })
            blockchain.add_block(
                f"INTRUSION: {attack_types_out[i]} | SRC: {md['source_ip']} | Conf: {float(probs[i]):.2%} | Sev: {tri['severity']}"
            )

    uploaded_data_store['dataframe'] = df
    uploaded_data_store['predictions'] = preds
    uploaded_data_store['probabilities'] = probs
    uploaded_data_store['log_reports'] = reports

    graph_data = {
        "pie": {"labels":["Benign","Intrusion"], "values":[benign_count, intrusion_count]},
        "bar": {"labels":["Critical","High","Medium","Low"],
                "values":[sum(1 for r in reports if r['severity']=="CRITICAL"),
                          sum(1 for r in reports if r['severity']=="HIGH"),
                          sum(1 for r in reports if r['severity']=="MEDIUM"),
                          sum(1 for r in reports if r['severity']=="LOW")]},
        "line": {"labels":[f"Flow {i}" for i in range(min(20, len(probs)))],
                 "values": probs[:20].tolist()}
    }

    return {"message":"File processed successfully with attack-type classification",
            "filename": file.filename,
            "summary":{"rows": len(df), "columns": df.columns.tolist()[:10],
                       "benign_count": benign_count, "intrusion_count": intrusion_count,
                       "segregated_data": reports[:10]},
            "graph_data": graph_data, "total_log_entries": len(reports)}

@app.get("/threat_log")
async def get_threat_log():
    return blockchain.get_chain()

@app.get("/simulate")
async def simulate_flows():
    if unsw_model.binary_model is None:
        raise HTTPException(503, "Model not loaded")
    if 'dataframe' not in uploaded_data_store:
        raise HTTPException(400, "Upload a file first")

    template = uploaded_data_store['dataframe'].head(1)
    rows = []
    for _ in range(5):
        r = {}
        for col in template.columns:
            if str(template[col].dtype) in ['int64','float64']:
                r[col] = float(np.random.rand() * max(1.0, float(template[col].abs().max())))
            else:
                r[col] = template[col].iloc[0]
        rows.append(r)
    df = pd.DataFrame(rows)
    X = unsw_model.preprocessor.transform(df)
    preds, probs = unsw_model.predict(X)

    out = []
    for i, (p, pr) in enumerate(zip(preds, probs)):
        if p == 1:
            atype = "Unknown"
            if unsw_model.attack_classifier is not None:
                t, c = unsw_model.predict_attack_type(X[i])
                atype = t[0]
            tri = triage_engine.evaluate(atype, float(pr),
                                         source_ip=f"10.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
                                         dest_port=int(np.random.choice([80,443,22,3306])), flow_metadata={})
            out.append({"flow_id": i, "prediction":"Intrusion", "attack_type": atype,
                        "confidence": f"{float(pr):.2%}", "action": tri['commands'][0], "severity": tri['severity']})
        else:
            out.append({"flow_id": i, "prediction":"Benign",
                        "confidence": f"{float(1-pr):.2%}", "action":"ALLOW_TRAFFIC", "severity":"NONE"})
    return out

@app.post("/explain")
async def explain_prediction(flow: FlowData):
    if unsw_model.binary_model is None:
        raise HTTPException(503, "Model not loaded")
    if 'dataframe' not in uploaded_data_store:
        raise HTTPException(400, "Upload a CSV first")

    template = uploaded_data_store['dataframe'].head(1)
    arr = np.array(flow.flow, dtype=object)
    if len(arr) != len(template.columns):
        raise HTTPException(400, f"Expected {len(template.columns)} features, got {len(arr)}")
    df = pd.DataFrame([arr], columns=template.columns)
    X = unsw_model.preprocessor.transform(df)
    preds, probs = unsw_model.predict(X)
    label = "Intrusion" if preds[0] == 1 else "Benign"

    sv = unsw_model.get_shap_values(X)
    shap_abs = np.abs(sv[0])
    top_idx = np.argsort(shap_abs)[-5:][::-1]
    top_features = [(unsw_model.feature_names[i], float(sv[0][i])) for i in top_idx]

    blockchain.add_block(f"XAI: {label} | Conf: {float(probs[0]):.2%} | Top: {top_features[0][0]}")
    return {"prediction": label, "confidence": f"{float(probs[0]):.2%}",
            "top_features": top_features, "feature_count": len(template.columns)}

@app.get("/model_info")
async def model_info():
    status = "loaded" if unsw_model.binary_model is not None else "not_loaded"
    atk = unsw_model.attack_classifier is not None
    return {"status": status, "threshold": unsw_model.threshold, "features": len(unsw_model.feature_names),
            "attack_classifier_loaded": atk, "triage_engine": True, "shap_ready": unsw_model.explainer is not None}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)