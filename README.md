# DebugDawg

# 🛡️ CyberSecure: AI/ML Real-Time Network Intrusion Triage

## 🌟 Project Overview

**CyberSecure** is an advanced, end-to-end Machine Learning (ML) solution designed to provide **automated, real-time intrusion detection and triage** for Security Operations Centers (SOCs).

The system uses a highly optimized **Random Forest** model to classify network traffic flows, aiming for maximum **Recall** to ensure minimal missed attacks. For every detected intrusion, the system suggests an immediate, tactical security response. Crucially, the system implements an **immutable logging mechanism** using cryptographic hashing, providing an auditable, tamper-proof record of every security incident.

---

## 🛠️ Tech Stack & Dependencies

| Component | Technology | Role in the System |
| :--- | :--- | :--- |
| **Backend/API** | **FASTAPI** (Python) | High-performance API for serving the ML model and handling data inputs. |
| **Machine Learning** | **Random Forest** (Python/Scikit-learn) | The core classification engine trained for speed and high Recall. |
| **Dataset** | **CIC-IDS 2017** | Sanitized tabular dataset used for training and simulation. |
| **Frontend/Dashboard** | **HTML, CSS, JAVASCRIPT** | Interactive, real-time visualization of the threat log and statistics. |
| **Immutable Logging** | **SHA-256 Hashing** | Cryptographic method for chaining security log entries (Blockchain concept). |

---

## 🏗️ Architecture and Solution Flow

The CyberSecure solution is built around a robust, two-part system: the **Data Entry Point** and the **Common Prediction Pipeline**.

### 1. Data Entry Point

Data enters the system via one of two modes:

* **📤 Batch Upload:** Users upload a CSV/TXT file. The backend parses rows, and each row is fed sequentially into the pipeline.
* **📡 Simulated Real-Time Feed:** A script continuously streams network flow records to the `/predict` FastAPI endpoint, mimicking a live sensor environment.

### 2. The Common Prediction Pipeline

Once a network flow record is received, it passes through the following stages:

#### **A. Preprocessing Layer**
* **Validation:** Handle missing values.
* **Encoding:** Convert categorical features (like protocol or flag) into numerical formats.
* **Scaling:** Normalize features to prepare the vector for the ML model.

#### **B. Random Forest Classification (The ML Model)**
The model receives the cleaned feature vector and performs a **binary classification (Benign/Intrusion)**, often alongside a finer multi-class prediction (DoS, Probe, R2L, etc.). It outputs the classification label and a **confidence score**.

#### **C. Security Mapping Engine (Triage Logic)**
If the prediction is **Intrusion**, a rule-based engine maps the attack type to a suggested, actionable response:
* *Example:* DoS $\rightarrow$ **"Block Source IP"**
* *Example:* R2L $\rightarrow$ **"Quarantine Endpoint"**

#### **D. Log Generation Module**
A detailed entry is created containing the **Timestamp, Prediction, Attack Type, Confidence Score**, and the **Suggested Action**. This log feeds both the frontend display and the blockchain layer.



---

## 📊 Output & Visualization

### 1. Visualization Layer (Frontend Dashboard)
The log data is rendered on an interactive dashboard using JavaScript libraries.

* **Real-Time Feed:** Mimics a live SOC monitor, displaying the latest detected intrusions and their actions.
* **Statistical Charts:** Displays attack frequency, attack type distribution (Pie Charts), and intrusion trends over time (Time-Series Graphs).

### 2. 🔗 Blockchain Logging Layer (Immutable Audit Trail)

This critical bonus feature ensures security log integrity. **Only intrusion records** are logged here.

1.  The intrusion log entry is converted into a JSON string.
2.  The JSON string is hashed using **SHA-256**.
3.  The new hash is chained to the previous block's hash, forming an immutable ledger.

**Benefits:** This creates a **tamper-proof audit trail** and a verifiable source for forensics.


---

## ⭐ Evaluation & Performance

The success of **CyberSecure** is defined by its ability to prevent missed attacks. Therefore, the primary focus is on maximizing **Recall ($\text{Sensitivity}$)**:

$$\text{Recall} = \frac{\text{True Positives}}{\text{True Positives} + \text{False Negatives}}$$

* **Goal:** Achieve a high **True Positive Rate** while minimizing **False Negatives (Missed Attacks)**.
* **Secondary Metrics:** Maintain high **Accuracy** and **F1-score**.

---

## 🔮 Future Scope & Enhancements

* **Explainable AI (XAI) with SHAP:** Integrate **SHAP (SHapley Additive exPlanations)** to provide feature importance, showing *why* the model made a decision (e.g., "The high duration and low packet count were critical in flagging this as an R2L intrusion").
* **Interactive Chatbot:** Develop a natural language interface to allow SOC analysts to query the intrusion log and analytics dashboard efficiently.
