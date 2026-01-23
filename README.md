# AnomAI — AI-Assisted Security Log Analysis & Threat Detection

AnomAI is a mini Security Operations Center (SOC) analytics system that combines rule-based security detections with Large Language Model (LLM) reasoning to analyze system logs, detect suspicious behavior, and generate human-readable security insights.

The project simulates how modern SOCs blend traditional SIEM rules with AI-assisted analysis, using open-source tools and local data.
---

## Key Features

- Rule-based security detections (failed logins, brute force, privilege escalation, etc.)
- Centralized log storage using DuckDB
- AI-powered explanations using LLMs (Local LLaMA or OpenRouter)
- Notebook-based analysis and API-based access
- Modular and extensible architecture

---

## How It Works

![Architecture Diagram](./images/architecture.png)

1. **Log Ingestion**
   - Raw security logs are loaded and stored in DuckDB
2. **Rule-Based Detection**
   - SQL-based security rules analyze logs
3. **Detection Aggregation**
   - Findings are summarized
4. **AI Reasoning Layer**
   - LLM generates analyst-style explanations
5. **Output**
   - Results viewed via notebooks or API

---

## Project Structure

```text
AnomAI/
├── api/                # FastAPI backend and UI
├── src/
│   ├── security_rules.py
│   ├── preprocess.py
│   └── llm_handler.py
├── notebooks/          # Analysis notebooks
├── data/               # DuckDB database
└── README.md
```
---

##  Security Rules Implemented

All rules are implemented in **`src/security_rules.py`** as reusable functions.

### Included Detections

- ❌ Failed login attempts
- 🔁 Brute-force attacks
- 🔐 Privilege escalation
- 🔒 Account lockouts
- 🧹 Log clearing / tampering
- ⚙️ Suspicious process execution
- 🌐 RDP login activity
- 🔑 SSH root logins

Each rule:
- Uses SQL queries on DuckDB
- Returns pandas DataFrames
- Can be reused by notebooks, APIs, or automation

---

## AI-Powered Analysis

AnomAI uses an **LLM reasoning layer** to convert raw detections into **SOC analyst-style explanations**.

### What the AI Does

- Summarizes detected security events
- Explains why activity is suspicious
- Identifies attack patterns
- Suggests investigation steps

![LLM Output](./images/LLM_Output.png)

### Supported LLM Options

- **Local LLaMA (llama-cpp)** — fully offline
- **OpenRouter models** — fast inference, free-tier support

> The LLM is used only for **analysis and explanation**, not training.

---

##  Running the Analysis (Notebook)

1. Install dependencies:
```bash
pip install -r requirements.txt
```
```jupyter notebook
Run notebooks:
analysis.ipynb → security rules
llm_analysis.ipynb → AI explanations
```

Running the API (Optional)

Start the backend API:
```
uvicorn api.api:app --reload --port 8001
```

Open:

http://127.0.0.1:8001/docs for Swagger UI

---

**Technologies Used**
- Python
- DuckDB
- pandas
- SQL
- FastAPI
- Jupyter Notebook
- llama-cpp-python
- OpenRouter API
- Hugging Face Hub

## Project Ownership

| Contributor | Responsibilities |
|------------|------------------|
| [**Ishaq Ahmed**](https://github.com/4ahmedIshaq) | Architecture, LLM integration, API design | 
| [**Evan Mcnaughton**](https://github.com/Evan7252) | Data ingestion, detection rules, evaluation |

---
## **Disclaimer**

This project is for educational and research purposes only.
Not intended for production SOC environments.

Logs Source from Kaggle: [CAC_DA_SIEM_UEBA_ba_V2](https://www.kaggle.com/datasets/teddylegessemunea/cac-da-siem-ueba-ba-v2)

