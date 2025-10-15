from dotenv import load_dotenv
from fastapi import FastAPI, Query, Body
import sys, os
import duckdb
from src.security_rules_build import combined_rules, build_llm_context
from src.llm_handler import analyze_logs

# a helper to ensure src folder is visible to python and ensure api key is attached
load_dotenv()
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

#print("Loaded Local Model Path:", os.getenv("LOCAL_LLAMA_PATH"))
#print("Loaded OpenRouter API Key:", os.getenv("OPENROUTER_API_KEY"))


app = FastAPI(title="AnomAI API")

# === Database connection ===
def get_connection():
    return duckdb.connect("data/logs.duckdb")

# === Routes ===

@app.get("/")
def root():
    return {"message": " AnomAI API is running."}


@app.get("/run_rules")
def run_all_rules():
    """Run all security rules and return a summary context."""
    con = get_connection()
    results = combined_rules(con)
    context_summary = build_llm_context(results)
    return {"summary": context_summary}


@app.post("/analyze")
def analyze(
    mode: str = Query("openrouter", description="LLM mode: openrouter or local"),
    context_mode: str = Query("rules", description="Choose context: 'rules' or 'dataset'"),
    temperature: float = Query(0.5),
    max_tokens: int = Query(700),
    user_prompt: dict = Body(..., description="Natural language query or instruction"),
):
    
    
    prompt_text = user_prompt.get("user_prompt", "")
    con = get_connection()
    results = combined_rules(con)

    # === Select context ===
    if context_mode == "rules":
        context_data = build_llm_context(results)
    else:
        total_rows = con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        columns = con.execute("PRAGMA table_info('logs')").fetchall()
        col_names = [col[1] for col in columns]
        context_data = f"The dataset contains {total_rows} records with columns: {', '.join(col_names)}."

    # === Build final prompt ===
    prompt = f"""
You are a SOC (Security Operations Center) analyst.
Analyze the following SIEM detections and describe:
1. What these detections indicate
2. The potential threats or attack patterns
3. Recommended mitigation steps

--Context ({context_mode.upper()})--
{context_data}

-- User Query --
{prompt_text}

Provide a concise analysis with data, identify possible threats or anomalies, 
and recommend mitigation steps if applicable while answering user query. 
"""

    # === Run selected LLM mode ===
    response = analyze_logs(
        prompt,
        mode=mode,
        api_key=os.getenv("OPENROUTER_API_KEY"),
        model_path=os.getenv("LOCAL_LLAMA_PATH"),
        temperature=temperature,
        max_tokens=max_tokens
    )
    return {"analysis": response}