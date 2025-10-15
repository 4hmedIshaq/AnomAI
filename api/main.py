# a helper to ensure src folder is visible to python and ensure api key is attached
import sys, os
from dotenv import load_dotenv
load_dotenv()
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, Query
import duckdb
from src.security_rules_build import combined_rules, build_llm_context
from src.llm_handler import analyze_logs





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
    mode: str = Query("openrouter", description="Select LLM mode: openrouter or local"),
    temperature: float = Query(0.5),
    max_tokens: int = Query(700),
):
    """Run detections and analyze them with the chosen LLM mode."""
    con = get_connection()
    results = combined_rules(con)
    context_summary = build_llm_context(results)
    
    prompt = f"""
You are a SOC (Security Operations Center) analyst.
Analyze the following SIEM detections and describe:
1. What these detections indicate
2. The potential threats or attack patterns
3. Recommended mitigation steps

Here are the detections:
{context_summary}
"""
    # Call either local or OpenRouter model
    response = analyze_logs(
        prompt,
        mode=mode,
        model_path="C:/Users/Ishaq/.cache/huggingface/hub/models--TheBloke--Llama-2-13B-chat-GGUF/snapshots/4458acc949de0a9914c3eab623904d4fe999050a/llama-2-13b-chat.Q5_K_M.gguf",
        temperature=temperature,
        max_tokens=max_tokens
    )
    return {"analysis": response}