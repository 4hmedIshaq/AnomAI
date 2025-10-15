"""
Handles LLM analysis for SOC log detections.
Supports both OpenRouter (cloud) and Local LLaMA models.
"""

import os
import json
import requests
from llama_cpp import Llama


# ============================================================
# OpenRouter (Cloud API) Version
# ============================================================

def run_openrouter_analysis(prompt, api_key=None, model="gpt-4o-mini", temperature=0.5, max_tokens=800):
    """
    Sends a prompt to the OpenRouter API and handles all response cases safely.
    """
    api_key = api_key or os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return "Error: OpenRouter API key not found. Set OPENROUTER_API_KEY in .env or pass it as an argument."

    if not model:
        model = "gpt-4o-mini"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a senior SOC analyst reviewing SIEM data."},
            {"role": "user", "content": prompt}
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    try:
        res = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=data)
    except Exception as e:
        return f"Error: Request to OpenRouter failed - {str(e)}"

    # Ensure res is a valid JSON dict
    if isinstance(res, dict):
        response = res
    else:
        try:
            response = res.json()
        except Exception:
            return f"Error: Could not parse JSON. Raw response: {getattr(res, 'text', str(res))}"

    # Handle API error responses
    if "error" in response:
        err = response["error"]
        return f"OpenRouter error: {err.get('message', err)}"

    if "choices" not in response:
        return f"Unexpected response format:\n{json.dumps(response, indent=2)}"

    return response["choices"][0]["message"]["content"]



# Local LLaMA Version (Offline Inference)

def run_local_llama(prompt, model_path, temperature=0.5, max_tokens=700):
    """
    Runs the same prompt using a local LLaMA model via llama.cpp.
    Works offline and uses GPU acceleration if available.
    """
    if not model_path or not os.path.exists(model_path):
        return f"Error: Local model not found at path: {model_path}"

    llm = Llama(
        model_path=model_path,
        n_ctx=4096,
        n_threads=12,
        n_gpu_layers=42,
        n_batch=512
    )

    response = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": "You are a senior SOC analyst reviewing SIEM data."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=max_tokens,
        temperature=temperature
    )

    return response["choices"][0]["message"]["content"]


# ============================================================
# Unified Interface with Fallback Logic
# ============================================================

def analyze_logs(prompt, mode="openrouter", **kwargs):
    """
    Unified interface for LLM analysis.
    - mode='openrouter' → uses OpenRouter API
    - mode='local' → uses local LLaMA model
    Includes hybrid fallback if one method fails.
    """
    try:
        if mode == "openrouter":
            print("---- Using OpenRouter mode...")
            result = run_openrouter_analysis(
                prompt=prompt,
                api_key=kwargs.get("api_key"),
                model=kwargs.get("model", "gpt-4o-mini"),
                temperature=kwargs.get("temperature", 0.5),
                max_tokens=kwargs.get("max_tokens", 800)
            )
            # fallback to local if OpenRouter fails
            if "Error" in str(result) and kwargs.get("model_path"):
                print(" OpenRouter failed, switching to local model...")
                return run_local_llama(
                    prompt=prompt,
                    model_path=kwargs.get("model_path"),
                    temperature=kwargs.get("temperature", 0.5),
                    max_tokens=kwargs.get("max_tokens", 700)
                )
            return result

        elif mode == "local":
            print("---- Using Local LLaMA mode...")
            result = run_local_llama(
                prompt=prompt,
                model_path=kwargs.get("model_path"),
                temperature=kwargs.get("temperature", 0.5),
                max_tokens=kwargs.get("max_tokens", 700)
            )
            # fallback to OpenRouter if local model fails
            if "Error" in str(result) and os.getenv("OPENROUTER_API_KEY"):
                print(" Local model missing, switching to OpenRouter...")
                return run_openrouter_analysis(
                    prompt=prompt,
                    api_key=kwargs.get("api_key"),
                    model=kwargs.get("model", "gpt-4o-mini"),
                    temperature=kwargs.get("temperature", 0.5),
                    max_tokens=kwargs.get("max_tokens", 800)
                )
            return result

        else:
            return "Invalid mode. Choose 'openrouter' or 'local'."

    except Exception as e:
        return f"Unhandled error: {str(e)}"