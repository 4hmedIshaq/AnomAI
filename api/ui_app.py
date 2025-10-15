import gradio as gr
import requests
import time

API_URL = "http://127.0.0.1:8000/analyze"

def query_backend(prompt, mode, context_mode, temperature, max_tokens):
    start = time.time()
    params = {
        "mode": mode,
        "context_mode": context_mode,
        "temperature": temperature,
        "max_tokens": max_tokens
    }
    res = requests.post(API_URL, params=params, json={"user_prompt": prompt})
    end = time.time()
    
    if res.status_code != 200:
        return f"---- Error: {res.text}"
    result = res.json()
    analysis = result.get("analysis", "No response received.")
    context_info = (
        f"\n\n---\n**Context Source:** {context_mode}\n"
        f"**Model Mode:** {mode}\n"
        f"**Temperature:** {temperature}\n"
        f"**Max Tokens:** {max_tokens}\n"
    )
    analysis += f"\n\n---\n⏱ **Completed in {round(end - start, 2)} seconds.**"
    return analysis + context_info



iface = gr.Interface(
    fn=query_backend,
    inputs=[
        gr.Textbox(
            label=" Ask a Question or Write an Analysis Instruction",
            lines=4,
            placeholder="Example: Which IPs show repeated failed login attempts?"
        ),
        gr.Radio(["openrouter", "local"], label="Model Mode", value="openrouter"),
        gr.Radio(["rules", "dataset"], label="Context Source", value="rules"),
        gr.Slider(0.0, 1.0, value=0.5, step=0.1, label="Temperature (Creativity)"),
        gr.Slider(100, 1500, value=700, step=50, label="Max Tokens (Response Length)")
    ],
    outputs=gr.Markdown(label="Model Analysis Output"),
    title="AnomAI SOC Assistant",
    description="Query detections or datasets using either OpenRouter or Local LLaMA for security log analysis. Adjust parameters for finer control.",
    theme="gradio/soft",
    show_progress="full"
)

iface.launch()