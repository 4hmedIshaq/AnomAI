import gradio as gr
import requests

API_URL = "http://127.0.0.1:8000/analyze"

def query_backend(prompt, mode, context_mode, temperature, max_tokens):
    params = {
        "mode": mode,
        "context_mode": context_mode,
        "temperature": temperature,
        "max_tokens": max_tokens
    }
    res = requests.post(API_URL, params=params, json={"user_prompt": prompt})
    if res.status_code != 200:
        return f" ---- Error: {res.text}", ""
    result = res.json()
    analysis = result.get("analysis", "No response received.")
    context = (
        f"**Context Source:** {context_mode}\n\n"
        f"**Model Mode:** {mode}\n\n"
        f"**Temperature:** {temperature}\n"
        f"**Max Tokens:** {max_tokens}\n\n"
        f"*(For reference, this analysis was based on {context_mode} data.)*"
    )
    return analysis, context

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
    outputs=[
        gr.Markdown(label="Model Analysis Output"),
        gr.Markdown(label="Context Information")
    ],
    title="AnomAI SOC Intelligence Assistant",
    description="Query detections or datasets using either OpenRouter or Local LLaMA for security log analysis. Adjust parameters for finer control.",
    theme="gradio/soft"
)

iface.launch()