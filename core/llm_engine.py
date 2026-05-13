import json
import re
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "codellama:13b"

def clean_json_response(response_text):
    try:
        match = re.search(r'(\{.*\}|\[.*\])', response_text, re.DOTALL)
        if match:
            clean_text = match.group(1)
            return json.loads(clean_text)
        else:
            return json.loads(response_text)
    except Exception:
        return None

def ask_ollama(prompt, temperature=0.0):
    payload = {
        "model": MODEL_NAME, 
        "prompt": prompt, 
        "format": "json", 
        "stream": False,
        "options": {"temperature": temperature, "seed": 1337}
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=240)
        raw_text = response.json().get('response', '{}')
        return clean_json_response(raw_text)
    except Exception: 
        return None

def deobfuscate_code(code):
    prompt = f"De-obfuscate this C code. Return JSON: {{\"clean_code\": \"code\"}}\nCode: {code}"
    res = ask_ollama(prompt, temperature=0.2)
    return res.get("clean_code", code) if isinstance(res, dict) else code

def ask_ollama_strict_analysis(func_name, code, apis, triage_report):
    prompt = f"""
    You are a Strict Malware Reverse Engineer. 
    
    [PREVIOUS INTELLIGENCE]
    File flagged as Malware with {triage_report.get('confidence_score', 0)}% confidence.
    Traits: {triage_report.get('detected_features', 'N/A')}
    Conclusion: {triage_report.get('conclusion', 'N/A')}
    
    [YOUR TASK]
    Analyze this specific function knowing the overall file is malicious.
    
    Function: {func_name}
    APIs: {apis}
    Code: {code}
    
    Return ONLY JSON:
    {{
        "intent": "Strict technical description of behavior",
        "severity": "low/medium/high",
        "mitre_id": "MITRE ID like T1055 or N/A",
        "yara_rule": "MANDATORY: Write a YARA rule for these APIs. Use single quotes (') for strings to avoid JSON escape errors. Use \\n for newlines."
    }}
    """
    return ask_ollama(prompt)

def ask_ollama_summary(analysis_results, triage_report):
    simplified = [{"function": r['name'], "behavior": r['intent'], "severity": r.get('severity')} for r in analysis_results]
    prompt = f"""
    Review this malware analysis.
    Initial Confidence: {triage_report.get('confidence_score', 0)}%
    Behaviors: {json.dumps(simplified)}
    
    Return ONLY JSON:
    {{
        "overall_purpose": "2 sentences explaining the payload goal",
        "execution_flow": "Step-by-step kill-chain description"
    }}
    """
    return ask_ollama(prompt)

def chat_with_malware(question, context):
    prompt = f"""
    You are an AI assistant helping a malware analyst. Answer their question based ONLY on this context.
    Context: {json.dumps(context)}
    Question: {question}
    Return ONLY a JSON object: {{"answer": "Your detailed answer here"}}
    """
    res = ask_ollama(prompt, temperature=0.5)
    return res.get("answer", "I could not analyze that specific detail.") if isinstance(res, dict) else "Error generating response."