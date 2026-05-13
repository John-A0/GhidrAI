# ☣️ GhidrAI: Hybrid AI-Assisted Malware Reverse Engineering Pipeline

[![Ghidra](https://img.shields.io/badge/Ghidra-11.x-red.svg)](https://ghidra-sre.org/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-blue.svg)](https://ollama.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**GhidrAI** is a state-of-the-art, dual-stage pipeline designed to bridge the gap between deterministic static analysis and Large Language Model (LLM) intelligence. It acts as an AI co-pilot inside Ghidra, specifically architected to eliminate "LLM Hallucinations" and provide actionable threat intelligence, execution flow mapping, and automated YARA rule generation.

## 🧠 The Philosophy: Solving the "Yes-Man" Problem
Most AI security tools fail because they blindly feed raw code to an LLM, resulting in high false positives (hallucinations) and resource exhaustion. GhidrAI introduces a **Deterministic Triage Stage (Stage 1)**. 

If a file (e.g., `calc.exe`) passes the initial static analysis and VirusTotal checks without raising alarms, the pipeline **halts immediately**, completely bypassing the AI. The LLM is only invoked for confirmed or highly suspicious payloads (including Zero-Days caught via Entropy analysis), treating the AI not as a blind scanner, but as a **Context-Aware Interrogator**.

## ✨ Key Features

1. **Anti-Hallucination Architecture (Dual-Stage)**:
   - **Stage 1 (Triage):** Deterministic evaluation using VirusTotal API, PE Import Table (IAT) scanning, and Section Entropy calculations (Zero-Day packing detection).
   - **Stage 2 (Deep AI):** Only malicious/suspicious functions are decompiled, optionally deobfuscated, and sent to the LLM alongside the Stage 1 context.

2. **Automated Kill-Chain Mapping**:
   Generates a visual `Graphviz` threat map highlighting suspicious functions, categorized by severity (High/Medium/Low) and mapped to MITRE ATT&CK framework IDs.

3. **Thread-Safe Threat Memory (SQLite)**:
   Maintains a local SQLite database of analyzed threats. Automatically clusters new malware samples with historical data to identify threat actor groups or malware families based on shared MITRE techniques.

4. **Context-Aware "Chat with Malware"**:
   An interactive chat interface injected with the malware's decompiled context, allowing analysts to interrogate the AI about specific payload behaviors, network ports, or encryption routines without leaving the dashboard.

5. **Automated YARA Generation**:
   Forces the LLM to generate actionable, syntax-safe YARA rules based on the specific APIs and strings found within malicious functions.

## 🏗️ Project Architecture (Modular Core)

```text
GhidrAI/
├── core/                        
│   ├── __init__.py              
│   ├── static_triage.py         # Deterministic checks, Entropy, PE Analysis
│   ├── llm_engine.py            # Local Ollama integration & JSON Regex cleaning
│   └── memory_store.py          # SQLite-based historical clustering
├── app.py                       # Main Streamlit UI & Ghidra-Bridge Orchestrator
├── requirements.txt             # Python dependencies
├── threat_memory.db             # Auto-generated SQLite database
└── README.md
```

## 🚀 Installation & Setup

### Prerequisites
- [Ghidra](https://ghidra-sre.org/) (Version 11.0+)
- Python 3.10+
- [Ollama](https://ollama.com/) (Running locally)
- [Graphviz](https://graphviz.org/download/) (Added to System PATH)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Prepare Local LLM
Ensure Ollama is running and pull your preferred coding model (CodeLlama is highly recommended for C-decompilation analysis):
```bash
ollama run codellama:13b
```

### 3. Launch Ghidra-Bridge
Open your malware sample in Ghidra, open the Python Script manager, and run the `ghidra_bridge` server script inside Ghidra.

### 4. Execute GhidrAI
Open your terminal in the project directory and run:
```bash
streamlit run app.py
```

## ⚙️ Configuration
In the Streamlit Sidebar, you can configure:
- **VirusTotal API Key**: Optional, but highly recommended for robust Stage-1 triage.
- **Enable De-obfuscation**: Pre-processes the Ghidra C-code through the LLM to rename variables before deep analysis (Adds time but increases accuracy).
- **Local File Path (Fallback)**: Essential if Ghidra's bridge fails to provide an absolute path to the local OS.

## 🤝 Contributing
Contributions are welcome! If you want to integrate new LLM providers (e.g., OpenAI, Anthropic), enhance the smart-function filtering algorithm, or build a native Ghidra Java Plugin version, please submit a PR.

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

---
*Developed for the Open-Source Security Community.*
