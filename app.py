import streamlit as st
import ghidra_bridge
import os
from graphviz import Digraph

from core.memory_store import init_db, update_threat_memory, find_clusters
from core.static_triage import run_initial_triage
from core.llm_engine import deobfuscate_code, ask_ollama_strict_analysis, ask_ollama_summary, chat_with_malware

os.environ["PATH"] += os.pathsep + r'C:\Program Files\Graphviz\bin'

st.set_page_config(page_title="GhidrAI: Enterprise PoC", layout="wide", page_icon="☣️")

init_db()

if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
    st.session_state.results = []
    st.session_state.summary = {}
    st.session_state.chat_history = []
    st.session_state.dot_graph = None
    st.session_state.target_name = "Unknown_Sample"
    st.session_state.triage_report = {}

st.title("☣️ GhidrAI: Hybrid Pipeline")
st.markdown("---")

st.sidebar.header("⚙️ Configuration")
vt_key = st.sidebar.text_input("VirusTotal API Key (Optional)", type="password")
enable_deobf = st.sidebar.checkbox("🛡️ Enable De-obfuscation")
manual_path = st.sidebar.text_input("Local File Path (Fallback)", help="E.g., C:\\Malware\\sample.exe")

if st.button("🚀 Execute Hybrid Pipeline", type="primary"):
    with st.status("Initializing Systems...", expanded=True) as status:
        try:
            st.write("🔌 Connecting to Ghidra Bridge...")
            try:
                bridge = ghidra_bridge.GhidraBridge(namespace=globals())
                fm = currentProgram.getFunctionManager()
                decomp = ghidra.app.decompiler.DecompInterface()
                decomp.openProgram(currentProgram)
                
                target_path = manual_path if manual_path else str(currentProgram.getExecutablePath())
                target_name = str(currentProgram.getName())
            except Exception:
                st.error("Ghidra Bridge Connection Failed! Please ensure the python script is running INSIDE Ghidra.")
                st.stop()
                
            st.session_state.target_name = target_name
            
            st.write(f"🔬 **Stage 1: Triage on `{target_name}`...**")
            triage_report = run_initial_triage(target_path, vt_key)
            st.session_state.triage_report = triage_report
            
            if not triage_report.get('is_malware'):
                st.success(f"🟢 {triage_report.get('conclusion')}")
                status.update(label="Pipeline Stopped (Benign)", state="complete")
                st.session_state.analyzed = False
                st.stop()

            st.write("🧠 **Stage 2: Deep Contextual AI Analysis...**")
            dot = Digraph(comment='Threat Map', format='png')
            dot.attr(bgcolor='#1e1e1e', fontcolor='white', rankdir='LR')
            
            results = []
            suspicious_apis = ["CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "GetVersion", "CreateProcess", "OpenProcess", "WSAStartup"]

            funcs = list(fm.getFunctions(True))
            p_bar = st.progress(0)
            
            for idx, func in enumerate(funcs):
                name = str(func.getName())
                try:
                    called_apis = [str(cf.getName()) for cf in func.getCalledFunctions(monitor)]
                except Exception: 
                    called_apis = []
                
                if any(api.lower() in str(called_apis).lower() for api in suspicious_apis) or any(x in name.lower() for x in ["entry", "main", "start"]):
                    st.write(f"   🔍 Analyzing: **{name}**")
                    
                    res = decomp.decompileFunction(func, 60, monitor) 
                    
                    if res and res.decompileCompleted():
                        raw_code = str(res.getDecompiledFunction().getC())
                        
                        if len(raw_code) > 2500:
                            raw_code = raw_code[:2500] + "\n\n/* [CODE TRUNCATED: FUNCTION TOO LARGE] */"
                            
                        final_code = deobfuscate_code(raw_code) if enable_deobf else raw_code
                        
                        analysis = ask_ollama_strict_analysis(name, final_code, called_apis, triage_report)
                        if analysis and isinstance(analysis, dict):
                            analysis['name'] = name
                            results.append(analysis)
                            
                            sev = str(analysis.get('severity', 'high')).lower()
                            color = "#ff4c4c" if sev == "high" else "#ffa500" if sev == "medium" else "#ffff00"
                            dot.node(name, f"{name}\n{analysis.get('mitre_id', 'N/A')}", color=color, style='filled', fillcolor='#2d2d2d')
                
                p_bar.progress(min((idx + 1) / max(len(funcs), 1), 1.0))

            st.write("🧩 Compiling Final Report...")
            summary = ask_ollama_summary(results, triage_report)
            if not summary or not isinstance(summary, dict):
                summary = {"overall_purpose": "Analysis complete.", "execution_flow": "Review function details below."}

            all_mitre = [r.get('mitre_id') for r in results if r.get('mitre_id') and str(r.get('mitre_id')).upper() != "N/A"]
            update_threat_memory(target_name, all_mitre, summary.get('overall_purpose', 'Unknown'))

            st.session_state.results = results
            st.session_state.summary = summary
            st.session_state.dot_graph = dot
            st.session_state.analyzed = True
            
            status.update(label="Dual-Stage Pipeline Complete!", state="complete", expanded=False)
            
        except Exception as e:
            st.error(f"Critical System Error: {str(e)}")

# ==========================================
# Show Results
# ==========================================
if st.session_state.analyzed:
    st.error(f"🚨 **Confirmed Threat:** `{st.session_state.target_name}` (Triage Confidence: {st.session_state.triage_report.get('confidence_score')}%)")
    st.warning(f"**Triage Intelligence:** {st.session_state.triage_report.get('conclusion')}")
    st.info(f"**Features Detected:** {st.session_state.triage_report.get('detected_features')}")

    tab1, tab2, tab3, tab4 = st.tabs(["📑 Strict Intel Report", "🕸️ Kill-Chain Map", "🧬 Threat Clustering", "💬 Chat with Malware"])
    
    with tab1:
        st.info(f"**🎯 Ultimate Goal:**\n{st.session_state.summary.get('overall_purpose', '')}")
        st.warning(f"**🔄 Execution Flow:**\n{st.session_state.summary.get('execution_flow', '')}")
        st.markdown("### 📝 Technical Breakdown")
        for item in st.session_state.results:
            with st.expander(f"🔴 {item['name']} - Severity: {str(item.get('severity', '')).upper()}"):
                st.write(f"**Intent:** {item.get('intent', '')}")
                st.code(f"MITRE ID: {item.get('mitre_id', '')}")
                yara = item.get('yara_rule', 'N/A')
                if yara.lower() != 'none':
                    st.code(yara.replace("\\n", "\n"), language='javascript')

    with tab2:
        if st.session_state.dot_graph:
            st.graphviz_chart(st.session_state.dot_graph)

    with tab3:
        st.markdown("### 🧬 Historic Threat Clusters")
        current_mitre = [r.get('mitre_id') for r in st.session_state.results if r.get('mitre_id') and str(r.get('mitre_id')).upper() != "N/A"]
        clusters = find_clusters(current_mitre)
        if clusters:
            for cluster in clusters:
                st.error(f"⚠️ **{cluster['match']}% Match** with historical sample: **{cluster['sample']}**")
                st.write(f"**Shared Techniques:** {', '.join(cluster['shared_mitre'])}")
        else:
            st.success("🟢 No historical matches found. This appears to be a novel threat profile.")

    with tab4:
        st.markdown("### 💬 Interrogate the Context-Aware AI")
        for msg in st.session_state.chat_history:
            with st.chat_message(msg["role"]): st.markdown(msg["content"])
                
        if prompt := st.chat_input("Ask about specific behaviors or APIs..."):
            st.session_state.chat_history.append({"role": "user", "content": prompt})
            with st.chat_message("user"): st.markdown(prompt)
            with st.chat_message("assistant"):
                with st.spinner("Analyzing context..."):
                    context_data = {"triage": st.session_state.triage_report, "summary": st.session_state.summary, "functions": st.session_state.results}
                    answer = chat_with_malware(prompt, context_data)
                    st.markdown(answer)
            st.session_state.chat_history.append({"role": "assistant", "content": answer})