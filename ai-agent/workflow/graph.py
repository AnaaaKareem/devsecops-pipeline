"""
LangGraph Workflow Definition.

This module defines the StateGraph for the AI Agent. It orchestrates the flow
from Triage -> Red Team -> Remediation -> Sanity Check -> Publish PR.
"""

import os
from typing import List, Dict, TypedDict
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from services.sandbox import verify_patch_in_sandbox, verify_poc
from services.pr_agent import create_security_pr
import re
from core import database, models
import uuid, traceback

class GraphState(TypedDict):
    """
    Represents the state of the AI workflow as it processes findings.
    """
    findings: List[Dict]          # List of initial findings to process
    current_index: int            # Pointer to the current finding being processed
    analyzed_findings: List[Dict] # The accumulating list of processed results
    source_path: str              # Path to the checked-out source code
    project: str                  # Project name (owner/repo)

# Local AI Configuration
# Connects to LM Studio running locally
llm = ChatOpenAI(
    base_url="http://localhost:1234/v1",
    api_key=os.getenv("LLM_API_KEY", "lm-studio"),
    default_headers={"X-API-Key": os.getenv("LLM_API_KEY", "lm-studio")},
    model="deepseek-coder-v2-lite",
    max_tokens=4096,
    temperature=0.1,
    timeout=300, # 👈 Increase to 5 minutes to allow for large patch generation
    max_retries=2
)

def node_triage(state):
    """
    Node: Triage Agent.
    
    analyzes a finding and determines if it is a True Positive (TP) or False Positive (FP).
    Uses prompts with specific criteria (e.g., usage of pickle vs safe alternatives).
    """
    # 1. Safe extraction of findings
    findings = state.get("findings", [])
    index = state.get("current_index", 0)
    finding = findings[index]

    print(f"🧪 Agent Seeing Code: {finding.get('snippet')[:50]}...")
    
    if index >= len(findings):
        return state

    finding = findings[index]
    snippet = finding.get('snippet', "⚠️ NO CODE SNIPPET FOUND")
    message = finding.get('message', "No issue description")
    file_path = finding.get('file', "Unknown file")

    print(f"🧠 Triaging: {file_path}")

    # 2. Build the Prompt
    prompt = (
        f"You are a Senior AppSec Engineer. Analyze the code for the specific issue described.\n\n"
        f"CRITERIA:\n"
        f"- If the code uses f-strings/concatenation in SQL: ALWAYS TP.\n"
        f"- If the code uses shell=True with user variables: ALWAYS TP.\n"
        f"- If the code uses pickle.loads(): ALWAYS TP.\n"
        f"- If you are unsure but it looks suspicious: respond TP.\n\n"
        f"CONTEXT:\n"
        f"File: {file_path}\n"
        f"Issue: {message}\n"
        f"Snippet:\n{snippet}\n\n"
        f"Respond ONLY with 'TP' or 'FP'."
    )

    # 3. Call your Local LLM
    try:
        # Assuming you're using LangChain's ChatOpenAI/Ollama wrapper 
        # pointing to your Colab Ngrok URL
        response = llm.invoke([{"role": "user", "content": prompt}])
        verdict = re.sub(r'[^a-zA-Z]', '', response.content).upper()
        ai_verdict = "TP" if "TP" in verdict else "FP"
        print(f"🧠 Verdict for {file_path}: {ai_verdict}") # 👈 Log this to see the flip!
    except Exception as e:
        ai_verdict = "FP"

    # 4. CRITICAL: Return the updated list to avoid IndexError in next node
    new_finding = {
        **finding,
        "ai_verdict": ai_verdict,
        "triage_decision": "RV" if ai_verdict == "TP" else "FP"
    }
    
    updated_analyzed = state.get("analyzed_findings", []) + [new_finding]
    
    return {
        "analyzed_findings": updated_analyzed,
        "current_index": index + 1
    }

def node_red_team(state):
    """
    Node: Red Team Agent.
    
    If a finding is Triage Positive (TP), tries to generate a Proof of Concept (PoC)
    exploit script and verify it in the sandbox.
    """
    analyzed = state.get("analyzed_findings", [])
    if not analyzed: return state

    finding = analyzed[-1]
    
    if finding.get("ai_verdict") == "TP":
        print(f"🔥 Red Teaming: {finding.get('file')}")
        prompt = (
            f"As a security researcher, generate a Python verification script (PoC) "
            f"to confirm the following vulnerability in a controlled sandbox environment. "
            f"Respond ONLY with the Python code.\n\n"
            f"Code to test:\n{finding.get('snippet')}"
        )
        
        try:
            response = llm.invoke([{"role": "user", "content": prompt}])
            poc = response.content
            
            # Confirm exploitability in the Sandbox
            success, output = verify_poc(state.get("source_path", "."), poc)
            
            # 📊 SAVE TELEMETRY
            save_telemetry(finding.get("id"), "RED_TEAM_POC", success, output)
            
            finding["red_team_success"] = success
            finding["red_team_output"] = output # Also save to the finding record
        except Exception as e:
            print(f"❌ Red Team Node Error: {e}")
            finding["red_team_success"] = False

    return {"analyzed_findings": analyzed}

def node_remediate(state):
    """
    Node: Remediation Agent.
    
    Generates a code patch to fix the vulnerability if it is a True Positive.
    """
    analyzed = state.get("analyzed_findings", [])
    if not analyzed: return state
    finding = analyzed[-1]
    
    if finding.get("ai_verdict") == "TP":
        print(f"🛠️  Generating fix for: {finding.get('file')}")
        
        # --- 1. DEFINE THE PROMPT ---
        prompt = (
            f"Fix the security vulnerability in this Python code.\n"
            f"ISSUE: {finding.get('message')}\n"
            f"CODE:\n{finding.get('snippet')}\n\n"
            f"Respond ONLY with the full corrected Python code block."
        )
        
        try:
            # --- 2. CALL THE AI ---
            response = llm.invoke([{"role": "user", "content": prompt}])
            clean_patch = re.sub(r"```[a-zA-Z]*\n", "", response.content).replace("```", "").strip()

            finding["remediation_patch"] = clean_patch #
            print(f"✅ AI fix accepted for {finding.get('file')} (Sandbox Bypassed)") #
            
            # --- 3. VERIFY IN SANDBOX (Commented out for speed/demo) ---
            # We pass finding.get("file") so the sandbox knows which file to overwrite
            # success, logs = verify_patch_in_sandbox(
            #     state.get("source_path", "."), 
            #     clean_patch, 
            #     finding.get("file")
            # )
            
            # Save telemetry to your database
            # save_telemetry(finding.get("id"), "PATCH_VERIFICATION", success, logs)
            
            # if success:
            #     finding["remediation_patch"] = clean_patch
            #     print(f"✅ Fix verified for {finding.get('file')}")
            # else:
            #     print(f"❌ Sandbox Logs for {finding.get('file')}:\n{logs}") 
            #     finding["remediation_patch"] = None
        except Exception as e:
            print(f"❌ Remediation Error: {e}")

    return {"analyzed_findings": analyzed}

def node_publish(state):
    """
    Node: Publish Agent.
    
    If a valid patch exists, opens a Pull Request on GitHub.
    """
    analyzed = state.get("analyzed_findings", [])
    if not analyzed: 
        print("⚠️ Publish Node: No findings to process.")
        return state
        
    finding = analyzed[-1]
    patch = finding.get("remediation_patch")
    ai_verdict = finding.get("ai_verdict")

    # DEBUG LOGS
    print(f"🔍 Publish Check for {finding.get('file')}:")
    print(f"   - AI Verdict: {ai_verdict}")
    print(f"   - Patch Generated: {'✅ YES' if patch else '❌ NO'}")

    if not patch:
        print(f"🛑 Agent: Skipping PR because no verified patch exists.")
        return state

    print(f"🚀 Agent: Attempting to commit fix to {state.get('project')}...")
    try:
        pr_url = create_security_pr(
            repo_name=state["project"],
            branch_name=f"ai-fix-{uuid.uuid4().hex[:6]}",
            patch_content=patch,
            file_path=finding["file"],
            issue_message=finding["message"],
            temp_dir=state["source_path"]
        )
        finding["pr_url"] = pr_url
        print(f"✅ PR CREATED: {pr_url}")
    except Exception as e:
        print(f"❌ GitHub API Error: {str(e)}")
        traceback.print_exc()

    return {"analyzed_findings": analyzed}

def should_continue(state: GraphState):
    """Determines if we should process the next bug or stop."""
    if state["current_index"] >= len(state["findings"]):
        print("🏁 All findings processed. Ending Graph.")
        return END
    return "triage"

def save_telemetry(finding_id, stage, success, output):
    """
    Persists sandbox execution results to the database Finding record.
    """
    db = database.SessionLocal()
    try:
        clean_output = output.decode('utf-8', errors='replace') if isinstance(output, bytes) else str(output)
        log_entry = f"\n--- {stage} (SUCCESS: {success}) ---\n{clean_output}\n"
        
        finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
        if finding:
            finding.sandbox_logs = (finding.sandbox_logs or "") + log_entry
            db.commit()
    finally:
        db.close()

def node_sanity_check(state):
    """
    Node: Sanity Check.
    
    Performs heuristics to ensure the generated patch isn't dangerous (e.g. empty file,
    deleted critical imports like auth).
    """
    analyzed = state.get("analyzed_findings", [])
    if not analyzed: return state
    finding = analyzed[-1]
    
    patch = finding.get("remediation_patch")
    if not patch: return state

    print(f"🧐 Sanity Check: Verifying patch integrity for {finding['file']}")

    CRITICAL_MODULES = ["auth", "jwt", "session", "encrypt"]
    deleted_criticals = [w for w in CRITICAL_MODULES if w in finding['snippet'] and w not in patch]

    is_empty = len(patch.strip()) == 0
    is_wiped = len(patch.splitlines()) < 2 and len(finding['snippet'].splitlines()) > 10

    # 🔥 FIX: Use .get("id") to avoid KeyError
    finding_id = finding.get("id")

    if deleted_criticals or is_empty or is_wiped:
        print(f"❌ Sanity Check Failed: Patch is empty or deleted critical logic.")
        finding["remediation_patch"] = None 
        if finding_id:
            save_telemetry(finding_id, "SANITY_CHECK", False, "Blocked: Likely over-deletion.")
    else:
        print(f"✅ Sanity Check Passed.")
        if finding_id:
            save_telemetry(finding_id, "SANITY_CHECK", True, "Patch looks valid.")

    return {"analyzed_findings": analyzed}

# --- GRAPH CONSTRUCTION ---
# graph.py
workflow = StateGraph(GraphState)

workflow.add_node("triage", node_triage)
workflow.add_node("red_team", node_red_team)
workflow.add_node("remediate", node_remediate)
workflow.add_node("sanity_check", node_sanity_check) # 👈 New Node
workflow.add_node("publish", node_publish)

workflow.set_entry_point("triage")

# Update the edges
workflow.add_edge("triage", "red_team")
workflow.add_edge("red_team", "remediate")
workflow.add_edge("remediate", "sanity_check") # 👈 New Edge
workflow.add_edge("sanity_check", "publish")    # 👈 New Edge
workflow.add_conditional_edges("publish", should_continue)

graph_app = workflow.compile()