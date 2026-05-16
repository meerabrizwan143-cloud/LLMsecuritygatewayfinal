"""
LLM Security Gateway – Main Application
CSC 262 Lab Final
"""

import time
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# Internal modules
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from app.detectors.rule_detector     import rule_detector
from app.detectors.semantic_detector import semantic_detector
from app.pii.presidio_custom         import analyze_pii, mask_pii
from app.policy.policy_engine        import compute_risk, make_decision
from app.utils.language              import detect_language
from app.utils.logging               import build_response, log_event, generate_id


app = FastAPI(
    title="LLM Security Gateway",
    description="Robust multilingual security gateway for LLM applications",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    prompt: str
    input_id: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """
    Full pipeline:
      Language Detection → Rule Detector → Semantic Detector
      → PII Analyzer → Policy Engine → Audit Log → Response
    """
    start = time.time()

    if not req.prompt or not req.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt must not be empty")

    input_id = req.input_id or generate_id()

    # 1. Language detection
    lang_info = detect_language(req.prompt)
    language  = lang_info["primary"]

    # 2. Rule-based detector
    rule_result = rule_detector(req.prompt)

    # 3. Semantic ML detector
    sem_result = semantic_detector(req.prompt)

    # 4. PII detection
    pii_result = analyze_pii(req.prompt)

    # 5. Policy engine
    final_risk = compute_risk(
        rule_score     = rule_result["score"],
        semantic_score = sem_result["score"],
        pii_weight     = pii_result["pii_weight"],
        has_secret     = pii_result["has_secret"],
    )
    decision = make_decision(
        final_risk     = final_risk,
        pii_count      = pii_result["pii_count"],
        rule_score     = rule_result["score"],
        semantic_score = sem_result["score"],
    )

    # 6. Build safe output
    if decision == "BLOCK":
        safe_text = None
    elif decision == "MASK":
        safe_text = mask_pii(req.prompt, pii_result["entities"])
    else:
        safe_text = req.prompt

    latency_ms = (time.time() - start) * 1000

    # 7. Build structured response
    response = build_response(
        input_id       = input_id,
        language       = language,
        rule_result    = rule_result,
        semantic_result= sem_result,
        pii_result     = pii_result,
        final_risk     = final_risk,
        decision       = decision,
        safe_text      = safe_text,
        latency_ms     = latency_ms,
    )

    # 8. Audit log
    log_event(response)

    return response


@app.post("/batch")
def batch_analyze(prompts: list[str]):
    """Analyze multiple prompts at once (for evaluation)."""
    results = []
    for p in prompts:
        r = analyze(AnalyzeRequest(prompt=p))
        results.append(r)
    return {"results": results, "count": len(results)}


@app.get("/stats")
def stats():
    """Return basic statistics from the audit log."""
    import json
    from pathlib import Path
    log_file = Path("audit_log.jsonl")
    if not log_file.exists():
        return {"total": 0}
    lines = log_file.read_text().strip().split("\n")
    records = [json.loads(l) for l in lines if l.strip()]
    decisions = {}
    for r in records:
        d = r.get("decision", "UNKNOWN")
        decisions[d] = decisions.get(d, 0) + 1
    return {
        "total":     len(records),
        "decisions": decisions,
        "avg_latency_ms": round(
            sum(r.get("latency_ms", 0) for r in records) / max(len(records), 1), 2
        ),
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
