from fastapi import FastAPI
from models import EmailPayload, AnalysisResult
from scoring import run_signals, score_to_verdict, build_explanation

app = FastAPI(title="Malicious Email Scorer")


# Main API endpoint that receives an email and returns the analysis result
@app.post("/analyze", response_model=AnalysisResult)
def analyze(email: EmailPayload):

    # Run all scoring signals on the incoming email
    signals = run_signals(email)

    # Calculate final score
    score = min(sum(signal.weight for signal in signals), 100)

    # Convert score to verdict
    verdict = score_to_verdict(score)

    # Build human-readable explanation
    explanation = build_explanation(signals, score, verdict)

    # Return structured analysis response
    return AnalysisResult(
        score=score,
        verdict=verdict,
        signals=signals,
        explanation=explanation
    )


# Simple health-check endpoint used to verify the backend is running
@app.get("/health")
def health():
    return {"status": "ok"}