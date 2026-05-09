from fastapi import FastAPI
from models import EmailPayload, AnalysisResult
from scoring import analyze_email


# Creates the FastAPI backend application
app = FastAPI(title="Malicious Email Scorer")


# Main API endpoint that receives an email and returns the analysis result
@app.post("/analyze", response_model=AnalysisResult)
def analyze(email: EmailPayload):

    # Run the scoring engine on the incoming email
    score, verdict, reasons = analyze_email(email)

    # Return the structured analysis response
    return AnalysisResult(
        score=score,
        verdict=verdict,
        reasons=reasons
    )


# Simple health-check endpoint used to verify the backend is running
@app.get("/health")
def health():
    return {"status": "ok"}