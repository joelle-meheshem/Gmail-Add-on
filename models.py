from pydantic import BaseModel, Field
from typing import List


# Represents the email data sent from the Gmail Add-on to the backend
class EmailPayload(BaseModel):
    message_id: str = Field(..., max_length=200)
    sender: str
    subject: str = ""
    body_text: str = ""
    links: List[str] = []


# Represents a single security signal triggered during email analysis
class SignalResult(BaseModel):
    name: str
    triggered: bool
    weight: int
    detail: str


# Represents the final analysis result returned to the Gmail Add-on
class AnalysisResult(BaseModel):
    score: int
    verdict: str
    signals: List[SignalResult]
    explanation: str