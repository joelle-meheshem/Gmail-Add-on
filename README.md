# MailGuard — Malicious Email Scorer

## Overview

MailGuard is a Gmail Add-on that analyzes opened emails and produces a maliciousness score with an explainable security verdict.

The project was designed as a lightweight phishing and malicious email detection system focused on:

* Gmail integration
* Explainable security analysis
* Clean backend architecture
* Rule-based phishing detection
* Safe handling of untrusted email content

The system combines a Gmail Add-on built with Google Apps Script and a FastAPI backend service responsible for email analysis and scoring.

---

# Features

## Gmail Add-on Integration

* Runs directly inside Gmail
* Analyzes the currently opened email
* Displays the result as a Gmail card UI

## Security Signals

Implemented phishing and maliciousness heuristics include:

* Urgency / social-engineering language
* Credential theft attempts
* URL shorteners
* Suspicious top-level domains
* Lookalike / typosquatted domains
* Brand impersonation
* Risky attachment indicators
* Bare IP URLs
* Spam-like formatting
* Suspicious HTML artifacts

## Explainable Analysis

The add-on provides:

* Numerical risk score
* Final verdict
* Triggered security signals
* Human-readable explanation

## Error Handling

* Graceful backend failure handling
* User-friendly Gmail error cards
* Runtime exception protection

---

# Architecture

```text
Gmail Add-on (Apps Script)
        ↓
FastAPI Backend
        ↓
Scoring Engine
        ↓
Structured Analysis Result
        ↓
Rendered Gmail Card
```

---

# Technology Stack

## Frontend / Integration

* Google Apps Script
* Gmail Add-on APIs
* CardService UI

## Backend

* Python 3
* FastAPI
* Pydantic

## Development Tools

* ngrok
* VS Code

---

# Project Structure

```text
project/
│
├── main.py
├── models.py
├── scoring.py
├── requirements.txt
├── Code.gs
├── appsscript.json
└── README.md
```

---

# File Responsibilities

## main.py

API layer of the backend.
Receives email data from Gmail, validates requests, invokes the scoring engine, and returns structured JSON responses.

Main endpoints:

* POST /analyze
* GET /health

---

## models.py

Defines validated request and response schemas using Pydantic.
Ensures type safety and protects the backend from malformed input.

Main models:

* EmailPayload
* SignalResult
* AnalysisResult

---

## scoring.py

Contains the phishing detection and maliciousness scoring engine.
Implements all rule-based security heuristics and generates:

* Scores
* Verdicts
* Explanations
* Triggered signals

---

## Code.gs

Implements the Gmail Add-on using Google Apps Script.
Responsible for:

* Accessing the opened Gmail message
* Extracting email metadata
* Calling the backend API
* Rendering Gmail cards
* Handling runtime/backend errors

---

## appsscript.json

Google Apps Script manifest file.
Defines:

* OAuth permissions
* Gmail contextual triggers
* Add-on metadata
* Gmail integration behavior

---

# Setup Instructions

## 1. Create Virtual Environment

```bash
python -m venv venv
```

---

## 2. Activate Virtual Environment

Windows PowerShell:

```bash
venv\Scripts\activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Start FastAPI Backend

```bash
uvicorn main:app --reload
```

Expected:

```bash
Uvicorn running on http://127.0.0.1:8000
```

---

## 5. Start ngrok

In a second terminal:

```bash
ngrok http 8000
```

Copy the generated HTTPS forwarding URL.

---

## 6. Update Backend URL

Inside Code.gs:

```javascript
const BACKEND_URL = "https://YOUR-NGROK-URL/analyze";
```

Replace the placeholder with the active ngrok URL.

---

## 7. Deploy Gmail Add-on

Inside Google Apps Script:

1. Deploy
2. Test deployments
3. Install
4. Approve Gmail permissions

---

## 8. Test The Add-on

1. Open Gmail
2. Open any email
3. Open the MailGuard Add-on from the Gmail sidebar
4. Review the score, verdict, and explanation

---

# Example Analysis Result

```json
{
  "score": 78,
  "verdict": "Malicious",
  "signals": [
    {
      "name": "url_shortener",
      "triggered": true,
      "weight": 25,
      "detail": "Email contains a shortened URL"
    }
  ]
}
```

---

# Security Considerations

The system treats all incoming email data as untrusted input.

Implemented protections include:

* Pydantic validation
* HTML escaping before rendering Gmail cards
* Controlled OAuth scopes
* Structured backend separation
* Graceful runtime error handling
* Safe URL extraction

---

# Design Decisions

## Why FastAPI?

FastAPI was chosen because it enables rapid backend development while maintaining clean API contracts, automatic validation, and strong readability.

---

## Why Rule-Based Detection?

A rule-based approach was selected because it provides:

* Explainability
* Deterministic behavior
* Easier debugging
* Fast prototyping
* Better interview demonstration value

---

## Why ngrok?

ngrok was used to securely expose the local FastAPI backend during Gmail Add-on development and testing.

---

# Limitations

Current limitations include:

* No machine-learning classification
* No live threat-intelligence integration
* No attachment sandboxing
* Local development environment using ngrok
* Rule-based scoring may produce false positives or false negatives

---

# Future Improvements

Potential future enhancements:

* Machine learning phishing classifier
* Threat intelligence feeds
* URL reputation APIs
* Domain reputation analysis
* Real-time phishing feeds
* Attachment sandboxing
* Cloud deployment (Cloud Run / AWS)
* User feedback collection

---

# Demo Flow

1. Open Gmail
2. Open a suspicious email
3. Launch the MailGuard Add-on
4. View the maliciousness score
5. Review triggered security signals
6. Explain backend architecture
7. Discuss trade-offs and future improvements

---

# Author

Joelle Meheshem
Computer Science Student — University of Haifa
