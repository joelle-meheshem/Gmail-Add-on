import re
from urllib.parse import urlparse
from models import EmailPayload, SignalResult


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}

SUSPICIOUS_TLDS = {
    ".ru", ".cn", ".tk", ".top", ".xyz", ".click", ".zip"
}

RISKY_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".js",
    ".jar", ".msi", ".ps1", ".hta", ".reg", ".docm", ".xlsm", ".pptm",
    ".iso", ".img", ".dmg", ".apk", ".zip", ".7z", ".rar",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "mail.com", "protonmail.com", "tutanota.com", "yandex.com",
}

TRUSTED_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "intel": ["intel.com", "workday.com", "myworkday.com"],
}

URGENCY_PATTERN = re.compile(
    r"\b(urgent|immediately|act now|action required|verify your account|"
    r"suspended|limited time|click here|confirm your|unusual activity|"
    r"security alert|your password|reset your|account (has been|will be)|"
    r"expires? (today|soon)|update your (payment|billing|credit)|"
    r"final warning|verify now)\b",
    re.IGNORECASE,
)

LOOKALIKE_PATTERN = re.compile(
    r"(paypa1|amaz0n|g00gle|micros0ft|app1e|faceb00k|arnazon|paypai|"
    r"llnked|linkedln)",
    re.IGNORECASE,
)


def extract_domain(value: str) -> str:
    if not value:
        return ""

    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", value)
    if match:
        return match.group(1).lower().replace("www.", "")

    parsed = urlparse(value)
    return parsed.netloc.lower().replace("www.", "")


def run_signals(email: EmailPayload):
    signals = []

    body = email.body_text or ""
    subject = email.subject or ""
    sender = email.sender or ""
    combined_text = f"{subject} {body}"

    body_lower = body.lower()
    subject_lower = subject.lower()
    sender_lower = sender.lower()
    combined_lower = combined_text.lower()

    sender_domain = extract_domain(sender)

    all_links = list(email.links or [])
    body_links = re.findall(r"https?://[^\s<>\"]+", body)
    all_links.extend(body_links)

    # 1. Urgency / social engineering language
    urgency_hits = URGENCY_PATTERN.findall(combined_text)
    urgency = len(urgency_hits) > 0

    signals.append(SignalResult(
        name="urgency_language",
        triggered=urgency,
        weight=min(len(urgency_hits) * 8, 25) if urgency else 0,
        detail="Urgency or social-engineering language detected." if urgency else ""
    ))

    # 2. Credential theft attempt
    credential_phrases = [
        "password",
        "login",
        "verify your account",
        "confirm your identity",
        "credentials",
        "security code",
        "reset your password",
        "two-factor",
        "2fa",
    ]

    credential_request = any(phrase in combined_lower for phrase in credential_phrases)

    signals.append(SignalResult(
        name="credential_request",
        triggered=credential_request,
        weight=30 if credential_request else 0,
        detail="Email appears to request login credentials or account verification." if credential_request else ""
    ))

    # 3. URL shortener detection
    shortened_url_detected = False

    for link in all_links:
        domain = extract_domain(link)
        if domain in URL_SHORTENERS:
            shortened_url_detected = True
            break

    signals.append(SignalResult(
        name="url_shortener",
        triggered=shortened_url_detected,
        weight=25 if shortened_url_detected else 0,
        detail="Email contains a shortened URL, which can hide the real destination." if shortened_url_detected else ""
    ))

    # 4. Bare IP URL
    bare_ip_url = any(
        re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", link)
        for link in all_links
    ) or bool(re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", combined_text))

    signals.append(SignalResult(
        name="bare_ip_url",
        triggered=bare_ip_url,
        weight=25 if bare_ip_url else 0,
        detail="Email contains a URL using a raw IP address instead of a domain." if bare_ip_url else ""
    ))

    # 5. Suspicious top-level domain
    suspicious_tld = any(sender_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

    signals.append(SignalResult(
        name="suspicious_domain_tld",
        triggered=suspicious_tld,
        weight=20 if suspicious_tld else 0,
        detail=f"Sender domain uses a suspicious top-level domain: {sender_domain}" if suspicious_tld else ""
    ))

    # 6. Free email provider
    free_email_sender = sender_domain in FREE_EMAIL_DOMAINS

    signals.append(SignalResult(
        name="free_email_sender",
        triggered=free_email_sender,
        weight=5 if free_email_sender else 0,
        detail=f"Sender uses a free consumer email provider: {sender_domain}" if free_email_sender else ""
    ))

    # 7. Lookalike / typosquatting
    lookalike_detected = bool(
        LOOKALIKE_PATTERN.search(sender_lower)
        or any(LOOKALIKE_PATTERN.search(link) for link in all_links)
    )

    signals.append(SignalResult(
        name="lookalike_domain",
        triggered=lookalike_detected,
        weight=35 if lookalike_detected else 0,
        detail="Sender or link contains a lookalike / typosquatted brand pattern." if lookalike_detected else ""
    ))

    # 8. Brand impersonation
    impersonation_detected = False
    impersonated_brand = ""

    all_link_domains = [extract_domain(link) for link in all_links]

    for brand, valid_domains in TRUSTED_BRANDS.items():
        sender_mentions_brand = brand in sender_lower
        subject_mentions_brand = brand in subject_lower

        link_mentions_brand = any(
            brand in domain for domain in all_link_domains if domain
        )

        email_claims_brand_identity = (
            sender_mentions_brand or
            subject_mentions_brand or
            link_mentions_brand
        )

        sender_matches_brand = any(
            sender_domain.endswith(domain) for domain in valid_domains
        )

        if email_claims_brand_identity and sender_domain and not sender_matches_brand:
            impersonation_detected = True
            impersonated_brand = brand
            break

    signals.append(SignalResult(
        name="brand_impersonation",
        triggered=impersonation_detected,
        weight=35 if impersonation_detected else 0,
        detail=f"Email mentions {impersonated_brand} but was sent from an unrelated domain." if impersonation_detected else ""
    ))

    # 9. Risky attachment indicators
    attachment_pattern = re.compile(
        r"\b[a-zA-Z0-9_-]+(\.exe|\.zip|\.rar|\.js|\.bat|\.scr|\.docm|\.xlsm)\b",
        re.IGNORECASE
    )

    risky_attachment = bool(attachment_pattern.search(combined_text))

    signals.append(SignalResult(
        name="risky_attachment",
        triggered=risky_attachment,
        weight=30 if risky_attachment else 0,
        detail="Email references a potentially risky attachment type." if risky_attachment else ""
    ))

    # 10. Suspicious HTML/script artifacts
    html_artifact = bool(re.search(r"<\s*(script|iframe|object|embed)", body, re.IGNORECASE))

    signals.append(SignalResult(
        name="html_script_artifact",
        triggered=html_artifact,
        weight=25 if html_artifact else 0,
        detail="Email body contains suspicious HTML script-like artifacts." if html_artifact else ""
    ))

    # 11. Spam-like formatting
    excessive_caps = subject.isupper() and len(subject) > 8
    many_exclamations = subject.count("!") >= 3 or body.count("!") >= 5

    spam_formatting = excessive_caps or many_exclamations

    signals.append(SignalResult(
        name="spam_formatting",
        triggered=spam_formatting,
        weight=10 if spam_formatting else 0,
        detail="Email uses spam-like formatting such as excessive capitalization or exclamation marks." if spam_formatting else ""
    ))

    return signals


def score_to_verdict(score: int) -> str:
    if score <= 25:
        return "Safe"
    elif score <= 60:
        return "Suspicious"
    return "Malicious"


def build_explanation(signals, score, verdict):
    active = [s for s in signals if s.triggered]

    if not active:
        return "No suspicious indicators were detected."

    reason_text = " ".join([s.detail for s in active])

    return f"Verdict: {verdict}. Score: {score}/100. {reason_text}"