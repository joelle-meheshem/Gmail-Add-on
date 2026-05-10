// Backend API endpoint exposed through ngrok
const BACKEND_URL = "https://throwback-dugout-harness.ngrok-free.dev/analyze";


// Displays the add-on homepage when no email is opened
function onHomepage(e) {

  return CardService.newCardBuilder()
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("Open an email to scan it for malicious indicators.")
        )
    )
    .build();
}


// Main Gmail Add-on function that analyzes the currently opened email
function buildAddOn(e) {

  try {

    // Validate Gmail message context
    if (!e || !e.gmail || !e.gmail.messageId) {

      return buildErrorCard(
        "No email context found",
        "Please open a Gmail message and try again."
      );
    }

    // Grant temporary access to the currently opened Gmail message
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

    // Retrieve the current Gmail message
    var messageId = e.gmail.messageId;

    var message = GmailApp.getMessageById(messageId);

    // Build backend payload
    var payload = {
      message_id: messageId,
      subject: message.getSubject() || "",
      sender: message.getFrom() || "",
      body_text: message.getPlainBody() || "",
      links: extractLinks(message.getPlainBody() || "")
    };

    // Send email to backend for analysis
    var response = UrlFetchApp.fetch(BACKEND_URL, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    });

    // Extract backend response
    var statusCode = response.getResponseCode();

    var responseText = response.getContentText();

    // Handle backend errors gracefully
    if (statusCode < 200 || statusCode >= 300) {

      return buildErrorCard(
        "Backend request failed",
        "Status code: " + statusCode + "\n\nResponse: " + responseText
      );
    }

    // Parse backend JSON
    var result = JSON.parse(responseText);

    // Render Gmail result card
    return createResultCard(result);

  } catch (err) {

    // Handle unexpected runtime failures
    return buildErrorCard(
      "Unexpected add-on error",
      err.message || String(err)
    );
  }
}


// Builds the Gmail card displaying the email analysis result
function createResultCard(result) {

  var card = CardService.newCardBuilder();

  var section = CardService.newCardSection()
    .setHeader("MailGuard Security Scan");

  // Verdict color
  var verdictColor = "#22c55e";

  if (result.verdict === "Suspicious") {
    verdictColor = "#f59e0b";
  }

  if (result.verdict === "Malicious") {
    verdictColor = "#ef4444";
  }

  // Verdict display
  section.addWidget(
    CardService.newTextParagraph()
      .setText(
        "<b>Verdict:</b> " +
        "<b><font color='" +
        verdictColor +
        "'>" +
        result.verdict.toUpperCase() +
        "</font></b>"
      )
  );

  // Risk score
  section.addWidget(
    CardService.newTextParagraph()
      .setText(
        "<b>Risk Score:</b> " +
        result.score +
        "/100"
      )
  );

  // Reasoning
  if (result.explanation) {

    section.addWidget(
      CardService.newTextParagraph()
        .setText(
          "<b>Reasoning:</b><br>" +
          escapeHtml(result.explanation)
        )
    );
  }

  // Timestamp
  section.addWidget(
    CardService.newTextParagraph()
      .setText(
        "<font color='#888888'>" +
        "Scanned at: " +
        new Date().toLocaleString() +
        "</font>"
      )
  );

  card.addSection(section);

  return card.build();
}


// Creates reusable Gmail error cards
function buildErrorCard(title, message) {

  return CardService.newCardBuilder()
    .addSection(
      CardService.newCardSection()
        .setHeader("Add-on Error")
        .addWidget(
          CardService.newTextParagraph()
            .setText(
              "<b>" +
              escapeHtml(title) +
              "</b><br><br>" +
              escapeHtml(message)
            )
        )
    )
    .build();
}


// Extracts URLs from plain text using regex
function extractLinks(text) {

  var regex = /https?:\/\/[^\s<>"']+/g;

  var matches = text.match(regex);

  return matches || [];
}


// Escapes HTML special characters
function escapeHtml(text) {

  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}