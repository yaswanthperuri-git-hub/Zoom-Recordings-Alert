const crypto = require("crypto");

function verifyZoomWebhook(req, secret) {
  const message = `v0:${req.headers["x-zm-request-timestamp"]}:${JSON.stringify(req.body)}`;
  const hash = crypto.createHmac("sha256", secret).update(message).digest("hex");
  const signature = `v0=${hash}`;
  return signature === req.headers["x-zm-signature"];
}

async function sendSlackAlert(webhookUrl, payload) {
  const { topic, host_email, id, deleted_files } = payload.object;

  const fileList =
    deleted_files && deleted_files.length > 0
      ? deleted_files.map((f) => `• ${f.file_type} (${f.recording_type})`).join("\n")
      : "• Details not available";

  const body = {
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: "🗑️ Zoom Recording Deleted",
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Meeting:*\n${topic}` },
          { type: "mrkdwn", text: `*Host:*\n${host_email}` },
          { type: "mrkdwn", text: `*Meeting ID:*\n${id}` },
          { type: "mrkdwn", text: `*Deleted at:*\n${new Date().toUTCString()}` },
        ],
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Files deleted:*\n${fileList}`,
        },
      },
    ],
  };

  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Slack responded with ${response.status}`);
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const ZOOM_SECRET = process.env.ZOOM_WEBHOOK_SECRET_TOKEN;
  const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;

  if (req.body?.event === "endpoint.url_validation") {
    const hashForValidate = crypto
      .createHmac("sha256", ZOOM_SECRET)
      .update(req.body.payload.plainToken)
      .digest("hex");

    return res.status(200).json({
      plainToken: req.body.payload.plainToken,
      encryptedToken: hashForValidate,
    });
  }

  if (!verifyZoomWebhook(req, ZOOM_SECRET)) {
    console.error("Invalid Zoom webhook signature");
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { event, payload } = req.body;

  if (event === "recording.deleted") {
    try {
      await sendSlackAlert(SLACK_WEBHOOK_URL, payload);
      console.log(`Alert sent for deleted recording: ${payload.object?.topic}`);
      return res.status(200).json({ success: true });
    } catch (err) {
      console.error("Failed to send Slack alert:", err.message);
      return res.status(500).json({ error: "Failed to send Slack alert" });
    }
  }

  return res.status(200).json({ received: true });
};
