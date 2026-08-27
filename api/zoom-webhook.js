const crypto = require("crypto");

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

  const { event, payload } = req.body;

  console.log("Zoom event received:", event);
  console.log("Full body:", JSON.stringify(req.body));

  if (event === "recording.trashed") {
    await fetch(SLACK_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: "<!here> Folks, deleted recordings from the cloud to free up space. Please restore any recordings from the trash if required."
      }),
    });

    return res.status(200).json({ success: true });
  }

  return res.status(200).json({ received: true });
};
