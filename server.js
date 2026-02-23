const express = require("express");
const app = express();

app.use(express.json());

let messages = []; // temporary storage

// Webhook Verification
app.get("/webhook", (req, res) => {
  const VERIFY_TOKEN = "unisolvex_token";

  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  res.sendStatus(403);
});

// Receive Messages
app.post("/webhook", (req, res) => {
  const body = req.body;

  if (body.entry) {
    const msg = body.entry[0].changes[0].value.messages?.[0];

    if (msg) {
      const newMessage = {
        from: msg.from,
        text: msg.text?.body || "Non-text message",
        time: new Date().toLocaleString()
      };

      messages.unshift(newMessage);
      console.log("New Message:", newMessage);
    }
  }

  res.sendStatus(200);
});

// API to fetch messages
app.get("/messages", (req, res) => {
  res.json(messages);
});

// Root
app.get("/", (req, res) => {
  res.send("UniSolveX CRM Backend Running 🚀");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running"));