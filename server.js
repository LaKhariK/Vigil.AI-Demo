import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import dotenv from "dotenv";
import { spawn } from "child_process";
import session from "express-session";
import authRoutes from "./routes/auth.js";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

dotenv.config();

// ESM does not expose __dirname automatically, so I rebuild it here for
// serving dashboard files from the project folder.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* ----------------------------------------------------------
   Middleware
---------------------------------------------------------- */
app.use(
  cors({
    // The capstone prototype is normally run from localhost, so CORS is kept
    // narrow instead of opening the API to every origin.
    origin: "http://localhost:3000",
    credentials: true
  })
);

// Accept JSON for API calls and URL-encoded data for the login/register forms.
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// The frontend pages are static on purpose; the protected routes below decide
// which screens a signed-in user can reach.
app.use(express.static("public"));

app.use(
  session({
    name: "vigil.sid",
    secret: process.env.SESSION_SECRET || "vigil_dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      // Keeping the session cookie unreadable by browser JS reduces the damage
      // from a simple script injection bug in the prototype UI.
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

/* ----------------------------------------------------------
   Default Route
---------------------------------------------------------- */
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

/* ----------------------------------------------------------
   Auth Routes
---------------------------------------------------------- */
app.use("/auth", authRoutes);

/* ----------------------------------------------------------
   Debug Route
---------------------------------------------------------- */
app.get("/debug-session", (req, res) => {
  res.json({ user: req.session?.user || null });
});

/* ----------------------------------------------------------
   Auth Guard
---------------------------------------------------------- */
function requireAuth(req, res, next) {
  // Most app pages depend on a session, so unauthenticated users get sent back
  // to the login page instead of receiving raw API errors.
  if (!req.session || !req.session.user) {
    return res.redirect("/login.html");
  }
  next();
}

/* ----------------------------------------------------------
   PROTECTED APP ENTRY POINT
---------------------------------------------------------- */
app.get("/app", requireAuth, (req, res) => {
  res.redirect("/chatbot-index.html");
});

/* ----------------------------------------------------------
   TSHARK LIVE CAPTURE (PROTECTED)
---------------------------------------------------------- */
const TSHARK_PATH =
  process.env.TSHARK_PATH || "C:\\Program Files\\Wireshark\\tshark.exe";

// Only one capture process is allowed at a time so the UI does not accidentally
// start multiple expensive packet captures on the same machine.
let tsharkProc = null;

// Recent capture events are kept in memory for live Server-Sent Events clients.
// The buffer is intentionally capped because packet streams can grow forever.
let eventRing = [];

function ringPush(evt) {
  eventRing.push(evt);
  if (eventRing.length > 800) eventRing = eventRing.slice(-600);
}

function stopTshark() {
  if (tsharkProc) {
    try {
      tsharkProc.kill("SIGINT");
    } catch (e) {
      // If tshark already exited, the stop route should still behave cleanly.
    }
    tsharkProc = null;
  }
}

// tshark prints fields as comma-separated text. This parser keeps only the
// fields the dashboard needs and ignores partial rows from noisy captures.
function parseLine(line) {
  const parts = line.split(",");
  if (parts.length < 9) return null;

  const ts = (parts[0] || "").trim();
  const src = (parts[1] || "").trim();
  const dst = (parts[2] || "").trim();
  const ipProto = (parts[3] || "").trim();
  const tcpSport = (parts[4] || "").trim();
  const tcpDport = (parts[5] || "").trim();
  const udpSport = (parts[6] || "").trim();
  const udpDport = (parts[7] || "").trim();
  const len = (parts[8] || "").trim();

  if (!src || !dst) return null;

  let proto = "IP";
  if (ipProto === "6") proto = "TCP";
  else if (ipProto === "17") proto = "UDP";

  const sport = tcpSport || udpSport || "";
  const dport = tcpDport || udpDport || "";

  return { ts, src, dst, proto, sport, dport, len };
}

// List interfaces: GET /api/interfaces
app.get("/api/interfaces", requireAuth, (req, res) => {
  try {
    // Interface numbering comes from tshark itself, which avoids guessing at
    // Windows adapter names from Node.
    const p = spawn(TSHARK_PATH, ["-D"], { windowsHide: true });

    let out = "";
    let err = "";

    p.stdout.on("data", (d) => (out += d.toString("utf8")));
    p.stderr.on("data", (d) => (err += d.toString("utf8")));

    p.on("close", (code) => {
      if (code !== 0) {
        return res.json({ ok: false, error: err || `tshark -D exited ${code}` });
      }

      const lines = out.split(/\r?\n/).filter(Boolean);
      const interfaces = lines
        .map((ln) => {
          const m = ln.match(/^(\d+)\.\s+(.*)$/);
          if (!m) return null;
          return { index: Number(m[1]), name: m[2] };
        })
        .filter(Boolean);

      return res.json({ ok: true, interfaces });
    });
  } catch (e) {
    return res.json({ ok: false, error: String(e) });
  }
});

// Start capture: POST /api/start?iface=4&mode=ip|tcp|udp|any
app.post("/api/start", requireAuth, (req, res) => {
  const iface = String(req.query.iface || "");
  const mode = String(req.query.mode || "ip");

  if (!iface) return res.json({ ok: false, error: "Missing iface" });

  stopTshark();
  eventRing = [];

  // The display filter is deliberately simple for the prototype so the student
  // demo can switch between broad protocol views without teaching tshark syntax.
  let displayFilter = "ip";
  if (mode === "tcp") displayFilter = "tcp";
  else if (mode === "udp") displayFilter = "udp";
  else if (mode === "any") displayFilter = "";

  const args = ["-l", "-i", iface];

  if (displayFilter) args.push("-Y", displayFilter);

  args.push(
    "-T", "fields",
    "-E", "separator=,",
    "-E", "occurrence=f",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "ip.proto",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "udp.srcport",
    "-e", "udp.dstport",
    "-e", "frame.len"
  );

  try {
    tsharkProc = spawn(TSHARK_PATH, args, { windowsHide: true });

    let buf = "";

    tsharkProc.stdout.on("data", (d) => {
      // stdout arrives in chunks, not always full lines, so leftovers stay in
      // buf until the next chunk completes the row.
      buf += d.toString("utf8");
      const lines = buf.split(/\r?\n/);
      buf = lines.pop() || "";

      for (const ln of lines) {
        const t = ln.trim();
        if (!t) continue;
        const evt = parseLine(t);
        if (evt) ringPush(evt);
      }
    });

    tsharkProc.stderr.on("data", (d) => {
      const msg = d.toString("utf8").trim();
      // tshark warnings are still useful to the live UI, especially when an
      // adapter cannot be opened or permissions are missing.
      if (msg) ringPush({ ts: "", src: "", dst: "", proto: "ERR", sport: "", dport: "", len: "", error: msg });
    });

    tsharkProc.on("close", () => {
      tsharkProc = null;
    });

    return res.json({ ok: true });
  } catch (e) {
    tsharkProc = null;
    return res.json({ ok: false, error: String(e) });
  }
});

// Stop capture: POST /api/stop
app.post("/api/stop", requireAuth, (req, res) => {
  stopTshark();
  return res.json({ ok: true });
});

// Stream capture: GET /api/live  (SSE)
app.get("/api/live", requireAuth, (req, res) => {
  // SSE keeps this lightweight: the browser receives rows as they arrive
  // without a polling loop hammering the server.
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  res.write(`event: status\ndata: ${JSON.stringify({ message: "Connected" })}\n\n`);

  let idx = 0;

  const timer = setInterval(() => {
    // Each client has its own cursor into the shared ring buffer.
    while (idx < eventRing.length) {
      res.write(`data: ${JSON.stringify(eventRing[idx])}\n\n`);
      idx++;
    }
  }, 250);

  req.on("close", () => clearInterval(timer));
});

/* ----------------------------------------------------------
   ML MODEL ROUTE — /predict (protected)
---------------------------------------------------------- */
app.post("/predict", requireAuth, (req, res) => {
  const features = req.body.features;
  if (!features) {
    return res.status(400).json({ error: "No features provided" });
  }

  // The model is kept in Python because the training pipeline uses sklearn and
  // joblib; Node just passes the feature vector through stdin and returns JSON.
  const py = spawn("python", ["model.py"], {
    stdio: ["pipe", "pipe", "pipe"]
  });

  py.stdin.write(JSON.stringify({ features }));
  py.stdin.end();

  let out = "";
  py.stdout.on("data", (d) => (out += d.toString()));
  py.stderr.on("data", (d) => console.error("PY ERR:", d.toString()));

  py.on("close", () => {
    try {
      // Bad JSON usually means the Python script crashed or printed extra text,
      // so the raw output is included to make capstone demo debugging faster.
      const parsed = JSON.parse(out);
      return res.json(parsed);
    } catch {
      return res.status(500).json({
        error: "Invalid Python response",
        raw: out
      });
    }
  });
});

/* ----------------------------------------------------------
   GEMINI ROUTE — /api/chat (protected)
---------------------------------------------------------- */
app.post("/api/chat", requireAuth, async (req, res) => {
  const { userMessage } = req.body;

  if (!userMessage) {
    return res.status(400).json({ error: "No userMessage provided" });
  }

  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: "Missing GEMINI_API_KEY in environment" });
  }

  try {
    const model = "gemini-3.5-flash";
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

    // The response is reshaped to look like a ChatGPT-style choices array so
    // the frontend can stay simple even though Gemini is the provider.
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": process.env.GEMINI_API_KEY
      },
      body: JSON.stringify({
        contents: [
  {
    role: "user",
    parts: [
      {
        text: `
You are Vigil.AI, a concise cybersecurity assistant. Keep answers short and conversational. Answer in 1-2 sentences unless the user asks for more detail. Do not use bullet points unless requested
You are Vigil.AI. Your primary expertise is cybersecurity, networking, and threat analysis. However, you can also answer general questions about technology, careers, programming, business, and everyday topics.

User: ${userMessage}
`
      }
    ]
  }
]
      })
    });

    const data = await response.json();

    const text =
      data?.candidates?.[0]?.content?.parts
        ?.map((p) => (typeof p?.text === "string" ? p.text : ""))
        .join("") || "";

    return res.json({
      choices: [
        {
          message: {
            role: "assistant",
            content: text
          }
        }
      ]
    });
  } catch (err) {
    console.error("Gemini server error:", err);
    return res.status(500).json({ error: "Failed to connect to Gemini API" });
  }
});

/* ----------------------------------------------------------
   MODEL DASHBOARD — /models (protected)
---------------------------------------------------------- */
app.get("/models", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "model_dashboard.html"));
});

/* ----------------------------------------------------------
   MODEL STATS JSON — /model_stats.json (protected)
---------------------------------------------------------- */
app.get("/model_stats.json", requireAuth, (req, res) => {
  const statsPath = path.join(__dirname, "model_stats.json");
  if (fs.existsSync(statsPath)) {
    res.sendFile(statsPath);
  } else {
    res.status(404).json({ error: "model_stats.json not found. Run train_vigil_ai_model.py first." });
  }
});

  /* ----------------------------------------------------------
   GEMINI CLASSIFY ROUTE — /api/classify (for LLM comparison)
---------------------------------------------------------- */
app.post("/api/classify", requireAuth, async (req, res) => {
  const { features, featureNames } = req.body;

  if (!Array.isArray(features) || !Array.isArray(featureNames)) {
    return res.status(400).json({ error: "features and featureNames arrays are required" });
  }

  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: "Missing GEMINI_API_KEY in environment" });
  }

  const featureDesc = featureNames.map((n, i) => `${n}: ${features[i]}`).join(", ");

  // The prompt asks for strict JSON because this route is used for comparison
  // against the local ML model, not for a free-form chatbot answer.
  const prompt = `You are a network intrusion detection system. Classify the following network traffic features into exactly ONE of these categories:
- Benign (Normal Traffic)
- DDoS Attack
- DoS Attack
- Port Scan Activity
- Botnet / Malware Behavior
- Infiltration Attempt
- Web Attack

Network traffic features: ${featureDesc}

Respond in this exact JSON format only, no other text:
{"classification": "CATEGORY_HERE", "confidence": "High/Medium/Low", "reasoning": "One sentence explanation"}`;

  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": process.env.GEMINI_API_KEY
      },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { response_mime_type: "application/json" }
      })
    });

    const data = await response.json();

    if (data.error) {
      console.error("Gemini API error:", data.error);
      return res.status(502).json({ error: "Gemini API error", detail: data.error.message });
    }

    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    if (!text) {
      console.error("Gemini empty response:", JSON.stringify(data));
      return res.status(502).json({ error: "Gemini returned no content" });
    }

    // Gemini can still wrap JSON in fences, so this small cleanup makes the
    // route more forgiving without changing the expected response shape.
    const parsed = JSON.parse(text.replace(/```json|```/g, "").trim());
    res.json(parsed);
  } catch (err) {
    console.error("Gemini classification error:", err);
    res.status(500).json({ error: "Gemini classification failed", detail: String(err) });
  }
});

/* ----------------------------------------------------------
   Start Server
---------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
