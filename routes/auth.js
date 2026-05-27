const express = require("express");
const bcrypt = require("bcrypt");
const db = require("../db/database");

const router = express.Router();

/* Registration creates a local account and immediately starts a session so the
   prototype feels like a normal web app after signup. */
router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: "Missing fields" });

  if (password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters" });

  // A stronger bcrypt cost is fine here because registration happens rarely,
  // while storing plain passwords would be a bad security habit to demonstrate.
  const hash = await bcrypt.hash(password, 12);

  db.run(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    [username, hash],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE"))
          return res.status(409).json({ error: "Username already exists" });
        // Keep database details out of the browser, but still return a clear
        // failure so the frontend can show a useful message.
        return res.status(500).json({ error: "DB error" });
      }

      req.session.user = { id: this.lastID, username };
      res.json({ ok: true });
    }
  );
});

/* Login checks the submitted password against the saved hash before storing
   only the small user object needed by the session. */
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (!user) return res.status(401).json({ error: "Invalid credentials" });

      // The same generic error is used for both cases so failed logins do not
      // reveal whether a username exists.
      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) return res.status(401).json({ error: "Invalid credentials" });

      req.session.user = { id: user.id, username: user.username };
      res.json({ ok: true });
    }
  );
});

/* Logging out destroys the server-side session record. */
router.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

module.exports = router;
