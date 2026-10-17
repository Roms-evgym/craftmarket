
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");
const { db, ensureAdmin } = require("./database");

const app = express();
const production = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET muss mindestens 32 Zeichen lang sein.");
}

ensureAdmin(process.env.ADMIN_PASSWORD);

if (production) app.set("trust proxy", 1);

app.disable("x-powered-by");

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));

app.use(express.json({ limit: "20kb" }));

const dataDir = process.env.DATA_DIR || __dirname;

app.use(session({
  name: "craftmarket.sid",
  secret: process.env.SESSION_SECRET,
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: dataDir,
    tableName: "sessions"
  }),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

function csrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const token = req.get("X-CSRF-Token");
  const expected = req.session.csrfToken;

  if (
    typeof token !== "string" ||
    typeof expected !== "string" ||
    token.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))
  ) {
    return res.status(403).json({ error: "Ungültiges CSRF-Token." });
  }

  next();
}

app.use("/api", csrf);

function clean(value, max = 1000) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function requireUser(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Bitte anmelden." });
  }

  const user = db.prepare(`
    SELECT id, username, role, must_change_password, disabled
    FROM users WHERE id = ?
  `).get(req.session.user.id);

  if (!user || user.disabled) {
    return req.session.destroy(() => {
      res.status(401).json({ error: "Konto nicht verfügbar." });
    });
  }

  req.user = user;

  if (
    user.must_change_password &&
    !["/password", "/logout", "/me"].includes(req.path)
  ) {
    return res.status(403).json({
      error: "Bitte ändere zuerst dein Passwort.",
      mustChangePassword: true
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin-Rechte erforderlich." });
  }
  next();
}

function getJob(id) {
  return db.prepare(`
    SELECT j.*, owner.username AS owner_name,
           worker.username AS worker_name
    FROM jobs j
    JOIN users owner ON owner.id = j.owner_id
    LEFT JOIN users worker ON worker.id = j.worker_id
    WHERE j.id = ?
  `).get(id);
}

function canAccessJob(job, user) {
  return !!job && (
    user.role === "admin" ||
    job.owner_id === user.id ||
    job.worker_id === user.id
  );
}

function validAmount(value) {
  return Number.isSafeInteger(value) &&
    value > 0 &&
    value <= 100000000000;
}

// CSRF-Token für die Anmeldung und für neue Sessions
app.get("/api/csrf", (req, res) => {
  req.session.csrfToken ||= crypto.randomBytes(32).toString("hex");
  res.json({ token: req.session.csrfToken });
});

// Anmeldung
app.post("/api/login", loginLimiter, (req, res, next) => {
  const username = clean(req.body.username, 80);
  const password = typeof req.body.password === "string"
    ? req.body.password
    : "";

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ? COLLATE NOCASE"
  ).get(username);

  if (
    !user ||
    user.disabled ||
    !bcrypt.compareSync(password, user.password_hash)
  ) {
    return res.status(401).json({
      error: "Benutzername oder Passwort falsch."
    });
  }

  req.session.regenerate(err => {
    if (err) return next(err);

    req.session.user = { id: user.id };
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");

    req.session.save(err => {
      if (err) return next(err);

      res.json({
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          mustChangePassword: !!user.must_change_password
        },
        csrfToken: req.session.csrfToken
      });
    });
  });
});

// Ab hier benötigen die API-Endpunkte ein angemeldetes Konto.
app.use("/api", (req, res, next) => {
  if (["/csrf", "/login"].includes(req.path)) return next();
  requireUser(req, res, next);
});

app.get("/api/me", (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role,
    mustChangePassword: !!req.user.must_change_password
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "Abmeldung fehlgeschlagen." });

    res.clearCookie("craftmarket.sid", {
      httpOnly: true,
      sameSite: "strict",
      secure: production
    });

    res.json({ ok: true });
  });
});

// Passwortänderung beim ersten Login
app.post("/api/password", (req, res, next) => {
  const password = req.body.password;

  if (
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 200
  ) {
    return res.status(400).json({
      error: "Das neue Passwort muss 12 bis 200 Zeichen haben."
    });
  }

  const hash = bcrypt.hashSync(password, 12);

  db.prepare(`
    UPDATE users SET password_hash = ?, must_change_password = 0
    WHERE id = ?
  `).run(hash, req.user.id);

  req.session.regenerate(err => {
    if (err) return next(err);

    req.session.user = { id: req.user.id };
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");

    req.session.save(err => {
      if (err) return next(err);
      res.json({ ok: true, csrfToken: req.session.csrfToken });
    });
  });
});

// Admin: Benutzerkonto anlegen
app.post("/api/users", requireAdmin, (req, res) => {
  const username = clean(req.body.username, 32);
  const password = req.body.password;

  if (
    !/^[a-zA-Z0-9_]{3,32}$/.test(username) ||
    username.toLowerCase() === "admin"
  ) {
    return res.status(400).json({
      error: "Ungültiger oder reservierter Benutzername."
    });
  }

  if (
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 200
  ) {
    return res.status(400).json({
      error: "Das Startpasswort muss 12 bis 200 Zeichen haben."
    });
  }

  try {
    const result = db.prepare(`
      INSERT INTO users
        (username, password_hash, role, must_change_password)
      VALUES (?, ?, 'user', 1)
    `).run(username, bcrypt.hashSync(password, 12));

    res.status(201).json({
      id: Number(result.lastInsertRowid),
      username,
      mustChangePassword: true
    });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "Dieser Benutzername ist bereits vergeben."
      });
    }
    throw err;
  }
});

// Admin: Benutzerliste
app.get("/api/users", requireAdmin, (req, res) => {
  res.json(db.prepare(`
    SELECT id, username, role, disabled, created_at
    FROM users ORDER BY created_at DESC
  `).all());
});

// Admin: Benutzer sperren
app.post("/api/users/:id/disable", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id === req.user.id) {
    return res.status(400).json({ error: "Ungültige Benutzer-ID." });
  }

  const result = db.prepare(`
    UPDATE users SET disabled = 1
    WHERE id = ? AND role != 'admin'
  `).run(id);

  if (!result.changes) {
    return res.status(404).json({ error: "Benutzer nicht gefunden." });
  }

  res.json({ ok: true });
});

// Aufträge auflisten
app.get("/api/jobs", (req, res) => {
  res.json(db.prepare(`
    SELECT j.*, owner.username AS owner_name,
           worker.username AS worker_name
    FROM jobs j
    JOIN users owner ON owner.id = j.owner_id
    LEFT JOIN users worker ON worker.id = j.worker_id
    ORDER BY j.id DESC
  `).all());
});

// Neuen Auftrag erstellen
app.post("/api/jobs", (req, res) => {
  const title = clean(req.body.title, 100);
  const description = clean(req.body.description, 3000);
  const currency = req.body.currency;
  const amount = req.body.budgetCents;

  if (
    title.length < 4 ||
    description.length < 10 ||
    !["EUR", "COINS"].includes(currency) ||
    !validAmount(amount)
  ) {
    return res.status(400).json({ error: "Ungültige Auftragsdaten." });
  }

  const result = db.prepare(`
    INSERT INTO jobs (owner_id, title, description, currency, budget_cents)
    VALUES (?, ?, ?, ?, ?)
  `).run(req.user.id, title, description, currency, amount);

  res.status(201).json(getJob(Number(result.lastInsertRowid)));
});

// Preisangebot senden
app.post("/api/jobs/:id/offers", (req, res) => {
  const job = getJob(Number(req.params.id));
  const amount = req.body.amountCents;
  const message = clean(req.body.message, 1000);

  if (!job || job.status !== "open" || job.owner_id === req.user.id) {
    return res.status(400).json({ error: "Auftrag ist nicht verfügbar." });
  }

  if (!validAmount(amount)) {
    return res.status(400).json({ error: "Ungültiger Angebotspreis." });
  }

  const result = db.prepare(`
    INSERT INTO offers (job_id, user_id, amount_cents, message)
    VALUES (?, ?, ?, ?)
  `).run(job.id, req.user.id, amount, message);

  res.status(201).json({ id: Number(result.lastInsertRowid) });
});

// Angebote für den Auftraggeber und Admin anzeigen
app.get("/api/jobs/:id/offers", (req, res) => {
  const job = getJob(Number(req.params.id));

  if (!job || (job.owner_id !== req.user.id && req.user.role !== "admin")) {
    return res.status(403).json({ error: "Kein Zugriff auf diese Angebote." });
  }

  res.json(db.prepare(`
    SELECT o.*, u.username
    FROM offers o JOIN users u ON u.id = o.user_id
    WHERE o.job_id = ?
    ORDER BY o.id DESC
  `).all(job.id));
});

// Angebot annehmen: atomare Zuweisung
app.post("/api/offers/:id/accept", (req, res) => {
  const tx = db.transaction(() => {
    const offer = db.prepare(`
      SELECT o.*, j.owner_id, j.status AS job_status, j.currency
      FROM offers o JOIN jobs j ON j.id = o.job_id
      WHERE o.id = ?
    `).get(Number(req.params.id));

    if (
      !offer ||
      offer.owner_id !== req.user.id ||
      offer.job_status !== "open" ||
      offer.status !== "pending" ||
      offer.user_id === offer.owner_id
    ) {
      throw new Error("Dieses Angebot kann nicht angenommen werden.");
    }

    const update = db.prepare(`
      UPDATE jobs
      SET worker_id = ?, agreed_cents = ?, status = 'in_progress'
      WHERE id = ? AND status = 'open'
    `).run(offer.user_id, offer.amount_cents, offer.job_id);

    if (update.changes !== 1) {
      throw new Error("Der Auftrag wurde bereits vergeben.");
    }

    db.prepare(`
      UPDATE offers SET status = 'rejected'
      WHERE job_id = ? AND status = 'pending'
    `).run(offer.job_id);

    db.prepare(`
      UPDATE offers SET status = 'accepted' WHERE id = ?
    `).run(offer.id);

    return offer.job_id;
  });

  try {
    const jobId = tx();
    res.json({ ok: true, job: getJob(jobId) });
  } catch (err) {
    res.status(409).json({ error: err.message });
  }
});

// Chat: Auftraggeber und alle Anbieter dürfen vor Annahme verhandeln.
// Nach Annahme dürfen nur die beiden Beteiligten schreiben.
app.post("/api/jobs/:id/messages", (req, res) => {
  const job = getJob(Number(req.params.id));
  const body = clean(req.body.body, 2000);

  if (!job || !["open", "in_progress"].includes(job.status)) {
    return res.status(400).json({ error: "Chat nicht verfügbar." });
  }

  
const allowed = job.owner_id === req.user.id ||
  job.worker_id === req.user.id ||
  (job.status === "open" && req.user.id !== job.owner_id);


  if (!allowed || body.length < 1) {
    return res.status(403).json({ error: "Nachricht nicht erlaubt." });
  }

  const result = db.prepare(`
    INSERT INTO messages (job_id, user_id, body)
    VALUES (?, ?, ?)
  `).run(job.id, req.user.id, body);

  res.status(201).json({ id: Number(result.lastInsertRowid) });
});

// Chatnachrichten lesen
app.get("/api/jobs/:id/messages", (req, res) => {
  const job = getJob(Number(req.params.id));

  if (!job) return res.status(404).json({ error: "Auftrag nicht gefunden." });

  const allowed = job.owner_id === req.user.id ||
    job.worker_id === req.user.id ||
    (job.status === "open" && req.user.role === "admin");

  if (!allowed) {
    return res.status(403).json({ error: "Kein Zugriff auf diesen Chat." });
  }

  res.json(db.prepare(`
    SELECT m.id, m.user_id, u.username, m.body, m.created_at
    FROM messages m JOIN users u ON u.id = m.user_id
    WHERE m.job_id = ? ORDER BY m.id ASC
  `).all(job.id));
});

// Auftrag separat als Käufer oder Verkäufer bestätigen
app.post("/api/jobs/:id/confirm", (req, res) => {
  const tx = db.transaction(() => {
    const job = getJob(Number(req.params.id));

    if (!job || job.status !== "in_progress" || !job.worker_id) {
      throw new Error("Auftrag kann nicht bestätigt werden.");
    }

    if (req.user.id === job.owner_id) {
      if (job.buyer_confirmed) throw new Error("Bereits bestätigt.");

      db.prepare(`
        UPDATE jobs SET buyer_confirmed = 1 WHERE id = ?
      `).run(job.id);
    } else if (req.user.id === job.worker_id) {
      if (job.seller_confirmed) throw new Error("Bereits bestätigt.");

      db.prepare(`
        UPDATE jobs SET seller_confirmed = 1 WHERE id = ?
      `).run(job.id);
    } else {
      throw new Error("Du bist nicht an diesem Auftrag beteiligt.");
    }

    db.prepare(`
      UPDATE jobs SET status = 'completed'
      WHERE id = ? AND buyer_confirmed = 1 AND seller_confirmed = 1
    `).run(job.id);

    return getJob(job.id);
  });

  try {
    res.json({ job: tx() });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Frontend-Dateien bereitstellen
app.use(express.static(path.join(__dirname, "public")));

app.use((err, req, res, next) => {
  console.error(err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Interner Serverfehler." });
});

const port = Number(process.env.PORT || 3000);

app.listen(port, "0.0.0.0", () => {
  console.log(`CraftMarket läuft auf Port ${port}.`);
});
