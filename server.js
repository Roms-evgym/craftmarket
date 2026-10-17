require("dotenv").config();

const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const {
  pool,
  initDatabase,
  ensureAdmin,
  withTransaction
} = require("./database");

const app = express();
const production = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET muss mindestens 32 Zeichen lang sein.");
}

if (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
  throw new Error("ADMIN_PASSWORD muss mindestens 12 Zeichen lang sein.");
}

if (production) app.set("trust proxy", 1);

app.disable("x-powered-by");

app.use(
  helmet({
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
  })
);

app.use(express.json({ limit: "20kb" }));

app.use(
  session({
    name: "craftmarket.sid",
    secret: process.env.SESSION_SECRET,
    store: new pgSession({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: true,
      pruneSessionInterval: 15 * 60
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: production,
      sameSite: "strict",
      maxAge: 8 * 60 * 60 * 1000
    }
  })
);

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

function asBool(value) {
  if (typeof value === "boolean") return value;
  return value === 1 || value === "1" || value === "t" || value === "true";
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    mustChangePassword: asBool(row.must_change_password)
  };
}

async function requireUser(req, res, next) {
  try {
    if (!req.session.user) {
      return res.status(401).json({ error: "Bitte anmelden." });
    }

    const result = await pool.query(
      `SELECT id, username, role, must_change_password, disabled
       FROM users WHERE id = $1`,
      [req.session.user.id]
    );

    const user = result.rows[0];

    if (!user || asBool(user.disabled)) {
      return req.session.destroy(() => {
        res.status(401).json({ error: "Konto nicht verfügbar." });
      });
    }

    req.user = user;

    if (
      asBool(user.must_change_password) &&
      !["/password", "/logout", "/me"].includes(req.path)
    ) {
      return res.status(403).json({
        error: "Bitte ändere zuerst dein Passwort.",
        mustChangePassword: true
      });
    }

    next();
  } catch (err) {
    next(err);
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin-Rechte erforderlich." });
  }

  next();
}

async function getJob(id, client = pool) {
  const result = await client.query(
    `SELECT
       j.*,
       owner.username AS owner_name,
       worker.username AS worker_name
     FROM jobs j
     JOIN users owner ON owner.id = j.owner_id
     LEFT JOIN users worker ON worker.id = j.worker_id
     WHERE j.id = $1`,
    [id]
  );

  return result.rows[0] || null;
}

function validAmount(value) {
  return (
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= 100000000000
  );
}

/* CSRF-Token */

app.get("/api/csrf", (req, res) => {
  req.session.csrfToken ||= crypto.randomBytes(32).toString("hex");
  res.json({ token: req.session.csrfToken });
});

/* Anmeldung */

app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const username = clean(req.body.username, 80);
    const password =
      typeof req.body.password === "string" ? req.body.password : "";

    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(username) = LOWER($1)",
      [username]
    );

    const user = result.rows[0];

    if (
      !user ||
      asBool(user.disabled) ||
      !bcrypt.compareSync(password, user.password_hash)
    ) {
      return res.status(401).json({
        error: "Benutzername oder Passwort falsch."
      });
    }

    req.session.regenerate((err) => {
      if (err) return next(err);

      req.session.user = { id: user.id };
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");

      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        res.json({
          user: publicUser(user),
          csrfToken: req.session.csrfToken
        });
      });
    });
  } catch (err) {
    next(err);
  }
});

/* Anmeldung für geschützte API-Routen erforderlich */

app.use("/api", (req, res, next) => {
  if (["/csrf", "/login"].includes(req.path)) {
    return next();
  }

  requireUser(req, res, next);
});

/* Aktueller Benutzer */

app.get("/api/me", (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role,
    mustChangePassword: asBool(req.user.must_change_password)
  });
});

/* Abmeldung */

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        error: "Abmeldung fehlgeschlagen."
      });
    }

    res.clearCookie("craftmarket.sid", {
      httpOnly: true,
      sameSite: "strict",
      secure: production
    });

    res.json({ ok: true });
  });
});

/* Passwort ändern */

app.post("/api/password", async (req, res, next) => {
  try {
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

    await pool.query(
      `UPDATE users
       SET password_hash = $1, must_change_password = FALSE
       WHERE id = $2`,
      [hash, req.user.id]
    );

    const userId = req.user.id;

    req.session.regenerate((err) => {
      if (err) return next(err);

      req.session.user = { id: userId };
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");

      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        res.json({
          ok: true,
          csrfToken: req.session.csrfToken
        });
      });
    });
  } catch (err) {
    next(err);
  }
});

/* Benutzer erstellen – nur Admin */

app.post("/api/users", requireAdmin, async (req, res, next) => {
  try {
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

    const result = await pool.query(
      `INSERT INTO users
         (username, password_hash, role, must_change_password)
       VALUES ($1, $2, 'user', TRUE)
       RETURNING id`,
      [username, bcrypt.hashSync(password, 12)]
    );

    res.status(201).json({
      id: result.rows[0].id,
      username,
      mustChangePassword: true
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "Dieser Benutzername ist bereits vergeben."
      });
    }

    next(err);
  }
});

/* Benutzer auflisten – nur Admin */

app.get("/api/users", requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, username, role, disabled, created_at
       FROM users ORDER BY created_at DESC`
    );

    res.json(
      result.rows.map((row) => ({
        ...row,
        disabled: asBool(row.disabled)
      }))
    );
  } catch (err) {
    next(err);
  }
});

/* Benutzer deaktivieren – nur Admin */

app.post("/api/users/:id/disable", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id <= 0 || id === Number(req.user.id)) {
      return res.status(400).json({
        error: "Ungültige Benutzer-ID."
      });
    }

    const result = await pool.query(
      `UPDATE users SET disabled = TRUE
       WHERE id = $1 AND role != 'admin'`,
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Benutzer nicht gefunden."
      });
    }

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

/* Aufträge auflisten */

app.get("/api/jobs", async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT
         j.*,
         owner.username AS owner_name,
         worker.username AS worker_name
       FROM jobs j
       JOIN users owner ON owner.id = j.owner_id
       LEFT JOIN users worker ON worker.id = j.worker_id
       ORDER BY j.id DESC`
    );

    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

/* Auftrag erstellen */

app.post("/api/jobs", async (req, res, next) => {
  try {
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
      return res.status(400).json({
        error: "Ungültige Auftragsdaten."
      });
    }

    const result = await pool.query(
      `INSERT INTO jobs
         (owner_id, title, description, currency, budget_cents)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [req.user.id, title, description, currency, amount]
    );

    res.status(201).json(await getJob(result.rows[0].id));
  } catch (err) {
    next(err);
  }
});

/* Angebot abgeben */

app.post("/api/jobs/:id/offers", async (req, res, next) => {
  try {
    const job = await getJob(Number(req.params.id));
    const amount = req.body.amountCents;
    const message = clean(req.body.message, 1000);

    if (
      !job ||
      job.status !== "open" ||
      Number(job.owner_id) === Number(req.user.id)
    ) {
      return res.status(400).json({
        error: "Auftrag ist nicht verfügbar."
      });
    }

    if (!validAmount(amount)) {
      return res.status(400).json({
        error: "Ungültiger Angebotspreis."
      });
    }

    const result = await pool.query(
      `INSERT INTO offers (job_id, user_id, amount_cents, message)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [job.id, req.user.id, amount, message]
    );

    res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    next(err);
  }
});

/* Angebote eines Auftrags anzeigen */

app.get("/api/jobs/:id/offers", async (req, res, next) => {
  try {
    const job = await getJob(Number(req.params.id));

    if (
      !job ||
      (Number(job.owner_id) !== Number(req.user.id) &&
        req.user.role !== "admin")
    ) {
      return res.status(403).json({
        error: "Kein Zugriff auf diese Angebote."
      });
    }

    const result = await pool.query(
      `SELECT o.*, u.username
       FROM offers o
       JOIN users u ON u.id = o.user_id
       WHERE o.job_id = $1
       ORDER BY o.id DESC`,
      [job.id]
    );

    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

/* Angebot annehmen */

app.post("/api/offers/:id/accept", async (req, res, next) => {
  try {
    const jobId = await withTransaction(async (client) => {
      const result = await client.query(
        `SELECT o.*, j.owner_id, j.status AS job_status
         FROM offers o
         JOIN jobs j ON j.id = o.job_id
         WHERE o.id = $1
         FOR UPDATE OF j, o`,
        [Number(req.params.id)]
      );

      const offer = result.rows[0];

      if (
        !offer ||
        Number(offer.owner_id) !== Number(req.user.id) ||
        offer.job_status !== "open" ||
        offer.status !== "pending" ||
        Number(offer.user_id) === Number(offer.owner_id)
      ) {
        throw new Error("Dieses Angebot kann nicht angenommen werden.");
      }

      const update = await client.query(
        `UPDATE jobs
         SET worker_id = $1,
             agreed_cents = $2,
             status = 'in_progress'
         WHERE id = $3 AND status = 'open'`,
        [offer.user_id, offer.amount_cents, offer.job_id]
      );

      if (update.rowCount !== 1) {
        throw new Error("Der Auftrag wurde bereits vergeben.");
      }

      await client.query(
        `UPDATE offers SET status = 'rejected'
         WHERE job_id = $1 AND status = 'pending'`,
        [offer.job_id]
      );

      await client.query(
        "UPDATE offers SET status = 'accepted' WHERE id = $1",
        [offer.id]
      );

      return offer.job_id;
    });

    res.json({
      ok: true,
      job: await getJob(jobId)
    });
  } catch (err) {
    if (
      [
        "Dieses Angebot kann nicht angenommen werden.",
        "Der Auftrag wurde bereits vergeben."
      ].includes(err.message)
    ) {
      return res.status(409).json({ error: err.message });
    }

    next(err);
  }
});

/* Nachricht senden */

app.post("/api/jobs/:id/messages", async (req, res, next) => {
  try {
    const job = await getJob(Number(req.params.id));
    const body = clean(req.body.body, 2000);

    if (!job || !["open", "in_progress"].includes(job.status)) {
      return res.status(400).json({
        error: "Chat nicht verfügbar."
      });
    }

    const allowed =
      Number(job.owner_id) === Number(req.user.id) ||
      Number(job.worker_id) === Number(req.user.id) ||
      (job.status === "open" &&
        Number(req.user.id) !== Number(job.owner_id));

    if (!allowed || body.length < 1) {
      return res.status(403).json({
        error: "Nachricht nicht erlaubt."
      });
    }

    const result = await pool.query(
      `INSERT INTO messages (job_id, user_id, body)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [job.id, req.user.id, body]
    );

    res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    next(err);
  }
});

/* Nachrichten eines Auftrags anzeigen */

app.get("/api/jobs/:id/messages", async (req, res, next) => {
  try {
    const job = await getJob(Number(req.params.id));

    if (!job) {
      return res.status(404).json({
        error: "Auftrag nicht gefunden."
      });
    }

    const allowed =
      Number(job.owner_id) === Number(req.user.id) ||
      Number(job.worker_id) === Number(req.user.id) ||
      (job.status === "open" && req.user.role === "admin");

    if (!allowed) {
      return res.status(403).json({
        error: "Kein Zugriff auf diesen Chat."
      });
    }

    const result = await pool.query(
      `SELECT m.id, m.user_id, u.username, m.body, m.created_at
       FROM messages m
       JOIN users u ON u.id = m.user_id
       WHERE m.job_id = $1
       ORDER BY m.id ASC`,
      [job.id]
    );

    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

/* Auftrag bestätigen */


/* Auftrag bestätigen und nach beidseitiger Bestätigung löschen */
app.post("/api/jobs/:id/confirm", async (req, res, next) => {
  try {
    const result = await withTransaction(async (client) => {
      const found = await client.query(
        "SELECT * FROM jobs WHERE id = $1 FOR UPDATE",
        [Number(req.params.id)]
      );

      const current = found.rows[0];

      if (
        !current ||
        current.status !== "in_progress" ||
        !current.worker_id
      ) {
        throw new Error("Auftrag kann nicht bestätigt werden.");
      }

      if (Number(req.user.id) === Number(current.owner_id)) {
        if (asBool(current.buyer_confirmed)) {
          throw new Error("Bereits bestätigt.");
        }

        await client.query(
          "UPDATE jobs SET buyer_confirmed = TRUE WHERE id = $1",
          [current.id]
        );
      } else if (Number(req.user.id) === Number(current.worker_id)) {
        if (asBool(current.seller_confirmed)) {
          throw new Error("Bereits bestätigt.");
        }

        await client.query(
          "UPDATE jobs SET seller_confirmed = TRUE WHERE id = $1",
          [current.id]
        );
      } else {
        throw new Error(
          "Du bist nicht an diesem Auftrag beteiligt."
        );
      }

      // Aktuellen Bestätigungsstand aus der Datenbank lesen
      const updated = await client.query(
        "SELECT * FROM jobs WHERE id = $1",
        [current.id]
      );

      const job = updated.rows[0];

      // Erst löschen, wenn beide Seiten bestätigt haben
      if (
        asBool(job.buyer_confirmed) &&
        asBool(job.seller_confirmed)
      ) {
        await client.query(
          "UPDATE jobs SET status = 'completed' WHERE id = $1",
          [current.id]
        );

        await client.query(
          "DELETE FROM jobs WHERE id = $1",
          [current.id]
        );

        return {
          deleted: true,
          message: "Auftrag abgeschlossen und gelöscht."
        };
      }

      return {
        deleted: false,
        buyerConfirmed: asBool(job.buyer_confirmed),
        sellerConfirmed: asBool(job.seller_confirmed),
        message: "Bestätigung gespeichert."
      };
    });

    res.json(result);
  } catch (err) {
    if (
      [
        "Auftrag kann nicht bestätigt werden.",
        "Bereits bestätigt.",
        "Du bist nicht an diesem Auftrag beteiligt."
      ].includes(err.message)
    ) {
      return res.status(400).json({ error: err.message });
    }

    next(err);
  }
});


    res.json({ job: await getJob(jobId) });
  } catch (err) {
    if (
      [
        "Auftrag kann nicht bestätigt werden.",
        "Bereits bestätigt.",
        "Du bist nicht an diesem Auftrag beteiligt."
      ].includes(err.message)
    ) {
      return res.status(400).json({ error: err.message });
    }

    next(err);
  }
});

/* Statische Website */

app.use(express.static(path.join(__dirname, "public")));

/* Fehlerbehandlung */

app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "Interner Serverfehler."
  });
});

/* Datenbank zuerst initialisieren, dann Admin anlegen, dann Server starten */

const port = Number(process.env.PORT || 3000);

async function startServer() {
  await initDatabase();
  console.log("Datenbanktabellen wurden überprüft.");

  await ensureAdmin(process.env.ADMIN_PASSWORD);
  console.log("Admin-Konto wurde überprüft.");

  app.listen(port, "0.0.0.0", () => {
    console.log(`CraftMarket läuft auf Port ${port}.`);
  });
}

startServer().catch((err) => {
  console.error("CraftMarket konnte nicht gestartet werden:", err);
  process.exit(1);
});
