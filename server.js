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

function
