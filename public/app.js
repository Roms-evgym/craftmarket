
"use strict";

const $ = (selector) => document.querySelector(selector);

const views = {
  auth: $("#auth-view"),
  password: $("#password-view"),
  app: $("#app-view")
};

let csrfToken = "";
let currentUser = null;

function showNotice(message, isError = false) {
  const notice = $("#notice");
  notice.textContent = message;
  notice.classList.remove("hidden");
  notice.classList.toggle("error", isError);
  notice.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideNotice() {
  $("#notice").classList.add("hidden");
}

function showView(name) {
  Object.entries(views).forEach(([key, element]) => {
    element.classList.toggle("hidden", key !== name);
  });

  $("#admin-panel").classList.toggle(
    "hidden",
    name !== "app" || currentUser?.role !== "admin"
  );
}

async function api(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(url, {
    ...options,
    method,
    headers,
    credentials: "same-origin"
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401) {
      currentUser = null;
      showView("auth");
    }

    throw new Error(data.error || `Fehler (${response.status})`);
  }

  if (data.csrfToken) csrfToken = data.csrfToken;

  return data;
}

async function refreshCsrf() {
  const data = await api("/api/csrf");
  csrfToken = data.token;
}

function money(cents, currency = "EUR") {
  const amount = Number(cents) / 100;

  if (!Number.isFinite(amount)) return "–";

  if (currency === "COINS") {
    return `${amount.toLocaleString("de-DE")} Coins`;
  }

  return new Intl.NumberFormat("de-DE", {
    style: "currency",
    currency: "EUR"
  }).format(amount);
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);

  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;

  return element;
}

function makeButton(text, handler, className = "btn secondary") {
  const button = makeElement("button", className, text);
  button.type = "button";
  button.addEventListener("click", handler);
  return button;
}

async function enterApplication(user) {
  currentUser = user;

  $("#header-user").textContent =
    `${user.username}${user.role === "admin" ? " · Admin" : ""}`;

  hideNotice();

  if (user.mustChangePassword) {
    showView("password");
    return;
  }

  showView("app");

  try {
    await Promise.all([loadJobs(), loadUsersIfAdmin()]);
  } catch (error) {
    showNotice(error.message, true);
  }
}

async function checkSession() {
  try {
    await refreshCsrf();

    const user = await api("/api/me");
    await enterApplication(user);
  } catch {
    currentUser = null;
    $("#header-user").textContent = "";
    showView("auth");
  }
}

/* Login */

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  hideNotice();

  const username = $("#login-username").value.trim();
  const password = $("#login-password").value;

  try {
    await refreshCsrf();

    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });

    $("#login-password").value = "";

    await enterApplication(data.user);
    showNotice(`Willkommen, ${data.user.username}!`);
  } catch (error) {
    showNotice(error.message, true);
  }
});

/* Passwort ändern */

$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  hideNotice();

  const password = $("#new-password").value;
  const confirmation = $("#confirm-password").value;

  if (password.length < 12) {
    return showNotice(
      "Das Passwort muss mindestens 12 Zeichen lang sein.",
      true
    );
  }

  if (password !== confirmation) {
    return showNotice("Die Passwörter stimmen nicht überein.", true);
  }

  try {
    await api("/api/password", {
      method: "POST",
      body: JSON.stringify({ password })
    });

    $("#password-form").reset();

    const user = await api("/api/me");
    await enterApplication(user);

    showNotice("Passwort erfolgreich geändert.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

/* Logout */

$("#logout-button").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
  } catch (error) {
    showNotice(error.message, true);
    return;
  }

  currentUser = null;
  $("#header-user").textContent = "";
  showView("auth");
  await refreshCsrf().catch(() => {});
  showNotice("Du wurdest abgemeldet.");
});

/* Benutzerverwaltung */

async function loadUsersIfAdmin() {
  if (currentUser?.role !== "admin") return;

  const container = $("#user-list");
  container.replaceChildren();

  try {
    const users = await api("/api/users");

    if (!users.length) {
      container.append(makeElement("p", "muted", "Noch keine Benutzer."));
      return;
    }

    for (const user of users) {
      const row = makeElement("div", "user-row");
      const details = makeElement("div");
      details.append(
        makeElement("strong", "", user.username),
        makeElement(
          "p",
          "muted",
          `${user.role}${user.disabled ? " · Deaktiviert" : ""}`
        )
      );

      row.append(details);

      if (
        user.role !== "admin" &&
        !user.disabled &&
        Number(user.id) !== Number(currentUser.id)
      ) {
        row.append(
          makeButton("Deaktivieren", async () => {
            if (!confirm(`Benutzer ${user.username} deaktivieren?`)) return;

            try {
              await api(`/api/users/${user.id}/disable`, {
                method: "POST",
                body: JSON.stringify({})
              });

              showNotice("Benutzer deaktiviert.");
              await loadUsersIfAdmin();
            } catch (error) {
              showNotice(error.message, true);
            }
          })
        );
      }

      container.append(row);
    }
  } catch (error) {
    showNotice(`Benutzerliste: ${error.message}`, true);
  }
}

$("#user-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (currentUser?.role !== "admin") {
    return showNotice("Admin-Rechte erforderlich.", true);
  }

  const username = $("#new-username").value.trim();
  const password = $("#initial-password").value;

  try {
    await api("/api/users", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });

    $("#user-form").reset();
    showNotice(`Benutzer ${username} wurde erstellt.`);
    await loadUsersIfAdmin();
  } catch (error) {
    showNotice(error.message, true);
  }
});

/* Aufträge */

async function loadJobs() {
  const container = $("#job-list");
  container.replaceChildren();

  const jobs = await api("/api/jobs");

  if (!jobs.length) {
    container.append(
      makeElement("p", "muted", "Noch keine Aufträge vorhanden.")
    );
    return;
  }

  for (const job of jobs) {
    const card = makeElement("article", "panel job-card");
    const title = makeElement("h3", "", job.title);
    const description = makeElement(
      "p",
      "",
      job.description
    );

    const status = makeElement(
      "span",
      "badge",
      job.status === "open"
        ? "Offen"
        : job.status === "in_progress"
          ? "In Bearbeitung"
          : job.status === "completed"
            ? "Abgeschlossen"
            : job.status
    );

    const budget = job.budget_cents ?? job.budgetCents;

    card.append(
      title,
      status,
      description,
      makeElement(
        "p",
        "muted",
        `Auftraggeber: ${job.owner_name || "Unbekannt"}`
      ),
      makeElement(
        "strong",
        "",
        money(budget, job.currency)
      ),
      makeButton("Details öffnen", () => openJob(job))
    );

    container.append(card);
  }
}

async function openJob(job) {
  const panel = $("#detail-panel");

  panel.classList.remove("hidden");
  $("#detail-title").textContent = job.title;
  $("#detail-description").textContent = job.description;

  $("#detail-meta").textContent =
    `Status: ${job.status} · Auftraggeber: ${job.owner_name || "Unbekannt"}`;

  $("#offer-section").replaceChildren();
  $("#chat-section").replaceChildren();
  $("#confirm-section").replaceChildren();

  if (
    job.status === "open" &&
    Number(job.owner_id) !== Number(currentUser.id)
  ) {
    const heading = makeElement("h3", "", "Angebot abgeben");
    const form = makeElement("form", "offer-form");
    const amount = makeElement("input");
    const message = makeElement("textarea");
    const submit = makeElement("button", "btn primary", "Angebot senden");

    amount.type = "number";
    amount.min = "0.01";
    amount.step = "0.01";
    amount.required = true;
    amount.placeholder = "Preis";

    message.maxLength = 1000;
    message.placeholder = "Nachricht (optional)";

    submit.type = "submit";

    form.append(amount, message, submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      try {
        await api(`/api/jobs/${job.id}/offers`, {
          method: "POST",
          body: JSON.stringify({
            amountCents: Math.round(Number(amount.value) * 100),
            message: message.value
          })
        });

        showNotice("Angebot wurde gesendet.");
        form.reset();
      } catch (error) {
        showNotice(error.message, true);
      }
    });

    $("#offer-section").append(heading, form);
  }

  const canChat =
    Number(job.owner_id) === Number(currentUser.id) ||
    Number(job.worker_id) === Number(currentUser.id) ||
    job.status === "open";

  if (canChat && ["open", "in_progress"].includes(job.status)) {
    await loadChat(job);
  }

  if (
    job.status === "in_progress" &&
    (
      Number(job.owner_id) === Number(currentUser.id) ||
      Number(job.worker_id) === Number(currentUser.id)
    )
  ) {
    const button = makeButton("Auftrag bestätigen", async () => {
      try {
        await api(`/api/jobs/${job.id}/confirm`, {
          method: "POST",
          body: JSON.stringify({})
        });

        showNotice("Bestätigung gespeichert.");
        await loadJobs();
        await openJob(await getJob(job.id));
      } catch (error) {
        showNotice(error.message, true);
      }
    }, "btn primary");

    $("#confirm-section").append(button);
  }

  if (
    Number(job.owner_id) === Number(currentUser.id) &&
    job.status === "open"
  ) {
    await loadOffers(job);
  }

  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function getJob(id) {
  const jobs = await api("/api/jobs");
  return jobs.find((job) => Number(job.id) === Number(id));
}

async function loadOffers(job) {
  const section = $("#offer-section");
  section.append(makeElement("h3", "", "Erhaltene Angebote"));

  try {
    const offers = await api(`/api/jobs/${job.id}/offers`);

    if (!offers.length) {
      section.append(makeElement("p", "muted", "Noch keine Angebote."));
      return;
    }

    for (const offer of offers) {
      const row = makeElement("div", "offer-row");
      row.append(
        makeElement(
          "p",
          "",
          `${offer.username}: ${money(
            offer.amount_cents,
            job.currency
          )}`
        ),
        makeElement("p", "muted", offer.message || "")
      );

      if (offer.status === "pending") {
        row.append(
          makeButton("Annehmen", async () => {
            try {
              await api(`/api/offers/${offer.id}/accept`, {
                method: "POST",
                body: JSON.stringify({})
              });

              showNotice("Angebot angenommen.");
              await loadJobs();
              await openJob(await getJob(job.id));
            } catch (error) {
              showNotice(error.message, true);
            }
          }, "btn primary")
        );
      }

      section.append(row);
    }
  } catch (error) {
    showNotice(error.message, true);
  }
}

async function loadChat(job) {
  const section = $("#chat-section");
  section.append(makeElement("h3", "", "Chat"));

  const messages = makeElement("div", "chat-messages");
  section.append(messages);

  try {
    const rows = await api(`/api/jobs/${job.id}/messages`);

    for (const message of rows) {
      const item = makeElement("div", "chat-message");
      item.append(
        makeElement(
          "strong",
          "",
          `${message.username} · ${new Date(
            message.created_at
          ).toLocaleString("de-DE")}`
        ),
        makeElement("p", "", message.body)
      );
      messages.append(item);
    }
  } catch (error) {
    showNotice(error.message, true);
  }

  const form = makeElement("form", "chat-form");
  const input = makeElement("input");
  const button = makeElement("button", "btn primary", "Senden");

  input.required = true;
  input.maxLength = 2000;
  input.placeholder = "Nachricht schreiben ...";
  button.type = "submit";

  form.append(input, button);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    try {
      await api(`/api/jobs/${job.id}/messages`, {
        method: "POST",
        body: JSON.stringify({ body: input.value })
      });

      input.value = "";
      await openJob(await getJob(job.id));
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  section.append(form);
}

/* Auftrag veröffentlichen */

$("#job-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const title = $("#job-title").value.trim();
  const description = $("#job-description").value.trim();
  const currency = $("#job-currency").value;
  const budget = Number($("#job-budget").value);

  if (!Number.isFinite(budget) || budget <= 0) {
    return showNotice("Bitte gib ein gültiges Budget ein.", true);
  }

  try {
    await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify({
        title,
        description,
        currency,
        budgetCents: Math.round(budget * 100)
      })
    });

    $("#job-form").reset();
    showNotice("Auftrag wurde veröffentlicht.");
    await loadJobs();
  } catch (error) {
    showNotice(error.message, true);
  }
});

/* Bedienelemente */

$("#refresh-button").addEventListener("click", async () => {
  try {
    await loadJobs();
    showNotice("Aufträge aktualisiert.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

$("#close-detail").addEventListener("click", () => {
  $("#detail-panel").classList.add("hidden");
});

checkSession();
