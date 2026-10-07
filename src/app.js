(function () {
  "use strict";

  const { checkAccess, parseRepoInput, InputError } = window.RepoAccess;

  const form = document.getElementById("check-form");
  const repoInput = document.getElementById("repo");
  const tokenInput = document.getElementById("token");
  const toggleBtn = document.getElementById("toggle-token");
  const submitBtn = document.getElementById("submit");
  const formError = document.getElementById("form-error");
  const results = document.getElementById("results");

  // Allow prefilling the repo (never the token) via ?repo=owner/name.
  const prefill = new URLSearchParams(location.search).get("repo");
  if (prefill) repoInput.value = prefill;

  toggleBtn.addEventListener("click", () => {
    const show = tokenInput.type === "password";
    tokenInput.type = show ? "text" : "password";
    toggleBtn.textContent = show ? "Hide" : "Show";
    toggleBtn.setAttribute("aria-pressed", String(show));
  });

  repoInput.addEventListener("input", () => {
    repoInput.removeAttribute("aria-invalid");
    showFormError(null);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showFormError(null);

    try {
      parseRepoInput(repoInput.value);
    } catch (err) {
      repoInput.setAttribute("aria-invalid", "true");
      showFormError(err.message);
      repoInput.focus();
      return;
    }

    setLoading(true);
    try {
      const result = await checkAccess({ repoInput: repoInput.value, token: tokenInput.value });
      render(result);
    } catch (err) {
      if (err instanceof InputError) showFormError(err.message);
      else showFormError(`Something went wrong: ${err.message}`);
      results.hidden = true;
    } finally {
      setLoading(false);
    }
  });

  function setLoading(on) {
    submitBtn.disabled = on;
    submitBtn.classList.toggle("loading", on);
    submitBtn.querySelector(".label").textContent = on ? "Checking…" : "Check access";
  }

  function showFormError(message) {
    formError.hidden = !message;
    formError.textContent = message || "";
  }

  // Tiny element builder. Strings become text nodes, so API data is never parsed as HTML.
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else el.setAttribute(k, v);
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : String(child));
    }
    return el;
  }

  function render(result) {
    const sections = [
      renderVerdict(result.verdict),
      result.token.provided ? renderToken(result.token) : null,
      result.repo && result.repo.accessible ? renderRepo(result) : null,
      result.repo && result.repo.accessible && result.token.provided ? renderPermissions(result.repo) : null,
      result.probes.length ? renderProbes(result.probes) : null,
      result.rateLimit ? renderRateLimit(result.rateLimit) : null,
    ];
    results.replaceChildren(...sections.filter(Boolean));
    results.hidden = false;
    results.firstElementChild.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function renderVerdict(v) {
    const icon = { ok: "✓", warn: "!", bad: "✕" }[v.level];
    return h("div", { class: `card verdict ${v.level}`, role: "status" },
      h("span", { class: "icon", "aria-hidden": "true" }, icon),
      h("div", null,
        h("h2", null, v.title),
        v.detail ? h("p", null, v.detail) : null,
        v.link ? h("a", { class: "action", href: v.link.href, target: "_blank", rel: "noopener noreferrer" }, `${v.link.label} ↗`) : null
      )
    );
  }

  function row(label, value) {
    return [h("dt", null, label), h("dd", null, value)];
  }

  function renderToken(t) {
    let status;
    if (t.status === 401) status = "Invalid";
    else if (t.login) status = "Valid";
    else if (t.valid) status = "Valid (not a user token)";
    else status = `Unknown (HTTP ${t.status})`;

    let scopes = null;
    if (t.scopes) {
      scopes = t.scopes.length ? t.scopes.map((s) => h("span", { class: "pill" }, s)) : h("span", { class: "muted" }, "No scopes (public data only)");
    } else if (t.type && t.type.fineGrained) {
      scopes = h("span", { class: "muted" }, "Fine-grained tokens use per-repository permissions; see the checks below.");
    }

    return h("div", { class: "card" },
      h("h3", null, "Token"),
      h("dl", { class: "details" },
        row("Status", status),
        t.login ? row("Account", h("span", { class: "identity" },
          t.avatarUrl ? h("img", { src: t.avatarUrl, alt: "" }) : null,
          h("a", { href: `https://github.com/${t.login}`, target: "_blank", rel: "noopener noreferrer" }, `@${t.login}`),
          t.name ? h("span", { class: "muted" }, t.name) : null
        )) : null,
        t.type ? row("Type", t.type.label) : null,
        scopes ? row("Scopes", scopes) : null,
        t.expiresAt ? row("Expires", t.expiresAt) : null
      )
    );
  }

  function renderRepo(result) {
    const r = result.repo;
    return h("div", { class: "card" },
      h("h3", null, "Repository"),
      h("dl", { class: "details" },
        row("Name", h("a", { href: r.htmlUrl, target: "_blank", rel: "noopener noreferrer" }, r.fullName)),
        r.renamed ? row("Note", `Requested ${result.target.owner}/${result.target.repo}, which redirects here (renamed or transferred).`) : null,
        r.description ? row("Description", r.description) : null,
        row("Visibility", capitalize(r.visibility) + (r.archived ? " · archived" : "") + (r.fork ? " · fork" : "")),
        row("Default branch", h("code", null, r.defaultBranch)),
        r.role ? row("Your role", h("strong", null, r.role)) : null
      )
    );
  }

  function renderPermissions(r) {
    if (!r.permissions) return null;
    const levels = [["pull", "Read"], ["triage", "Triage"], ["push", "Write"], ["maintain", "Maintain"], ["admin", "Admin"]];
    return h("div", { class: "card" },
      h("h3", null, "Repository role permissions"),
      h("div", { class: "perm-grid" },
        levels.map(([key, label]) => {
          const yes = Boolean(r.permissions[key]);
          return h("div", { class: `perm ${yes ? "yes" : "no"}` },
            h("span", { class: "mark", "aria-hidden": "true" }, yes ? "✓" : "—"),
            label,
            h("span", { class: "visually-hidden" }, yes ? " allowed" : " not allowed")
          );
        })
      )
    );
  }

  function renderProbes(probes) {
    const label = { ok: "✓ Allowed", denied: "✕ Denied", na: "— N/A", error: "! Error" };
    return h("div", { class: "card" },
      h("h3", null, "What this token can read"),
      h("table", { class: "probes" },
        h("thead", null, h("tr", null, h("th", null, "Area"), h("th", null, "Result"), h("th", { class: "endpoint" }, "Endpoint"))),
        h("tbody", null, probes.map((p) =>
          h("tr", null,
            h("td", null, p.label),
            h("td", null,
              h("span", { class: `state ${p.state}` }, label[p.state]),
              p.state !== "ok" ? h("div", { class: "muted" }, p.note) : null
            ),
            h("td", { class: "endpoint" }, h("code", null, `GET …${p.path.split("?")[0]}`))
          )
        ))
      )
    );
  }

  function renderRateLimit(rl) {
    return h("p", { class: "muted", style: "margin:0;text-align:center" },
      `API rate limit: ${rl.remaining} of ${rl.limit} requests left`,
      rl.reset ? `, resets at ${rl.reset.toLocaleTimeString()}` : "",
      "."
    );
  }

  function capitalize(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
  }
})();
