/*
 * Core logic for the repo access checker. Has no DOM dependencies so it can be
 * loaded as a classic <script> in the browser (exposes window.RepoAccess) or
 * required from Node for tests.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.RepoAccess = api;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
  const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;

  class InputError extends Error {}

  /**
   * Parse anything that identifies a repo: "owner/repo", an https URL (with or
   * without .git, extra path segments, query or hash), or an SSH remote.
   * Returns { host, owner, repo }.
   */
  function parseRepoInput(input) {
    let s = String(input || "").trim();
    if (!s) throw new InputError("Enter a repository link or owner/repo.");

    let host = "github.com";
    let path;

    const scpLike = s.match(/^[\w.-]+@([^:/]+):(.+)$/); // git@github.com:owner/repo.git
    if (scpLike) {
      host = scpLike[1];
      path = scpLike[2];
    } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
      let url;
      try {
        url = new URL(s);
      } catch {
        throw new InputError("That doesn't look like a valid URL.");
      }
      host = url.hostname;
      path = url.pathname;
    } else if (/^[^/\s]+\.[^/\s]+\//.test(s)) {
      // github.com/owner/repo without a scheme
      const slash = s.indexOf("/");
      host = s.slice(0, slash);
      path = s.slice(slash + 1).split(/[?#]/)[0];
    } else {
      path = s.split(/[?#]/)[0];
    }

    host = host.toLowerCase().replace(/^www\./, "");
    if (host === "api.github.com") host = "github.com";

    let parts = path.split("/").filter(Boolean);
    if (parts[0] === "repos" && parts.length >= 3) parts = parts.slice(1); // API URL
    if (parts.length < 2) {
      throw new InputError("Couldn't find an owner and repository name. Use a link like https://github.com/owner/repo.");
    }

    const owner = decodeURIComponent(parts[0]);
    const repo = decodeURIComponent(parts[1]).replace(/\.git$/i, "");

    if (!OWNER_RE.test(owner)) throw new InputError(`"${owner}" isn't a valid GitHub owner name.`);
    if (!REPO_RE.test(repo) || repo === "." || repo === "..") {
      throw new InputError(`"${repo}" isn't a valid repository name.`);
    }

    return { host, owner, repo };
  }

  function apiBaseFor(host) {
    return host === "github.com" ? "https://api.github.com" : `https://${host}/api/v3`;
  }

  const TOKEN_TYPES = [
    ["github_pat_", "Fine-grained personal access token"],
    ["ghp_", "Personal access token (classic)"],
    ["gho_", "OAuth app token"],
    ["ghu_", "GitHub App user token"],
    ["ghs_", "GitHub App installation token"],
    ["ghr_", "GitHub App refresh token"],
  ];

  function detectTokenType(token) {
    if (!token) return null;
    for (const [prefix, label] of TOKEN_TYPES) {
      if (token.startsWith(prefix)) return { prefix, label, fineGrained: prefix === "github_pat_" };
    }
    if (/^[0-9a-f]{40}$/i.test(token)) return { prefix: "", label: "Legacy token (classic format)", fineGrained: false };
    return { prefix: "", label: "Unrecognized token format", fineGrained: false };
  }

  function validateToken(token) {
    const t = String(token || "").trim();
    if (/\s/.test(t)) throw new InputError("The token contains whitespace. Paste only the token itself.");
    return t;
  }

  /** Highest role implied by the `permissions` object of GET /repos/{owner}/{repo}. */
  function roleFromPermissions(p) {
    if (!p) return null;
    if (p.admin) return "Admin";
    if (p.maintain) return "Maintain";
    if (p.push) return "Write";
    if (p.triage) return "Triage";
    if (p.pull) return "Read";
    return "None";
  }

  function parseSso(header) {
    if (!header) return null;
    const m = header.match(/url=([^;\s]+)/);
    return { required: /required/i.test(header), url: m ? m[1] : null };
  }

  function rateLimitFrom(headers) {
    const limit = headers.get("x-ratelimit-limit");
    if (limit === null) return null;
    const reset = Number(headers.get("x-ratelimit-reset"));
    return {
      limit: Number(limit),
      remaining: Number(headers.get("x-ratelimit-remaining")),
      reset: reset ? new Date(reset * 1000) : null,
    };
  }

  function isRateLimited(res) {
    return (res.status === 403 || res.status === 429) && res.headers.get("x-ratelimit-remaining") === "0";
  }

  // Read-only endpoints used to see what the token can actually do. For
  // fine-grained tokens the repo `permissions` object reflects the account's
  // role, not the token's grants, so these probes fill in the gap.
  const PROBES = [
    { key: "contents", label: "Code (commits)", path: "/commits?per_page=1", permission: "Contents: read" },
    { key: "issues", label: "Issues", path: "/issues?per_page=1", permission: "Issues: read" },
    { key: "pulls", label: "Pull requests", path: "/pulls?per_page=1", permission: "Pull requests: read" },
    { key: "actions", label: "Actions runs", path: "/actions/runs?per_page=1", permission: "Actions: read" },
    { key: "hooks", label: "Webhooks (admin only)", path: "/hooks?per_page=1", permission: "Webhooks: read" },
  ];

  async function readJson(res) {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }

  function interpretProbe(probe, res, body) {
    const message = body && body.message ? body.message : "";
    if (res.ok) return { state: "ok", note: "Allowed" };
    if (res.status === 409 && /empty/i.test(message)) return { state: "ok", note: "Allowed (repository is empty)" };
    if (res.status === 410) return { state: "na", note: "Disabled for this repository" };
    if (isRateLimited(res)) return { state: "error", note: "Rate limited" };
    if (res.status === 403 || res.status === 404) {
      const needed = res.headers.get("x-accepted-github-permissions");
      return { state: "denied", note: needed ? `Denied (needs ${needed})` : `Denied (likely needs ${probe.permission})` };
    }
    return { state: "error", note: `HTTP ${res.status}${message ? `: ${message}` : ""}` };
  }

  /**
   * Run the full access check. `fetchImpl` is injectable for tests.
   * Never throws for HTTP failures; they are reported in the result.
   */
  async function checkAccess({ repoInput, token, fetchImpl }) {
    const doFetch = fetchImpl || (typeof fetch !== "undefined" ? fetch.bind(globalThis) : null);
    const target = parseRepoInput(repoInput);
    const cleanToken = validateToken(token);
    const apiBase = apiBaseFor(target.host);
    const repoPath = `/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}`;

    const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
    if (cleanToken) headers.Authorization = `Bearer ${cleanToken}`;
    const get = (path) => doFetch(apiBase + path, { headers, cache: "no-store" });

    const result = {
      target: { ...target, apiBase, webUrl: `https://${target.host}/${target.owner}/${target.repo}` },
      token: { provided: Boolean(cleanToken), type: detectTokenType(cleanToken) },
      repo: null,
      probes: [],
      rateLimit: null,
      verdict: null,
    };

    try {
      // 1. Who does the token belong to?
      if (cleanToken) {
        const res = await get("/user");
        const body = await readJson(res);
        result.rateLimit = rateLimitFrom(res.headers) || result.rateLimit;
        const scopes = res.headers.get("x-oauth-scopes");
        const expiration = res.headers.get("github-authentication-token-expiration");
        Object.assign(result.token, {
          status: res.status,
          valid: res.ok || (res.status === 403 && !isRateLimited(res)),
          login: res.ok && body ? body.login : null,
          name: res.ok && body ? body.name : null,
          avatarUrl: res.ok && body ? body.avatar_url : null,
          scopes: scopes === null ? null : scopes.split(",").map((s) => s.trim()).filter(Boolean),
          expiresAt: expiration || null,
        });
        if (res.status === 401) {
          result.verdict = { level: "bad", title: "Token is invalid", detail: "GitHub rejected this token (401 Bad credentials). It may be mistyped, revoked, or expired." };
          return result;
        }
        if (isRateLimited(res)) {
          result.verdict = rateLimitVerdict(result.rateLimit);
          return result;
        }
        // GitHub App installation tokens can't call /user (403); that's fine.
      }

      // 2. Can the token see the repository, and with which role?
      const res = await get(repoPath);
      const body = await readJson(res);
      result.rateLimit = rateLimitFrom(res.headers) || result.rateLimit;
      const sso = parseSso(res.headers.get("x-github-sso"));

      if (res.ok && body) {
        result.repo = {
          accessible: true,
          fullName: body.full_name,
          htmlUrl: body.html_url,
          description: body.description,
          visibility: body.visibility || (body.private ? "private" : "public"),
          private: body.private,
          archived: body.archived,
          fork: body.fork,
          defaultBranch: body.default_branch,
          ownerType: body.owner && body.owner.type,
          permissions: body.permissions || null,
          role: roleFromPermissions(body.permissions),
          renamed: body.full_name && body.full_name.toLowerCase() !== `${target.owner}/${target.repo}`.toLowerCase(),
        };
      } else {
        result.repo = { accessible: false, status: res.status, message: body && body.message, sso };
        result.verdict = failureVerdict(res, body, sso, result);
        return result;
      }

      // 3. Probe individual read-only endpoints.
      result.probes = await Promise.all(
        PROBES.map(async (probe) => {
          try {
            const pres = await get(repoPath + probe.path);
            const pbody = await readJson(pres);
            return { ...probe, status: pres.status, ...interpretProbe(probe, pres, pbody) };
          } catch (err) {
            return { ...probe, status: 0, state: "error", note: networkMessage(err) };
          }
        })
      );

      result.verdict = successVerdict(result);
      return result;
    } catch (err) {
      result.verdict = { level: "bad", title: "Couldn't reach GitHub", detail: networkMessage(err) };
      return result;
    }
  }

  function networkMessage(err) {
    return `Network error: ${err && err.message ? err.message : err}. Check your connection, or whether a browser extension or firewall is blocking the GitHub API.`;
  }

  function rateLimitVerdict(rl) {
    const when = rl && rl.reset ? ` It resets at ${rl.reset.toLocaleTimeString()}.` : "";
    return { level: "warn", title: "Rate limit exceeded", detail: `GitHub's API rate limit has been reached.${when} Adding a token raises the limit.` };
  }

  function failureVerdict(res, body, sso, result) {
    const name = `${result.target.owner}/${result.target.repo}`;
    if (isRateLimited(res)) return rateLimitVerdict(result.rateLimit);
    if (sso && sso.required) {
      return {
        level: "warn",
        title: "SSO authorization required",
        detail: `The organization that owns ${name} uses SAML single sign-on. Authorize this token for the organization, then try again.`,
        link: sso.url ? { href: sso.url, label: "Authorize token for SSO" } : null,
      };
    }
    if (res.status === 404) {
      return {
        level: "bad",
        title: "No access (or repository doesn't exist)",
        detail: result.token.provided
          ? `GitHub returns 404 both for repositories that don't exist and for private ones this token can't see. Check the name, that your account has access to ${name}, and — for fine-grained tokens — that the repository is selected and the resource owner is correct.`
          : `${name} doesn't exist or is private. Add a token to check access to private repositories.`,
      };
    }
    if (res.status === 403) {
      return {
        level: "bad",
        title: "Access forbidden",
        detail: (body && body.message) || "GitHub refused access to this repository with this token (403).",
      };
    }
    if (res.status === 401) {
      return { level: "bad", title: "Token is invalid", detail: "GitHub rejected this token (401 Bad credentials)." };
    }
    return { level: "bad", title: `Unexpected response (HTTP ${res.status})`, detail: (body && body.message) || "GitHub returned an unexpected error." };
  }

  function successVerdict(result) {
    const r = result.repo;
    const who = result.token.login ? `@${result.token.login}` : result.token.provided ? "This token" : "Anonymous access";
    if (!result.token.provided) {
      return { level: "ok", title: `${r.fullName} is public`, detail: "Anyone can read it. Add a token to see what your account is allowed to do." };
    }
    const role = r.role && r.role !== "None" ? r.role : "Read";
    const writeNote = r.archived ? " The repository is archived, so it's read-only for everyone." : "";
    const fgNote = result.token.type && result.token.type.fineGrained
      ? " For fine-grained tokens the role reflects your account; the checks below show what the token itself can reach."
      : "";
    return { level: "ok", title: `${who} has ${role} access to ${r.fullName}`, detail: `${writeNote}${fgNote}`.trim() };
  }

  return {
    InputError,
    parseRepoInput,
    apiBaseFor,
    detectTokenType,
    validateToken,
    roleFromPermissions,
    parseSso,
    checkAccess,
    PROBES,
  };
});
