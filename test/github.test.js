const test = require("node:test");
const assert = require("node:assert/strict");
const { parseRepoInput, detectTokenType, roleFromPermissions, parseSso, checkAccess, InputError } = require("../src/github.js");

test("parseRepoInput accepts common repo formats", () => {
  const expected = { host: "github.com", owner: "octo-org", repo: "hello.world" };
  for (const input of [
    "octo-org/hello.world",
    "https://github.com/octo-org/hello.world",
    "https://github.com/octo-org/hello.world.git",
    "https://www.github.com/octo-org/hello.world/tree/main/src?x=1#readme",
    "github.com/octo-org/hello.world",
    "git@github.com:octo-org/hello.world.git",
    "ssh://git@github.com/octo-org/hello.world.git",
    "https://api.github.com/repos/octo-org/hello.world",
    "  https://github.com/octo-org/hello.world/  ",
  ]) {
    assert.deepEqual(parseRepoInput(input), expected, input);
  }
});

test("parseRepoInput keeps enterprise hosts", () => {
  assert.deepEqual(parseRepoInput("https://git.example.com/team/app"), { host: "git.example.com", owner: "team", repo: "app" });
});

test("parseRepoInput rejects bad input", () => {
  for (const input of ["", "   ", "octocat", "https://github.com/octocat", "bad owner/repo", "-owner/repo", "owner/.."]) {
    assert.throws(() => parseRepoInput(input), InputError, input);
  }
});

test("detectTokenType recognizes prefixes", () => {
  assert.equal(detectTokenType("ghp_abc").label, "Personal access token (classic)");
  assert.equal(detectTokenType("github_pat_abc").fineGrained, true);
  assert.equal(detectTokenType("ghs_abc").label, "GitHub App installation token");
  assert.equal(detectTokenType(""), null);
});

test("roleFromPermissions picks the highest role", () => {
  assert.equal(roleFromPermissions({ admin: false, maintain: false, push: true, triage: true, pull: true }), "Write");
  assert.equal(roleFromPermissions({ admin: true, push: true, pull: true }), "Admin");
  assert.equal(roleFromPermissions({ pull: true }), "Read");
  assert.equal(roleFromPermissions(undefined), null);
});

test("parseSso extracts the authorization URL", () => {
  assert.deepEqual(parseSso("required; url=https://github.com/orgs/acme/sso?authorization_request=abc"), {
    required: true,
    url: "https://github.com/orgs/acme/sso?authorization_request=abc",
  });
  assert.equal(parseSso(null), null);
});

// --- checkAccess with a fake fetch -----------------------------------------

function response(status, body, headers = {}) {
  const h = new Map(Object.entries({ "x-ratelimit-limit": "5000", "x-ratelimit-remaining": "4999", ...headers }).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (k) => (h.has(k.toLowerCase()) ? h.get(k.toLowerCase()) : null) },
    json: async () => body,
  };
}

function fakeFetch(routes) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    const path = url.replace("https://api.github.com", "");
    const route = routes[path] || routes[path.split("?")[0]];
    if (!route) return response(404, { message: "Not Found" });
    return typeof route === "function" ? route() : route;
  };
  impl.calls = calls;
  return impl;
}

const repoBody = {
  full_name: "acme/app",
  html_url: "https://github.com/acme/app",
  private: true,
  visibility: "private",
  default_branch: "main",
  archived: false,
  fork: false,
  owner: { type: "Organization" },
  permissions: { admin: false, maintain: false, push: true, triage: true, pull: true },
};

test("checkAccess reports role, scopes and probes for a valid token", async () => {
  const fetchImpl = fakeFetch({
    "/user": response(200, { login: "octocat", name: "Mona" }, { "x-oauth-scopes": "repo, read:org" }),
    "/repos/acme/app": response(200, repoBody),
    "/repos/acme/app/commits": response(200, []),
    "/repos/acme/app/issues": response(410, { message: "Issues are disabled for this repo" }),
    "/repos/acme/app/pulls": response(200, []),
    "/repos/acme/app/actions/runs": response(200, { workflow_runs: [] }),
    "/repos/acme/app/hooks": response(404, { message: "Not Found" }),
  });

  const r = await checkAccess({ repoInput: "https://github.com/acme/app", token: " ghp_secret ", fetchImpl });

  assert.equal(r.token.login, "octocat");
  assert.deepEqual(r.token.scopes, ["repo", "read:org"]);
  assert.equal(r.repo.role, "Write");
  assert.equal(r.verdict.level, "ok");
  assert.match(r.verdict.title, /@octocat has Write access to acme\/app/);
  const states = Object.fromEntries(r.probes.map((p) => [p.key, p.state]));
  assert.deepEqual(states, { contents: "ok", issues: "na", pulls: "ok", actions: "ok", hooks: "denied" });
  // Token is trimmed and sent as a bearer token, and only to the GitHub API.
  for (const call of fetchImpl.calls) {
    assert.equal(call.init.headers.Authorization, "Bearer ghp_secret");
    assert.ok(call.url.startsWith("https://api.github.com/"));
  }
});

test("checkAccess stops on an invalid token", async () => {
  const fetchImpl = fakeFetch({ "/user": response(401, { message: "Bad credentials" }) });
  const r = await checkAccess({ repoInput: "acme/app", token: "ghp_nope", fetchImpl });
  assert.equal(r.verdict.title, "Token is invalid");
  assert.equal(fetchImpl.calls.length, 1);
});

test("checkAccess explains 404 as no access", async () => {
  const fetchImpl = fakeFetch({ "/user": response(200, { login: "octocat" }) });
  const r = await checkAccess({ repoInput: "acme/secret", token: "github_pat_x", fetchImpl });
  assert.equal(r.repo.accessible, false);
  assert.equal(r.verdict.level, "bad");
  assert.match(r.verdict.title, /No access/);
});

test("checkAccess surfaces SAML SSO requirement", async () => {
  const fetchImpl = fakeFetch({
    "/user": response(200, { login: "octocat" }),
    "/repos/acme/app": response(403, { message: "Resource protected by organization SAML enforcement." }, {
      "x-github-sso": "required; url=https://github.com/orgs/acme/sso?authorization_request=xyz",
    }),
  });
  const r = await checkAccess({ repoInput: "acme/app", token: "ghp_x", fetchImpl });
  assert.equal(r.verdict.title, "SSO authorization required");
  assert.equal(r.verdict.link.href, "https://github.com/orgs/acme/sso?authorization_request=xyz");
});

test("checkAccess works anonymously for public repos", async () => {
  const fetchImpl = fakeFetch({
    "/repos/acme/app": response(200, { ...repoBody, private: false, visibility: "public", permissions: undefined }),
  });
  const r = await checkAccess({ repoInput: "acme/app", token: "", fetchImpl });
  assert.equal(r.verdict.level, "ok");
  assert.match(r.verdict.title, /is public/);
  assert.ok(fetchImpl.calls.every((c) => !("Authorization" in c.init.headers)));
});

test("checkAccess reports rate limiting", async () => {
  const fetchImpl = fakeFetch({
    "/repos/acme/app": response(403, { message: "API rate limit exceeded" }, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000" }),
  });
  const r = await checkAccess({ repoInput: "acme/app", token: "", fetchImpl });
  assert.equal(r.verdict.title, "Rate limit exceeded");
});

test("checkAccess reports network failures", async () => {
  const r = await checkAccess({ repoInput: "acme/app", token: "", fetchImpl: async () => { throw new TypeError("Failed to fetch"); } });
  assert.equal(r.verdict.title, "Couldn't reach GitHub");
});

test("checkAccess rejects tokens containing whitespace", async () => {
  await assert.rejects(checkAccess({ repoInput: "acme/app", token: "ghp_a b", fetchImpl: fakeFetch({}) }), InputError);
});
