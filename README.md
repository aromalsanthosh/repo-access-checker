# Repo Access Checker

A small static web app that tells you what a GitHub token can do in a repository. Paste a repo link and a token, and it shows:

- **Whether the token is valid**, which account it belongs to, its type (classic, fine-grained, OAuth, GitHub App) and its OAuth scopes
- **Whether the repo is reachable**, plus its visibility, default branch, and whether it is archived or was renamed
- **The account's role** on the repo (Read / Triage / Write / Maintain / Admin)
- **What the token can actually read**: commits, issues, pull requests, Actions runs and webhooks. This matters for fine-grained tokens, whose grants can be narrower than the account's role.
- Clear explanations for common failures: bad credentials, 404 (missing *or* no access), SAML SSO authorization (with a link to authorize), and rate limits

Repository input can be `owner/repo`, any `https://github.com/...` URL (including `.git`, `/tree/...`, query strings), or an SSH remote like `git@github.com:owner/repo.git`. GitHub Enterprise Server hosts are supported too: their API is reached at `https://<host>/api/v3`.

## Privacy

There is no backend. The page calls the GitHub REST API directly from your browser, so the token goes only to GitHub. It is not stored in `localStorage`, cookies or the URL. Only read-only `GET` requests are made.

## Run locally

No build step or dependencies.

```bash
npm start          # serves the app at http://localhost:8080
```

Or open `index.html` directly, or serve the folder with any static file server. To prefill the repository field, link to `?repo=owner/name` (the token can never be prefilled).

## Deploy

Because it is plain HTML, CSS and JS, it can be hosted on GitHub Pages, Netlify, Vercel, Cloudflare Pages, or any static host. For GitHub Pages: go to **Settings → Pages**, choose "Deploy from a branch", and pick the branch and `/ (root)`.

## Tests

```bash
npm test
```

Unit tests (Node's built-in test runner) cover repo URL parsing, token type detection, and the access check flow against a mocked GitHub API.

## Project layout

```
index.html         page markup
styles.css         styles (light and dark mode, responsive)
src/github.js      core logic: input parsing, GitHub API calls, result interpretation (no DOM)
src/app.js         UI: form handling and result rendering
test/              unit tests
```
