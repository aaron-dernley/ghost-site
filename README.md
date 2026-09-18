# @aaronge/ghost-site

A swamp model extension for the Ghost Admin API — for any self-hosted or
Ghost(Pro) site. Server/droplet provisioning, DNS, and OS-level setup are out
of scope here; use `@swamp/digitalocean`, `@swamp/ssh`, or whatever fits your
infrastructure for that. This extension only talks to a Ghost site that's
already installed and running: site health, theme upload/activation, and a
JSON content export.

Auth uses Ghost's own Admin API Key scheme (`<id>:<secret>`) — every call
signs a short-lived JWT (HS256, 5 minute expiry) from that key using nothing
but Web Crypto, no extra dependency:

```ts
const token = await signAdminApiToken(globalArgs.adminApiKey);
// Authorization: Ghost <token>
```

## Installation

Source-loaded — no registry pull needed if you're working in this repo:

```sh
swamp model type search ghost-site --json
```

## Usage

Create a model instance, wiring the Admin API key through a vault (never
inline):

```sh
swamp vault put my-secrets GHOST_ADMIN_API_KEY "<id>:<secret>" --json

swamp model create @aaronge/ghost-site my-site \
  --global-arg 'apiUrl=https://example.com' \
  --global-arg 'adminApiKey=${{ vault.get("my-secrets", "GHOST_ADMIN_API_KEY") }}' \
  --json

swamp model method run my-site sync --json
```

## Global arguments

| Argument      | Type   | Required | Description                                                                             |
| ------------- | ------ | -------- | ----------------------------------------------------------------------------------------- |
| `apiUrl`      | string | Yes      | Ghost site base URL, e.g. `https://example.com` (no trailing slash).                      |
| `adminApiKey` | string | Yes      | Admin API Key (`<id>:<secret>`) from Ghost Admin → Settings → Integrations. Vault-wired.   |

## How it works

### `site` resource — `sync` method

`GET /site/` — title, description, url, Ghost version. Cheap health/drift
check; no auth actually required by Ghost for this endpoint, but the request
is signed anyway for consistency.

### `theme` resource — `uploadTheme` / `activateTheme` methods

`uploadTheme(zipPath)` — multipart `POST /themes/upload/`. Uploads but does
**not** activate; Ghost's own `gscan` linter runs server-side and any
warnings/errors land in the `theme` resource's `warnings`/`errors` fields.
Check those before calling `activateTheme(name)` (`PUT /themes/{name}/activate/`) —
`name` is the theme's declared name from the upload result, not the zip
filename.

### `export` file — `exportContent` method

`GET /db/` — full JSON content export. **As of Ghost 6.64 this returns 403
for Integration API keys** (`You do not have permission to exportContent db`)
— Ghost restricts full DB export to session-authenticated staff, not Admin
API tokens. The method is kept in case a future Ghost version or role change
lifts that restriction. Until then, an infra-level DB backup (mysqldump cron,
managed DB snapshots, etc.) is the real backup path for your deployment.

## Workflow

This extension has no workflow of its own — it's a plain model with no
scheduled/recurring behavior. If your deployment uses swamp for the
underlying server too (droplet, DNS, Node/MySQL/Nginx/Ghost-CLI install), that
belongs in its own workflow alongside wherever that infrastructure is
managed, not here.
