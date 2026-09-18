/**
 * Ghost Admin API client for any self-hosted or Ghost(Pro) site — droplet/
 * server provisioning, DNS, and OS-level setup are out of scope for this
 * model (use `@swamp/digitalocean`, `@swamp/ssh`, or whatever fits your
 * infrastructure). This model only talks to the Ghost Admin API of a site
 * that's already installed and running: site health, theme upload/
 * activation, and a JSON content export.
 *
 * Auth: Ghost Admin API Keys are `<id>:<secret>` (secret is hex-encoded).
 * Every request signs a short-lived JWT (HS256, 5 minute expiry) from that
 * key — see https://ghost.org/docs/admin-api/#token-authentication. No
 * dependency pulled in for this; it's a handful of Web Crypto calls.
 *
 * @module
 */
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  apiUrl: z.url().describe(
    "Ghost site base URL, e.g. https://example.com (no trailing slash).",
  ),
  adminApiKey: z.string().meta({ sensitive: true }).describe(
    "Ghost Admin API Key in '<id>:<secret>' format, from Settings → " +
      "Integrations → (a custom integration) in Ghost Admin. Wire with a " +
      "vault.get(...) expression — never inline.",
  ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// Explicit fields, no .passthrough() — passthrough blocks CEL expression
// validation on unlisted attributes (see extension/references/model/api.md,
// "Schema requirement"). Fields below are confirmed live against a running
// Ghost 6.64 site (GET /site/); anything Ghost adds/removes still lands in
// the stored data (Zod warns on mismatch, doesn't throw), it just won't be
// CEL-addressable until declared here.
const SiteSchema = z.object({
  title: z.string(),
  description: z.string().nullable().optional(),
  logo: z.string().nullable().optional(),
  icon: z.string().nullable().optional(),
  cover_image: z.string().nullable().optional(),
  accent_color: z.string().nullable().optional(),
  locale: z.string().optional(),
  timezone: z.string().optional(),
  url: z.string(),
  version: z.string(),
  allow_external_signup: z.boolean().optional(),
  site_uuid: z.string().optional(),
});

// Theme fields are per Ghost's documented Admin API shape, NOT live-verified
// (uploadTheme/activateTheme were never exercised against a real theme — no
// zip existed to test with when this was written). Same passthrough note as
// above applies if Ghost's actual shape differs.
const ThemeWarningSchema = z.object({
  level: z.string().optional(),
  rule: z.string().optional(),
  code: z.string().optional(),
  details: z.string().optional(),
});

const ThemeSchema = z.object({
  name: z.string(),
  package: z.record(z.string(), z.unknown()).nullable().optional(),
  active: z.boolean(),
  templates: z.array(z.string()).optional(),
  warnings: z.array(ThemeWarningSchema).optional(),
  errors: z.array(ThemeWarningSchema).optional(),
});

/** Signs a Ghost Admin API token (HS256 JWT, 5 minute expiry) from an `<id>:<secret>` key. */
export async function signAdminApiToken(adminApiKey: string): Promise<string> {
  const sepIndex = adminApiKey.indexOf(":");
  if (sepIndex < 1 || sepIndex === adminApiKey.length - 1) {
    throw new Error(
      "adminApiKey must be in '<id>:<secret>' format — copy it from " +
        "Ghost Admin → Settings → Integrations.",
    );
  }
  const id = adminApiKey.slice(0, sepIndex);
  const secretHex = adminApiKey.slice(sepIndex + 1);
  if (!/^[0-9a-fA-F]+$/.test(secretHex) || secretHex.length % 2 !== 0) {
    throw new Error("adminApiKey secret half must be hex-encoded.");
  }

  const encoder = new TextEncoder();
  const base64url = (bytes: Uint8Array) => {
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(
      /=+$/,
      "",
    );
  };
  const base64urlJson = (obj: unknown) =>
    base64url(encoder.encode(JSON.stringify(obj)));

  const now = Math.floor(Date.now() / 1000);
  const headerB64 = base64urlJson({ alg: "HS256", typ: "JWT", kid: id });
  const payloadB64 = base64urlJson({
    iat: now,
    exp: now + 300,
    aud: "/admin/",
  });
  const signingInput = `${headerB64}.${payloadB64}`;

  const keyBytes = new Uint8Array(
    secretHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
  );
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64url(new Uint8Array(signature))}`;
}

/** Thin wrapper: signs a fresh token per call (5 min expiry, never reused) and hits `<apiUrl>/ghost/api/admin<path>`. */
async function ghostFetch(
  globalArgs: GlobalArgs,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const token = await signAdminApiToken(globalArgs.adminApiKey);
  const url = `${globalArgs.apiUrl.replace(/\/+$/, "")}/ghost/api/admin${path}`;
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Ghost ${token}`);
  return await fetch(url, { ...init, headers });
}

async function readErrorMessage(res: Response): Promise<string> {
  const text = await res.text();
  try {
    const body = JSON.parse(text);
    const first = body?.errors?.[0];
    if (first?.message) return first.message as string;
  } catch {
    // fall through to raw text
  }
  return text.slice(0, 500);
}

/** Model definition for managing the Ghost site's Admin API surface: site health, theme upload/activation, content export. */
export const model = {
  type: "@aaronge/ghost-site",
  version: "2026.09.18.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    site: {
      description:
        "Site info from GET /site/ — title, description, url, Ghost version.",
      schema: SiteSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    theme: {
      description:
        "Result of a theme upload or activation, including gscan warnings/errors.",
      schema: ThemeSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  files: {
    export: {
      description:
        "Full JSON content export from GET /db/ — app-level backup, a useful complement to whatever infra-level DB backup you run.",
      contentType: "application/json",
      lifetime: "30d",
      garbageCollection: 5,
    },
  },
  methods: {
    sync: {
      description:
        "Fetch current site info (title, description, url, version).",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            name: string,
            data: Record<string, unknown>,
          ) => Promise<{ name: string }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ) => {
        context.logger.info("Fetching site info from {apiUrl}", {
          apiUrl: context.globalArgs.apiUrl,
        });
        const res = await ghostFetch(context.globalArgs, "/site/");
        if (!res.ok) {
          throw new Error(
            `GET /site/ failed (${res.status}): ${await readErrorMessage(res)}`,
          );
        }
        const body = await res.json() as { site: Record<string, unknown> };
        const handle = await context.writeResource(
          "site",
          "current",
          body.site,
        );
        context.logger.info("Fetched site info for {title}", {
          title: body.site.title,
        });
        return { dataHandles: [handle] };
      },
    },
    updateSettings: {
      description:
        "Update site branding settings via PUT /settings/ (title, description/tagline, accent_color). Only the fields provided are changed.",
      arguments: z.object({
        title: z.string().optional().describe("Site title."),
        description: z.string().optional().describe(
          "Site tagline/description.",
        ),
        accent_color: z.string().optional().describe(
          "Accent color, e.g. #f0a63c.",
        ),
      }),
      execute: async (
        args: { title?: string; description?: string; accent_color?: string },
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            name: string,
            data: Record<string, unknown>,
          ) => Promise<{ name: string }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ) => {
        const settings = Object.entries(args)
          .filter(([, value]) => value !== undefined)
          .map(([key, value]) => ({ key, value }));
        if (settings.length === 0) {
          throw new Error(
            "updateSettings called with no fields to update — pass at " +
              "least one of title, description, accent_color.",
          );
        }
        const keys = settings.map((s) => s.key).join(", ");
        context.logger.info("Updating site settings: {keys}", { keys });

        const res = await ghostFetch(context.globalArgs, "/settings/", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ settings }),
        });
        if (!res.ok) {
          throw new Error(
            `PUT /settings/ failed (${res.status}): ${await readErrorMessage(
              res,
            )}`,
          );
        }

        // /settings/ responds with a flat key/value list, a different shape
        // than /site/ (which sync() and the "site" resource schema expect)
        // — re-fetch /site/ so the stored resource stays consistent.
        const siteRes = await ghostFetch(context.globalArgs, "/site/");
        if (!siteRes.ok) {
          throw new Error(
            `Settings updated, but GET /site/ failed to refresh (${siteRes.status}): ${await readErrorMessage(
              siteRes,
            )}`,
          );
        }
        const body = await siteRes.json() as { site: Record<string, unknown> };
        const handle = await context.writeResource(
          "site",
          "current",
          body.site,
        );
        context.logger.info("Site settings updated: {keys}", { keys });
        return { dataHandles: [handle] };
      },
    },
    uploadTheme: {
      description:
        "Upload a theme zip via POST /themes/upload/. Does not activate it — run activateTheme afterward.",
      arguments: z.object({
        zipPath: z.string().describe("Local path to the theme .zip file."),
      }),
      execute: async (
        args: { zipPath: string },
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            name: string,
            data: Record<string, unknown>,
          ) => Promise<{ name: string }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ) => {
        context.logger.info("Uploading theme from {zipPath}", {
          zipPath: args.zipPath,
        });
        const zipBytes = await Deno.readFile(args.zipPath);
        const form = new FormData();
        form.append(
          "file",
          new Blob([zipBytes], { type: "application/zip" }),
          args.zipPath.split("/").pop() ?? "theme.zip",
        );
        const res = await ghostFetch(context.globalArgs, "/themes/upload/", {
          method: "POST",
          body: form,
        });
        if (!res.ok) {
          throw new Error(
            `POST /themes/upload/ failed (${res.status}): ${await readErrorMessage(
              res,
            )}`,
          );
        }
        const body = await res.json() as {
          themes: Array<Record<string, unknown>>;
        };
        if (!body.themes || body.themes.length === 0) {
          throw new Error(
            "POST /themes/upload/ succeeded (2xx) but the response contained " +
              "no theme data — unexpected Ghost Admin API response shape.",
          );
        }
        const theme = body.themes[0];
        const handle = await context.writeResource(
          "theme",
          `upload-${theme.name}`,
          theme,
        );
        context.logger.info("Uploaded theme {name}", { name: theme.name });
        return { dataHandles: [handle] };
      },
    },
    activateTheme: {
      description:
        "Activate a previously uploaded theme via PUT /themes/{name}/activate/.",
      arguments: z.object({
        name: z.string().describe(
          "Theme name (the 'name' field from uploadTheme's result, not the zip filename).",
        ),
      }),
      execute: async (
        args: { name: string },
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            name: string,
            data: Record<string, unknown>,
          ) => Promise<{ name: string }>;
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ) => {
        context.logger.info("Activating theme {name}", { name: args.name });
        const res = await ghostFetch(
          context.globalArgs,
          `/themes/${encodeURIComponent(args.name)}/activate/`,
          { method: "PUT" },
        );
        if (!res.ok) {
          throw new Error(
            `PUT /themes/${args.name}/activate/ failed (${res.status}): ${await readErrorMessage(
              res,
            )}`,
          );
        }
        const body = await res.json() as {
          themes: Array<Record<string, unknown>>;
        };
        if (!body.themes || body.themes.length === 0) {
          throw new Error(
            `PUT /themes/${args.name}/activate/ succeeded (2xx) but the ` +
              "response contained no theme data — unexpected Ghost Admin " +
              "API response shape.",
          );
        }
        const theme = body.themes[0];
        const handle = await context.writeResource("theme", "active", theme);
        context.logger.info("Activated theme {name}", { name: theme.name });
        return { dataHandles: [handle] };
      },
    },
    exportContent: {
      description:
        "Full JSON content export via GET /db/. NOTE: as of Ghost 6.64, " +
        "this endpoint returns 403 for Integration API keys ('You do not " +
        "have permission to exportContent db') — Ghost restricts full DB " +
        "export to session-authenticated staff, not Admin API tokens. Kept " +
        "here in case a future Ghost version or role change lifts that " +
        "restriction; until then an infra-level DB backup (mysqldump cron, " +
        "managed DB snapshots, etc.) is the real backup path.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: {
          globalArgs: GlobalArgs;
          createFileWriter: (
            specName: string,
            name: string,
          ) => {
            writeText: (text: string) => Promise<{ name: string }>;
          };
          logger: {
            info: (msg: string, props?: Record<string, unknown>) => void;
          };
        },
      ) => {
        context.logger.info("Exporting full content DB from {apiUrl}", {
          apiUrl: context.globalArgs.apiUrl,
        });
        const res = await ghostFetch(context.globalArgs, "/db/");
        if (!res.ok) {
          throw new Error(
            `GET /db/ failed (${res.status}): ${await readErrorMessage(res)}`,
          );
        }
        const text = await res.text();
        const writer = context.createFileWriter(
          "export",
          `export-${new Date().toISOString().slice(0, 10)}`,
        );
        const handle = await writer.writeText(text);
        context.logger.info("Content export written", {
          bytes: text.length,
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
