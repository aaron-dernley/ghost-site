// Run with `deno test -A`.
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  createModelTestContext,
  withMockedFetch,
} from "jsr:@swamp-club/swamp-testing@0.20260824.32";
import { model, signAdminApiToken } from "./ghost_site.ts";

// createModelTestContext() returns a MethodContext typed with a default
// Record<string, unknown> globalArgs — narrower than each execute()'s own
// inline context type. This cast bridges that gap; the contextual type at
// each call site (inferred from execute()'s own parameter type) fills in T.
function asContext<T>(context: unknown): T {
  return context as T;
}

const GLOBAL_ARGS = {
  apiUrl: "https://example.com",
  adminApiKey: "abcdef0123456789abcdef01:" + "00".repeat(32),
};

// --- signAdminApiToken -----------------------------------------------------

Deno.test("signAdminApiToken produces a three-part JWT with the right header/payload shape", async () => {
  const token = await signAdminApiToken(GLOBAL_ARGS.adminApiKey);
  const parts = token.split(".");
  assertEquals(parts.length, 3);

  const decode = (b64url: string) => {
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - b64.length % 4) % 4);
    return JSON.parse(atob(padded));
  };

  const header = decode(parts[0]);
  assertEquals(header.alg, "HS256");
  assertEquals(header.typ, "JWT");
  assertEquals(header.kid, "abcdef0123456789abcdef01");

  const payload = decode(parts[1]);
  assertEquals(payload.aud, "/admin/");
  assertEquals(payload.exp - payload.iat, 300);
});

Deno.test("signAdminApiToken throws on a key with no colon", async () => {
  await assertRejects(
    () => signAdminApiToken("not-a-valid-key"),
    Error,
    "'<id>:<secret>' format",
  );
});

Deno.test("signAdminApiToken throws on a non-hex secret", async () => {
  await assertRejects(
    () => signAdminApiToken("abc123:not-hex-at-all"),
    Error,
    "hex-encoded",
  );
});

// --- sync --------------------------------------------------------------

Deno.test("sync writes the site resource on success", async () => {
  await withMockedFetch(
    (req) => {
      assert(req.url.endsWith("/ghost/api/admin/site/"));
      assert(req.headers.get("Authorization")?.startsWith("Ghost "));
      return Response.json({
        site: {
          title: "Example Site",
          url: "https://example.com/",
          version: "6.64",
        },
      });
    },
    async () => {
      const { context, getWrittenResources } = createModelTestContext({
        globalArgs: GLOBAL_ARGS,
        methodName: "sync",
      });
      await model.methods.sync.execute({}, asContext(context));

      const written = getWrittenResources();
      assertEquals(written.length, 1);
      assertEquals(written[0].specName, "site");
      const data = written[0].data as Record<string, unknown>;
      assertEquals(data.title, "Example Site");
    },
  );
});

Deno.test("sync logs on entry and completion", async () => {
  await withMockedFetch(
    () => Response.json({ site: { title: "Example Site" } }),
    async () => {
      const { context, getLogsByLevel } = createModelTestContext({
        globalArgs: GLOBAL_ARGS,
        methodName: "sync",
      });
      await model.methods.sync.execute({}, asContext(context));

      const infoLogs = getLogsByLevel("info");
      assert(infoLogs.length >= 2, "expected an entry and a completion log");
    },
  );
});

Deno.test("sync throws a descriptive error on a non-2xx response", async () => {
  await withMockedFetch(
    () =>
      Response.json({ errors: [{ message: "Authorization failed" }] }, {
        status: 401,
      }),
    async () => {
      const { context } = createModelTestContext({
        globalArgs: GLOBAL_ARGS,
        methodName: "sync",
      });
      await assertRejects(
        () => model.methods.sync.execute({}, asContext(context)),
        Error,
        "Authorization failed",
      );
    },
  );
});

// --- updateSettings ---------------------------------------------------------

Deno.test("updateSettings PUTs only the provided fields, then re-fetches /site/", async () => {
  let settingsBody: unknown;
  await withMockedFetch(
    async (req) => {
      if (req.url.endsWith("/ghost/api/admin/settings/")) {
        assertEquals(req.method, "PUT");
        settingsBody = await req.json();
        return Response.json({ settings: [] });
      }
      if (req.url.endsWith("/ghost/api/admin/site/")) {
        return Response.json({
          site: { title: "New Title", description: "New tagline" },
        });
      }
      throw new Error(`unexpected request: ${req.url}`);
    },
    async () => {
      const { context, getWrittenResources } = createModelTestContext({
        globalArgs: GLOBAL_ARGS,
        methodName: "updateSettings",
      });
      await model.methods.updateSettings.execute(
        { title: "New Title", description: "New tagline" },
        asContext(context),
      );

      assertEquals(settingsBody, {
        settings: [
          { key: "title", value: "New Title" },
          { key: "description", value: "New tagline" },
        ],
      });
      const written = getWrittenResources();
      assertEquals(
        (written[0].data as Record<string, unknown>).title,
        "New Title",
      );
    },
  );
});

Deno.test("updateSettings throws when called with no fields", async () => {
  const { context } = createModelTestContext({
    globalArgs: GLOBAL_ARGS,
    methodName: "updateSettings",
  });
  await assertRejects(
    () => model.methods.updateSettings.execute({}, asContext(context)),
    Error,
    "no fields to update",
  );
});

// --- uploadTheme ---------------------------------------------------------

Deno.test("uploadTheme writes the theme resource on success", async () => {
  await withMockedFetch(
    (req) => {
      assert(req.url.endsWith("/ghost/api/admin/themes/upload/"));
      assertEquals(req.method, "POST");
      return Response.json({
        themes: [{ name: "my-theme", active: false, warnings: [], errors: [] }],
      });
    },
    async () => {
      const tmp = await Deno.makeTempFile({ suffix: ".zip" });
      try {
        await Deno.writeFile(tmp, new Uint8Array([0x50, 0x4b, 0x03, 0x04]));
        const { context, getWrittenResources } = createModelTestContext({
          globalArgs: GLOBAL_ARGS,
          methodName: "uploadTheme",
        });
        await model.methods.uploadTheme.execute(
          { zipPath: tmp },
          asContext(context),
        );

        const written = getWrittenResources();
        assertEquals(written[0].specName, "theme");
        assertEquals(written[0].name, "upload-my-theme");
      } finally {
        await Deno.remove(tmp);
      }
    },
  );
});

Deno.test("uploadTheme throws a clear error when the API returns no theme data", async () => {
  await withMockedFetch(
    () => Response.json({ themes: [] }),
    async () => {
      const tmp = await Deno.makeTempFile({ suffix: ".zip" });
      try {
        await Deno.writeFile(tmp, new Uint8Array([0x50, 0x4b, 0x03, 0x04]));
        const { context } = createModelTestContext({
          globalArgs: GLOBAL_ARGS,
          methodName: "uploadTheme",
        });
        await assertRejects(
          () =>
            model.methods.uploadTheme.execute(
              { zipPath: tmp },
              asContext(context),
            ),
          Error,
          "no theme data",
        );
      } finally {
        await Deno.remove(tmp);
      }
    },
  );
});

// --- activateTheme ---------------------------------------------------------

Deno.test("activateTheme writes the theme resource under the 'active' instance name", async () => {
  await withMockedFetch(
    (req) => {
      assert(req.url.endsWith("/ghost/api/admin/themes/my-theme/activate/"));
      assertEquals(req.method, "PUT");
      return Response.json({ themes: [{ name: "my-theme", active: true }] });
    },
    async () => {
      const { context, getWrittenResources } = createModelTestContext({
        globalArgs: GLOBAL_ARGS,
        methodName: "activateTheme",
      });
      await model.methods.activateTheme.execute(
        { name: "my-theme" },
        asContext(context),
      );

      const written = getWrittenResources();
      assertEquals(written[0].specName, "theme");
      assertEquals(written[0].name, "active");
      assertEquals((written[0].data as Record<string, unknown>).active, true);
    },
  );
});

Deno.test("activateTheme throws a clear error when the API returns no theme data", async () => {
  await withMockedFetch(
    () => Response.json({ themes: [] }),
    async () => {
      const { context } = createModelTestContext({
        globalArgs: GLOBAL_ARGS,
        methodName: "activateTheme",
      });
      await assertRejects(
        () =>
          model.methods.activateTheme.execute(
            { name: "my-theme" },
            asContext(context),
          ),
        Error,
        "no theme data",
      );
    },
  );
});

// --- exportContent ---------------------------------------------------------

Deno.test("exportContent writes the export file on success", async () => {
  await withMockedFetch(
    (req) => {
      assert(req.url.endsWith("/ghost/api/admin/db/"));
      return new Response(JSON.stringify({ db: [{ data: {} }] }), {
        headers: { "Content-Type": "application/json" },
      });
    },
    async () => {
      const { context, getWrittenFiles } = createModelTestContext({
        globalArgs: GLOBAL_ARGS,
        methodName: "exportContent",
      });
      await model.methods.exportContent.execute({}, asContext(context));

      const written = getWrittenFiles();
      assertEquals(written.length, 1);
      assertEquals(written[0].specName, "export");
    },
  );
});

Deno.test("exportContent surfaces Ghost's 403 (Integration keys can't export db)", async () => {
  await withMockedFetch(
    () =>
      Response.json({
        errors: [{ message: "You do not have permission to exportContent db" }],
      }, { status: 403 }),
    async () => {
      const { context } = createModelTestContext({
        globalArgs: GLOBAL_ARGS,
        methodName: "exportContent",
      });
      await assertRejects(
        () => model.methods.exportContent.execute({}, asContext(context)),
        Error,
        "You do not have permission",
      );
    },
  );
});
