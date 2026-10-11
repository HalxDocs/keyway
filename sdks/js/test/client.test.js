import { describe, it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { KeywayClient } from "../src/index.js";
import { KeywayError } from "../src/errors.js";

// Ports pkg/client/client_test.go TestAuthURL + TestNewValidatesURL.
describe("buildAuthorizeUrl", () => {
  it("builds /authorize with all params", () => {
    const c = new KeywayClient("https://keyway.example");
    const u = c.buildAuthorizeUrl({
      tenant: "acme",
      redirectUri: "https://app.example/callback",
      state: "csrf-123",
      connection: "conn-1",
    });
    const parsed = new URL(u);
    assert.equal(parsed.pathname, "/authorize");
    assert.equal(parsed.searchParams.get("tenant"), "acme");
    assert.equal(parsed.searchParams.get("redirect_uri"), "https://app.example/callback");
    assert.equal(parsed.searchParams.get("state"), "csrf-123");
    assert.equal(parsed.searchParams.get("connection"), "conn-1");
  });

  it("omits empty state/connection", () => {
    const c = new KeywayClient("https://keyway.example");
    const u = c.buildAuthorizeUrl({ tenant: "acme", redirectUri: "https://app.example/callback" });
    assert.ok(!u.includes("connection="));
    assert.ok(!u.includes("state="));
  });

  it("rejects missing tenant/redirect", () => {
    const c = new KeywayClient("https://keyway.example");
    assert.throws(() => c.buildAuthorizeUrl({ tenant: "", redirectUri: "https://app.example/callback" }), KeywayError);
  });

  it("throws KeywayError (not TypeError) when called with no argument", () => {
    const c = new KeywayClient("https://keyway.example");
    assert.throws(() => c.buildAuthorizeUrl(), KeywayError);
  });
});

describe("constructor", () => {
  it("rejects empty and malformed URLs", () => {
    assert.throws(() => new KeywayClient(""), KeywayError);
    assert.throws(() => new KeywayClient("://bad"), KeywayError);
  });

  it("trims trailing slash (no //authorize)", () => {
    const c = new KeywayClient("https://keyway.example/");
    const u = c.buildAuthorizeUrl({ tenant: "acme", redirectUri: "https://app.example/callback" });
    assert.ok(!u.includes("//authorize"));
  });

  it("trims surrounding whitespace and rejects hostless URLs", () => {
    const c = new KeywayClient("  https://keyway.example/  ");
    assert.equal(c.baseUrl, "https://keyway.example");
    assert.throws(() => new KeywayClient("https:"), KeywayError);
  });
});

// Ports pkg/client/client_test.go TestExchange with an httptest-style stub.
function stubServer(handler) {
  const srv = http.createServer(handler);
  return new Promise((resolve) => {
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      resolve({ srv, base: `http://127.0.0.1:${port}` });
    });
  });
}

describe("exchangeCode", () => {
  it("throws KeywayError (not TypeError) when called with no argument", async () => {
    const c = new KeywayClient("https://keyway.example");
    await assert.rejects(c.exchangeCode(), KeywayError);
  });
  it("redeems code for identity, rejects bad code", async () => {
    const { srv, base } = await stubServer((req, res) => {
      if (req.url !== "/token" || req.method !== "POST") {
        res.writeHead(404).end();
        return;
      }
      let raw = "";
      req.on("data", (d) => (raw += d));
      req.on("end", () => {
        const form = new URLSearchParams(raw);
        if (form.get("code") !== "code-1" || form.get("redirect_uri") !== "https://app.example/callback") {
          res.writeHead(400, { "Content-Type": "application/json" }).end(
            JSON.stringify({ error: "invalid_grant", error_description: "code mismatch" }),
          );
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" }).end(
          JSON.stringify({ email: "ada@example.com", name: "Ada", groups: ["eng"] }),
        );
      });
    });
    try {
      const c = new KeywayClient(base);
      const ident = await c.exchangeCode({ code: "code-1", redirectUri: "https://app.example/callback" });
      assert.equal(ident.email, "ada@example.com");
      assert.equal(ident.name, "Ada");
      assert.deepEqual(ident.groups, ["eng"]);
      await assert.rejects(
        c.exchangeCode({ code: "bad-code", redirectUri: "https://app.example/callback" }),
        (e) => e instanceof KeywayError && e.code === "invalid_grant",
      );
    } finally {
      srv.close();
    }
  });

  it("rejects identity without email", async () => {    const { srv, base } = await stubServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ name: "Nope" }));
    });
    try {
      const c = new KeywayClient(base);
      await assert.rejects(c.exchangeCode({ code: "x", redirectUri: "https://app.example/callback" }), KeywayError);
    } finally {
      srv.close();
    }
  });

  it("sends form-encoded body with correct content type", async () => {
    let seen;
    const { srv, base } = await stubServer((req, res) => {
      seen = { contentType: req.headers["content-type"], url: req.url, method: req.method };
      res.writeHead(200, { "Content-Type": "application/json" }).end(
        JSON.stringify({ email: "a@b.c", name: "", groups: [] }),
      );
    });
    try {
      const c = new KeywayClient(base);
      await c.exchangeCode({ code: "x", redirectUri: "https://app.example/callback" });
      assert.equal(seen.method, "POST");
      assert.equal(seen.url, "/token");
      assert.equal(seen.contentType, "application/x-www-form-urlencoded");
    } finally {
      srv.close();
    }
  });
});
