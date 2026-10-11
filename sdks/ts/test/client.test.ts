import { describe, it, expect } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
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
    expect(parsed.pathname).toBe("/authorize");
    expect(parsed.searchParams.get("tenant")).toBe("acme");
    expect(parsed.searchParams.get("redirect_uri")).toBe("https://app.example/callback");
    expect(parsed.searchParams.get("state")).toBe("csrf-123");
    expect(parsed.searchParams.get("connection")).toBe("conn-1");
  });

  it("omits empty state/connection", () => {
    const c = new KeywayClient("https://keyway.example");
    const u = c.buildAuthorizeUrl({ tenant: "acme", redirectUri: "https://app.example/callback" });
    expect(u).not.toContain("connection=");
    expect(u).not.toContain("state=");
  });

  it("rejects missing tenant/redirect", () => {
    const c = new KeywayClient("https://keyway.example");
    expect(() => c.buildAuthorizeUrl({ tenant: "", redirectUri: "https://app.example/callback" })).toThrow(
      KeywayError,
    );
  });

  it("throws KeywayError (not TypeError) when called with no argument", () => {
    const c = new KeywayClient("https://keyway.example");
    // @ts-expect-error runtime guard for JS callers
    expect(() => c.buildAuthorizeUrl()).toThrow(KeywayError);
  });
});

describe("constructor", () => {
  it("rejects empty and malformed URLs", () => {
    expect(() => new KeywayClient("")).toThrow(KeywayError);
    expect(() => new KeywayClient("://bad")).toThrow(KeywayError);
  });

  it("trims trailing slash (no //authorize)", () => {
    const c = new KeywayClient("https://keyway.example/");
    const u = c.buildAuthorizeUrl({ tenant: "acme", redirectUri: "https://app.example/callback" });
    expect(u).not.toContain("//authorize");
  });

  it("trims surrounding whitespace and rejects hostless URLs", () => {
    const c = new KeywayClient("  https://keyway.example/  ");
    expect(c.baseUrl).toBe("https://keyway.example");
    expect(() => new KeywayClient("https:")).toThrow(KeywayError);
  });
});

// Ports pkg/client/client_test.go TestExchange with an httptest-style stub.
function stubServer(handler: (req: http.IncomingMessage, res: http.ServerResponse) => void) {
  const srv = http.createServer(handler);
  return new Promise<{ srv: http.Server; base: string }>((resolve) => {
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      resolve({ srv, base: `http://127.0.0.1:${port}` });
    });
  });
}

describe("exchangeCode", () => {
  it("throws KeywayError (not TypeError) when called with no argument", async () => {
    const c = new KeywayClient("https://keyway.example");
    // @ts-expect-error runtime guard for JS callers
    await expect(c.exchangeCode()).rejects.toThrow(KeywayError);
  });

  it("redeems code for identity, rejects bad code", async () => {
    const { srv, base } = await stubServer((req, res) => {
      if (req.url !== "/token" || req.method !== "POST") {
        res.writeHead(404).end();
        return;
      }
      let raw = "";
      req.on("data", (d: Buffer) => (raw += d));
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
      expect(ident.email).toBe("ada@example.com");
      expect(ident.name).toBe("Ada");
      expect(ident.groups).toEqual(["eng"]);
      await expect(
        c.exchangeCode({ code: "bad-code", redirectUri: "https://app.example/callback" }),
      ).rejects.toMatchObject({ code: "invalid_grant" });
    } finally {
      srv.close();
    }
  });

  it("rejects identity without email", async () => {
    const { srv, base } = await stubServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ name: "Nope" }));
    });
    try {
      const c = new KeywayClient(base);
      await expect(c.exchangeCode({ code: "x", redirectUri: "https://app.example/callback" })).rejects.toThrow(
        KeywayError,
      );
    } finally {
      srv.close();
    }
  });

  it("sends form-encoded body with correct content type", async () => {
    let seen = { contentType: "", url: "", method: "" };
    const { srv, base } = await stubServer((req, res) => {
      seen = {
        contentType: req.headers["content-type"] ?? "",
        url: req.url ?? "",
        method: req.method ?? "",
      };
      res.writeHead(200, { "Content-Type": "application/json" }).end(
        JSON.stringify({ email: "a@b.c", name: "", groups: [] }),
      );
    });
    try {
      const c = new KeywayClient(base);
      await c.exchangeCode({ code: "x", redirectUri: "https://app.example/callback" });
      expect(seen.method).toBe("POST");
      expect(seen.url).toBe("/token");
      expect(seen.contentType).toBe("application/x-www-form-urlencoded");
    } finally {
      srv.close();
    }
  });
});
