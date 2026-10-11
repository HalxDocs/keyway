// Minimal Keyway-integrated app — TS port of examples/demo-sso/main.go.
// Home page mints a state cookie + login link; /callback verifies state
// first, then redeems the single-use code. Zero runtime dependencies.
//
//   npx -y tsx examples/express-callback.ts
//   # open http://localhost:3000, click Log in with SSO
import http from "node:http";
import { KeywayClient, generateState, parseCallbackUrl } from "../src/index.js";

const KEYWAY: string = process.env.KEYWAY_URL ?? "http://127.0.0.1:8080";
const TENANT: string = process.env.KEYWAY_TENANT ?? "acme";
const REDIRECT: string = process.env.APP_REDIRECT ?? "http://localhost:3000/callback";
const CONNECTION: string = process.env.KEYWAY_CONNECTION ?? "";
const PORT: number = Number(process.env.PORT ?? 3000);

const client = new KeywayClient(KEYWAY);

function getCookie(req: http.IncomingMessage, name: string): string {
  const header: string = req.headers.cookie ?? "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return "";
}

// Escape text for HTML interpolation — mirrors Go's html.EscapeString in
// examples/demo-sso. Identity fields come from the IdP and must never be
// injected raw into a page.
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[ch] ?? ch;
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/") {
    const state = generateState();
    const loginUrl = client.buildAuthorizeUrl({
      tenant: TENANT,
      redirectUri: REDIRECT,
      state,
      connection: CONNECTION,
    });
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Set-Cookie": `keyway_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`,
    });
    res.end(`<h1>demo-sso (ts)</h1><p><a href="${escapeHtml(loginUrl)}">Log in with SSO</a></p>`);
    return;
  }
  if (url.pathname === "/callback") {
    const { code, state } = parseCallbackUrl(url);
    const want = getCookie(req, "keyway_state");
    if (!want || state !== want) {
      res.writeHead(400, { "Content-Type": "text/plain" }).end("state mismatch: login did not start here");
      return;
    }
    void client
      .exchangeCode({ code, redirectUri: REDIRECT })
      .then((ident) => {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(
          `<h1>logged in</h1><p>email: ${escapeHtml(ident.email)}</p><p>name: ${escapeHtml(ident.name)}</p><p>groups: ${ident.groups.map(escapeHtml).join(", ")}</p>`,
        );
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : "unknown error";
        res.writeHead(502, { "Content-Type": "text/plain" }).end(`exchange failed: ${message}`);
      });
    return;
  }
  res.writeHead(404).end("not found");
});

server.listen(PORT, () =>
  console.log(`demo listening on http://localhost:${PORT} for tenant ${JSON.stringify(TENANT)}`),
);
