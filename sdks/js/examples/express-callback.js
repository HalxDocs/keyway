// Minimal Keyway-integrated app — JS port of examples/demo-sso/main.go.
// Home page mints a state cookie + login link; /callback verifies state
// first, then redeems the single-use code. Zero dependencies (plain http).
//
//   node examples/express-callback.js
//   # open http://localhost:3000, click Log in with SSO
import http from "node:http";
import { KeywayClient, generateState, parseCallbackUrl } from "../src/index.js";

const KEYWAY = process.env.KEYWAY_URL ?? "http://127.0.0.1:8080";
const TENANT = process.env.KEYWAY_TENANT ?? "acme";
const REDIRECT = process.env.APP_REDIRECT ?? "http://localhost:3000/callback";
const CONNECTION = process.env.KEYWAY_CONNECTION ?? "";
const PORT = Number(process.env.PORT ?? 3000);

const client = new KeywayClient(KEYWAY);

function getCookie(req, name) {
  const header = req.headers.cookie ?? "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return "";
}

// Escape text for HTML interpolation — mirrors Go's html.EscapeString in
// examples/demo-sso. Identity fields come from the IdP and must never be
// injected raw into a page.
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (ch) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
  ));
}

const server = http.createServer(async (req, res) => {
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
    res.end(`<h1>demo-sso (js)</h1><p><a href="${escapeHtml(loginUrl)}">Log in with SSO</a></p>`);
    return;
  }
  if (url.pathname === "/callback") {
    const { code, state } = parseCallbackUrl(url);
    const want = getCookie(req, "keyway_state");
    if (!want || state !== want) {
      res.writeHead(400, { "Content-Type": "text/plain" }).end("state mismatch: login did not start here");
      return;
    }
    try {
      const ident = await client.exchangeCode({ code, redirectUri: REDIRECT });
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(
        `<h1>logged in</h1><p>email: ${escapeHtml(ident.email)}</p><p>name: ${escapeHtml(ident.name)}</p><p>groups: ${ident.groups.map(escapeHtml).join(", ")}</p>`,
      );
    } catch (err) {
      res.writeHead(502, { "Content-Type": "text/plain" }).end(`exchange failed: ${err.message}`);
    }
    return;
  }
  res.writeHead(404).end("not found");
});

server.listen(PORT, () => console.log(`demo listening on http://localhost:${PORT} for tenant ${JSON.stringify(TENANT)}`));
