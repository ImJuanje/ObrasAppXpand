import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const db = (n) => getStore(n);
const SECRET = () => process.env.SESSION_SECRET || "";

export const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", ...headers } });

export function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return salt + ":" + crypto.scryptSync(pw, salt, 64).toString("hex");
}
export function checkPw(pw, stored) {
  const [salt, h] = String(stored || "").split(":");
  if (!salt || !h) return false;
  const a = Buffer.from(h, "hex"), b = crypto.scryptSync(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const sign = (s) => crypto.createHmac("sha256", SECRET()).update(s).digest("base64url");
export function makeToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return body + "." + sign(body);
}
export function readToken(t) {
  if (!SECRET() || !t) return null;
  try {
    const [body, sig] = t.split(".");
    if (!body || !sig || sig !== sign(body)) return null;
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
export function sessionOf(req) {
  const m = (req.headers.get("cookie") || "").match(/(?:^|; )rf=([^;]+)/);
  return m ? readToken(m[1]) : null;
}
export const cookie = (token, maxAge) =>
  `rf=${token}; Path=/; HttpOnly; Secure; SameSite=Strict` + (maxAge ? `; Max-Age=${maxAge}` : "");
