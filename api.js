import crypto from "node:crypto";
import { db, json, hashPw, checkPw, makeToken, sessionOf, cookie } from "./lib.js";

export const config = { path: "/api/*" };

const MAX_TRIES = 5, BLOCK_MS = 15 * 60 * 1000, DAY = 86400000;
const DEFAULT_SETTINGS = { tipos: ["Baño", "Cocina", "Suelos", "Pintura", "Integral"], iva: 21 };
const clean = (s) => String(s || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 32);

async function limited(key) {
  const r = (await db("rate").get(key, { type: "json" })) || { n: 0, until: 0 };
  return { r, blocked: r.until > Date.now() };
}
async function fail(key, r) {
  r.n += 1;
  if (r.n >= MAX_TRIES) { r.until = Date.now() + BLOCK_MS; r.n = 0; }
  await db("rate").setJSON(key, r);
}

async function handle(req) {
  const action = new URL(req.url).pathname.replace(/^\/api\//, "");
  const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};
  const users = db("users"), invites = db("invites"), cfg = db("settings"), obras = db("obras"), clientes = db("clientes");
  const ses = sessionOf(req);

  if (action === "login") {
    const user = clean(body.user), ip = req.headers.get("x-nf-client-connection-ip") || "x";
    const key = `${ip}:${user}`, { r, blocked } = await limited(key);
    if (blocked) return json({ error: "Demasiados intentos. Prueba en 15 minutos." }, 429);
    let ok = false, role = "operario";
    if (user === "admin") {
      const a = Buffer.from(String(body.password || "")), b = Buffer.from(process.env.ADMIN_PASSWORD || "");
      ok = !!b.length && a.length === b.length && crypto.timingSafeEqual(a, b); role = "admin";
    } else {
      const u = await users.get(user, { type: "json" });
      ok = !!u && checkPw(String(body.password || ""), u.hash);
    }
    if (!ok) { await fail(key, r); return json({ error: "Usuario o contraseña incorrectos." }, 401); }
    await db("rate").delete(key);
    const age = body.remember ? 30 * DAY : DAY;
    return json({ user, role }, 200, { "set-cookie": cookie(makeToken({ user, role, exp: Date.now() + age }), body.remember ? age / 1000 : 0) });
  }

  if (action === "activate") {
    const user = clean(body.user), code = String(body.code || "").trim().toUpperCase();
    if (user.length < 3 || user === "admin" || String(body.password || "").length < 8)
      return json({ error: "Usuario mínimo 3 caracteres y contraseña mínimo 8." }, 400);
    const inv = await invites.get(code, { type: "json" });
    if (!inv || inv.exp < Date.now()) return json({ error: "Código no válido o caducado." }, 400);
    if (await users.get(user)) return json({ error: "Ese usuario ya existe." }, 409);
    await users.setJSON(user, { hash: hashPw(body.password), created: Date.now() });
    await invites.delete(code);
    return json({ ok: true });
  }

  if (action === "logout") return json({ ok: true }, 200, { "set-cookie": cookie("", 0).replace("rf=;", "rf=;") + "; Max-Age=0" });
  const byToken = async (t) => {
    t = String(t || "");
    const id = /^[a-f0-9]{48}$/.test(t) ? await db("tokens").get(t) : null;
    return id ? await obras.get(id, { type: "json" }) : null;
  };
  if (action === "portal-get") {
    const o = await byToken(body.t);
    if (!o) return json({ error: "Enlace no válido o desactivado." }, 404);
    return json({ cliente: o.cliente.nombre, direccion: o.direccion, estado: o.estado, iva: o.iva,
      presupuestos: o.presupuestos.filter((p) => ["Enviado", "Aprobado", "Rechazado"].includes(p.estado))
        .map((p) => ({ v: p.v, fecha: p.fecha, nota: p.nota, partidas: p.partidas, estado: p.estado, decision: p.decision })),
      modificados: (o.modificados || []).filter((m) => m.estado !== "Borrador")
        .map((m) => ({ id: m.id, n: m.n, desc: m.desc, partida: m.partida, plazo: m.plazo, coste: m.coste, fotos: m.fotos, estado: m.estado, decision: m.decision })) });
  }
  if (action === "portal-foto") {
    const u = new URL(req.url).searchParams, o = await byToken(u.get("t")), k = String(u.get("k") || "");
    const ok = o && /^[a-f0-9]+_\d$/.test(k) && (o.modificados || []).some((m) => m.estado !== "Borrador" && k.startsWith(m.id + "_"));
    const b = ok ? await db("fotos").get(o.id + "_" + k) : null;
    return b ? new Response(Buffer.from(b, "base64"), { headers: { "content-type": "image/jpeg", "cache-control": "private, max-age=3600" } }) : json({ error: "Foto no encontrada." }, 404);
  }
  if (action === "portal-decide") {
    const o = await byToken(body.t), si = body.decision === "aprobar";
    if (!o) return json({ error: "Enlace no válido o desactivado." }, 404);
    if (!si && body.decision !== "rechazar") return json({ error: "Decisión no válida." }, 400);
    const item = body.tipo === "presupuesto" ? o.presupuestos.find((p) => p.v === Number(body.id) && p.estado === "Enviado")
      : body.tipo === "modificado" ? (o.modificados || []).find((m) => m.id === body.id && m.estado === "Pendiente") : null;
    if (!item) return json({ error: "Esta propuesta ya está decidida o no está disponible." }, 409);
    const motivo = String(body.motivo || "").trim().slice(0, 300), now = Date.now();
    item.estado = si ? "Aprobado" : "Rechazado";
    item.decision = { fecha: now, motivo };
    (item.historial = item.historial || []).push({ fecha: now, quien: "cliente", accion: si ? "Aprobado por el cliente" : "Rechazado por el cliente", motivo, ip: req.headers.get("x-nf-client-connection-ip") || "" });
    if (si && body.tipo === "presupuesto") o.estado = "Aprobada";
    await obras.setJSON(o.id, o);
    return json({ ok: true });
  }

  if (!ses) return json({ error: "Sesión no válida." }, 401);
  if (action === "me") return json({ user: ses.user, role: ses.role });

  if (action === "settings-get") return json((await cfg.get("main", { type: "json" })) || DEFAULT_SETTINGS);

  const visible = (o) => ses.role === "admin" || o.asignado === ses.user;
  const strip = (o) => ses.role === "admin" ? o : { ...o, iva: undefined, token: undefined, presupuestos: o.presupuestos.map((p) => ({ v: p.v, fecha: p.fecha, nota: p.nota, estado: p.estado, partidas: p.partidas.map((x) => ({ desc: x.desc })) })), modificados: (o.modificados || []).map((m) => ({ ...m, coste: undefined, historial: m.historial.map(({ ip, ...h }) => h) })) };
  const tel = (s) => String(s || "").replace(/\D/g, "").slice(-12);
  if (action === "obras-list") {
    const all = await Promise.all((await obras.list()).blobs.map((b) => obras.get(b.key, { type: "json" })));
    return json(all.filter((o) => o && visible(o)).sort((a, b) => b.created - a.created)
      .map((o) => ({ id: o.id, cliente: o.cliente.nombre, direccion: o.direccion, estado: o.estado, asignado: o.asignado })));
  }
  if (action === "obra-get") {
    const o = await obras.get(String(body.id || ""), { type: "json" });
    return o && visible(o) ? json(strip(o)) : json({ error: "Obra no encontrada." }, 404);
  }

  const getObra = async (id) => { const o = await obras.get(String(id || ""), { type: "json" }); return o && visible(o) ? o : null; };
  const okEstado = (m) => m.estado === "Aprobado" || m.estado === "Desbloqueado";
  if (action === "foto") {
    const u = new URL(req.url).searchParams, o = await getObra(u.get("obra")), k = String(u.get("k") || "");
    const b = o && /^[a-f0-9]+_\d$/.test(k) && (o.modificados || []).some((m) => k.startsWith(m.id + "_")) ? await db("fotos").get(o.id + "_" + k) : null;
    return b ? new Response(Buffer.from(b, "base64"), { headers: { "content-type": "image/jpeg", "cache-control": "private, max-age=3600" } }) : json({ error: "Foto no encontrada." }, 404);
  }
  if (action === "modificado-add") {
    const o = await getObra(body.id);
    if (!o) return json({ error: "Obra no encontrada." }, 404);
    const last = o.presupuestos[o.presupuestos.length - 1];
    const desc = String(body.desc || "").trim().slice(0, 400), partida = String(body.partida || "");
    if (!desc) return json({ error: "Describe el modificado." }, 400);
    if (partida && !(last && last.partidas.some((p) => p.desc === partida))) return json({ error: "Esa partida no existe en el presupuesto actual." }, 400);
    const plazo = Math.round(Number(body.plazo) || 0);
    if (plazo < 0 || plazo > 365) return json({ error: "Plazo no válido." }, 400);
    let coste = null;
    if (ses.role === "admin" && body.coste !== "" && body.coste != null) { coste = Math.round(Number(body.coste) * 100) / 100; if (!(coste >= 0)) return json({ error: "Coste no válido." }, 400); }
    const fotos = (body.fotos || []).slice(0, 5);
    if (fotos.some((f) => typeof f !== "string" || f.length > 900000) || fotos.join("").length > 4000000) return json({ error: "Las fotos pesan demasiado. Prueba con menos fotos." }, 400);
    const id = crypto.randomBytes(4).toString("hex");
    await Promise.all(fotos.map((f, i) => db("fotos").set(`${o.id}_${id}_${i}`, f.replace(/^data:image\/jpeg;base64,/, ""))));
    o.modificados = o.modificados || [];
    o.modificados.push({ id, n: o.modificados.length + 1, desc, partida, plazo, coste, fotos: fotos.length, estado: "Borrador", por: ses.user, fecha: Date.now(), historial: [{ fecha: Date.now(), quien: ses.user, accion: "Creado" }] });
    await obras.setJSON(o.id, o);
    return json({ ok: true });
  }

  if (ses.role !== "admin") return json({ error: "Solo el administrador puede hacer esto." }, 403);

  if (action === "settings-set") {
    const tipos = (body.tipos || []).map((t) => String(t).trim().slice(0, 40)).filter(Boolean).slice(0, 40);
    const iva = Number(body.iva);
    if (!tipos.length || !(iva >= 0 && iva <= 30)) return json({ error: "Revisa los tipos de reforma y el IVA." }, 400);
    await cfg.setJSON("main", { tipos, iva });
    return json({ ok: true });
  }
  if (action === "invite-create") {
    const code = crypto.randomBytes(4).toString("hex").toUpperCase();
    await invites.setJSON(code, { exp: Date.now() + 3 * DAY });
    return json({ code });
  }
  if (action === "invite-delete") { await invites.delete(String(body.code || "")); return json({ ok: true }); }
  if (action === "team-list") {
    const u = (await users.list()).blobs.map((b) => b.key);
    const i = await Promise.all((await invites.list()).blobs.map(async (b) => ({ code: b.key, ...(await invites.get(b.key, { type: "json" })) })));
    return json({ users: u, invites: i.filter((x) => x.exp > Date.now()) });
  }
  if (action === "user-delete") { await users.delete(clean(body.user)); return json({ ok: true }); }

  if (action === "cliente-buscar") return json((await clientes.get(tel(body.tel), { type: "json" })) || null);
  if (action === "obra-save") {
    const t = tel(body.tel), nombre = String(body.nombre || "").trim().slice(0, 80), direccion = String(body.direccion || "").trim().slice(0, 160);
    if (t.length < 6 || !nombre || !direccion) return json({ error: "Faltan nombre, teléfono o dirección." }, 400);
    const asignado = !body.asignado || body.asignado === "admin" ? "admin" : clean(body.asignado);
    if (asignado !== "admin" && !(await users.get(asignado))) return json({ error: "El operario asignado no existe." }, 400);
    const iva = Number(body.iva);
    if (!(iva >= 0 && iva <= 30)) return json({ error: "IVA no válido." }, 400);
    const prev = body.id ? await obras.get(String(body.id), { type: "json" }) : null;
    if (body.id && !prev) return json({ error: "Obra no encontrada." }, 404);
    const o = { ...(prev || { id: crypto.randomBytes(6).toString("hex"), estado: "Presupuesto", presupuestos: [], created: Date.now() }),
      cliente: { nombre, tel: t }, direccion, asignado, iva, otro: String(body.otro || "").slice(0, 120),
      tipos: (body.tipos || []).map((x) => String(x).trim().slice(0, 40)).filter(Boolean).slice(0, 10),
      inicio: String(body.inicio || "").slice(0, 10), fin: String(body.fin || "").slice(0, 10) };
    await clientes.setJSON(t, { nombre, tel: t });
    await obras.setJSON(o.id, o);
    return json({ id: o.id });
  }
  if (action === "presupuesto-add") {
    const o = await obras.get(String(body.id || ""), { type: "json" });
    if (!o) return json({ error: "Obra no encontrada." }, 404);
    const partidas = (body.partidas || []).map((p) => ({ desc: String(p.desc || "").trim().slice(0, 160), importe: Math.round(Number(p.importe) * 100) / 100 })).filter((p) => p.desc);
    if (!partidas.length || partidas.some((p) => !(p.importe >= 0))) return json({ error: "Cada partida necesita descripción e importe." }, 400);
    o.presupuestos.push({ v: o.presupuestos.length + 1, fecha: Date.now(), nota: String(body.nota || "").slice(0, 300), partidas });
    await obras.setJSON(o.id, o);
    return json({ v: o.presupuestos.length });
  }

  if (action === "modificado-edit" || action === "modificado-desbloquear") {
    const o = await obras.get(String(body.id || ""), { type: "json" }), m = o && (o.modificados || []).find((x) => x.id === body.mid);
    if (!m) return json({ error: "Modificado no encontrado." }, 404);
    if (action === "modificado-edit") {
      if (m.estado !== "Borrador") return json({ error: "Solo se puede editar mientras es borrador." }, 400);
      const last = o.presupuestos[o.presupuestos.length - 1], partida = String(body.partida || "");
      const desc = String(body.desc || "").trim().slice(0, 400), plazo = Math.round(Number(body.plazo) || 0);
      const coste = body.coste === "" || body.coste == null ? null : Math.round(Number(body.coste) * 100) / 100;
      if (!desc || plazo < 0 || plazo > 365 || (coste !== null && !(coste >= 0)) || (partida && !(last && last.partidas.some((p) => p.desc === partida)))) return json({ error: "Revisa descripción, partida, plazo y coste." }, 400);
      Object.assign(m, { desc, partida, plazo, coste });
      m.historial.push({ fecha: Date.now(), quien: ses.user, accion: "Editado" });
    } else {
      const motivo = String(body.motivo || "").trim().slice(0, 300);
      if (okEstado(m) || m.reemplazado) return json({ error: "Este modificado ya no bloquea." }, 400);
      if (motivo.length < 5) return json({ error: "Indica el motivo del desbloqueo." }, 400);
      m.estado = "Desbloqueado";
      m.historial.push({ fecha: Date.now(), quien: ses.user, accion: "Desbloqueado sin ok del cliente", motivo });
    }
    await obras.setJSON(o.id, o);
    return json({ ok: true });
  }

  if (action === "enlace-generar") {
    const o = await obras.get(String(body.id || ""), { type: "json" });
    if (!o) return json({ error: "Obra no encontrada." }, 404);
    if (o.token) await db("tokens").delete(o.token);
    o.token = crypto.randomBytes(24).toString("hex");
    await db("tokens").set(o.token, o.id);
    await obras.setJSON(o.id, o);
    return json({ token: o.token });
  }
  if (["presupuesto-enviar", "modificado-enviar", "modificado-replantear"].includes(action)) {
    const o = await obras.get(String(body.id || ""), { type: "json" });
    if (!o) return json({ error: "Obra no encontrada." }, 404);
    const now = Date.now(), h = (accion) => ({ fecha: now, quien: ses.user, accion });
    if (!o.token) return json({ error: "Genera antes el enlace del cliente." }, 400);
    if (action === "presupuesto-enviar") {
      const p = o.presupuestos[o.presupuestos.length - 1];
      if (!p || p.v !== Number(body.v) || (p.estado && p.estado !== "Borrador")) return json({ error: "Solo se envía la última versión, si aún es borrador." }, 400);
      if (o.presupuestos.some((x) => x.estado === "Aprobado")) return json({ error: "Ya hay un presupuesto aprobado; los cambios van como modificados." }, 400);
      o.presupuestos.forEach((x) => { if (x.estado === "Enviado") x.estado = "Sustituido"; });
      p.estado = "Enviado";
      (p.historial = p.historial || []).push(h("Enviado al cliente"));
    } else {
      const ms = o.modificados || [], m = ms.find((x) => x.id === body.mid);
      if (!m) return json({ error: "Modificado no encontrado." }, 404);
      if (action === "modificado-enviar") {
        if (m.estado !== "Borrador" || m.coste == null) return json({ error: "Para enviarlo debe ser borrador y tener coste." }, 400);
        m.estado = "Pendiente";
        m.historial.push(h("Enviado al cliente"));
      } else {
        if (m.estado !== "Rechazado" || m.reemplazado) return json({ error: "Solo se replantea un modificado rechazado." }, 400);
        const id = crypto.randomBytes(4).toString("hex");
        await Promise.all(Array.from({ length: m.fotos }, async (_, i) => { const b = await db("fotos").get(`${o.id}_${m.id}_${i}`); if (b) await db("fotos").set(`${o.id}_${id}_${i}`, b); }));
        ms.push({ id, n: ms.length + 1, desc: m.desc, partida: m.partida, plazo: m.plazo, coste: m.coste, fotos: m.fotos, estado: "Borrador", por: ses.user, fecha: now, historial: [h(`Replanteado desde el modificado ${m.n}`)] });
        m.reemplazado = id;
        m.historial.push(h("Sustituido por una versión nueva"));
      }
    }
    await obras.setJSON(o.id, o);
    return json({ ok: true });
  }

  return json({ error: "No encontrado." }, 404);
}

export default async (req) => {
  try {
    return await handle(req);
  } catch (e) {
    console.error(e);
    return json({ error: "Fallo del servidor: " + (e && e.message ? e.message : e) }, 500);
  }
};
