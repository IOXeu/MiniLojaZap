// MiniLojaZap — servidor (Cloudflare Worker) — VERSÃO 2.0
// Rotas:
//   POST /api/comprar          — criar pagamento no Mercado Pago
//   GET  /api/licenca           — verificar pagamento e entregar código
//   POST /api/webhook           — webhook do Mercado Pago (entrega automática)
//   POST /api/publicar          — publicar loja (requer licença)
//   GET  /api/loja/:slug        — entregar dados de uma loja (+ contador de visitas)
//   GET  /api/admin            — painel de administração (requer ADMIN_PASSWORD)
//   DELETE /api/admin/loja/:slug — remover loja (requer ADMIN_PASSWORD)
//   GET  /api/health            — health check
//
// Segredos: MP_ACCESS_TOKEN, LIC_PRIVATE_JWK, LIC_PUBLIC_JWK
// Opcional: PRECO (padrão 19), ADMIN_PASSWORD
// KV: LOJAS

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,DELETE,OPTIONS", "access-control-allow-headers": "Content-Type, X-Admin-Password" } });
const te = new TextEncoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const slugify = s => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) || "minha-loja";
const ALG = { name: "ECDSA", namedCurve: "P-256" };
const SIG = { name: "ECDSA", hash: "SHA-256" };
const preco = env => +(env.PRECO || 19);
const LOJA_TTL = 7776000; // 90 dias

// CORS preflight
function cors(req) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,DELETE,OPTIONS", "access-control-allow-headers": "Content-Type, X-Admin-Password" } });
  }
  return null;
}

// Licença: assinar (usa chave privada)
async function assina(env, label) {
  const k = await crypto.subtle.importKey("jwk", JSON.parse(env.LIC_PRIVATE_JWK), ALG, false, ["sign"]);
  const p = b64(te.encode(label));
  return "ML1." + p + "." + b64(await crypto.subtle.sign(SIG, k, te.encode("ML1." + p)));
}

// Licença: verificar (usa apenas chave pública — MELHORIA 4)
async function verifica(env, code) {
  try {
    const pubJwk = env.LIC_PUBLIC_JWK ? JSON.parse(env.LIC_PUBLIC_JWK) : null;
    if (!pubJwk) return null;
    const p = String(code || "").replace(/\s+/g, "").split(".");
    if (p.length !== 3 || p[0] !== "ML1") return null;
    const k = await crypto.subtle.importKey("jwk", pubJwk, ALG, false, ["verify"]);
    return (await crypto.subtle.verify(SIG, k, unb64(p[2]), te.encode("ML1." + p[1]))) ? p[1] : null;
  } catch (e) { return null; }
}

// Mercado Pago helper
async function mp(env, url, opt = {}) {
  return fetch("https://api.mercadopago.com" + url, {
    ...opt,
    headers: { authorization: "Bearer " + env.MP_ACCESS_TOKEN, "content-type": "application/json" }
  });
}

// MELHORIA 3: Enviar e-mail via MailChannels
async function enviaEmail(env, para, code, nome) {
  try {
    const msg = `Olá ${nome}!\n\nSeu código de acesso vitalício ao Miniloja Relâmpago:\n\n${code}\n\nComo usar: abra o app, clique em CRIADOR, cole o código e toque em DESBLOQUEAR.\n\nObrigado pela compra!`;
    await fetch("https://api.mailchannels.net/tx/v1/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: para }] }],
        from: { email: "licenca@minilojazap.workers.dev", name: "Miniloja Relâmpago" },
        subject: "Seu código de acesso — Miniloja Relâmpago",
        content: [{ type: "text/plain", value: msg }]
      })
    });
  } catch (e) { /* falha no e-mail não bloqueia a resposta */ }
}

// Processar pagamento aprovado (compartilhado entre licenca e webhook)
async function processarPagamento(env, pid, ref) {
  const ja = await env.LOJAS.get("pag:" + pid, "json");
  if (ja) return { code: ja.code, nome: ja.nome, email: ja.email, jaExistia: true };

  if (!(await env.LOJAS.get("ord:" + ref))) return null;

  const p = await (await mp(env, "/v1/payments/" + pid)).json();
  if (p.external_reference !== ref) return null;
  if (p.status !== "approved") return { pendente: true, status: p.status };
  if (+p.transaction_amount < preco(env)) return null;

  const nome = (p.payer && (p.payer.first_name || (p.payer.email || "").split("@")[0])) || "cliente";
  const email = (p.payer && p.payer.email) || "";
  const code = await assina(env, nome + " #" + pid.slice(-4));
  await env.LOJAS.put("pag:" + pid, JSON.stringify({ ref, code, nome, email }));

  // MELHORIA 3: enviar e-mail automaticamente
  if (email) enviaEmail(env, email, code, nome);

  return { code, nome, email, jaExistia: false };
}

// MELHORIA 5: Autenticação admin
function checkAdmin(req, env) {
  const pwd = req.headers.get("X-Admin-Password") || "";
  return env.ADMIN_PASSWORD && pwd === env.ADMIN_PASSWORD;
}

export default {
  async fetch(req, env) {
    const corsResp = cors(req);
    if (corsResp) return corsResp;

    const u = new URL(req.url);
    const path = u.pathname;

    try {
      // 1) Criar pagamento no Mercado Pago
      if (path === "/api/comprar" && req.method === "POST") {
        const ref = "ML-" + crypto.randomUUID();
        const r = await mp(env, "/checkout/preferences", {
          method: "POST",
          body: JSON.stringify({
            items: [{ title: "Miniloja Relâmpago - licença vitalícia", quantity: 1, currency_id: "BRL", unit_price: preco(env) }],
            external_reference: ref,
            back_urls: { success: u.origin + "/", pending: u.origin + "/", failure: u.origin + "/" },
            auto_return: "approved",
            notification_url: u.origin + "/api/webhook"
          })
        });
        const d = await r.json();
        if (!d.init_point) return J({ erro: "O Mercado Pago recusou o pedido" }, 502);
        await env.LOJAS.put("ord:" + ref, "1", { expirationTtl: 2592000 });
        return J({ url: d.init_point, ref });
      }

      // 2) Verificar pagamento e entregar código de licença
      if (path === "/api/licenca" && req.method === "GET") {
        const pid = u.searchParams.get("payment_id") || "";
        const ref = u.searchParams.get("ref") || "";
        if (!/^\d+$/.test(pid) || !ref) return J({ erro: "Dados inválidos" }, 400);

        const r = await processarPagamento(env, pid, ref);
        if (!r) return J({ erro: "Pagamento ou pedido não encontrado" }, 404);
        if (r.pendente) return J({ pendente: true, status: r.status });
        return J({ code: r.code });
      }

      // MELHORIA 1: Webhook do Mercado Pago
      if (path === "/api/webhook" && req.method === "POST") {
        const body = await req.json();
        if (body.type === "payment" && body.data && body.data.id) {
          const pid = String(body.data.id);
          const p = await (await mp(env, "/v1/payments/" + pid)).json();
          if (p && p.status === "approved" && p.external_reference) {
            await processarPagamento(env, pid, p.external_reference);
          }
        }
        return J({ ok: true });
      }

      // 3) Publicar loja (requer licença válida)
      if (path === "/api/publicar" && req.method === "POST") {
        const b = await req.json();
        const dono = await verifica(env, b.code);
        if (!dono) return J({ erro: "Licença inválida" }, 403);

        const d = b.d;
        if (!d || !Array.isArray(d.produtos) || d.produtos.length < 1 || d.produtos.length > 6)
          return J({ erro: "Dados inválidos (1 a 6 produtos)" }, 400);
        if (JSON.stringify(d).length > 900000)
          return J({ erro: "Loja muito grande (reduza as fotos)" }, 413);

        let slug = slugify(b.slug || d.nome);
        if (slug === "api") slug = "api-loja";

        const atual = await env.LOJAS.get("loja:" + slug, "json");
        if (atual && atual.dono !== dono) {
          slug = slug.slice(0, 24) + "-" + crypto.randomUUID().slice(0, 4);
        }

        // MELHORIA 6: expiração automática de 90 dias (renovada a cada publicação)
        const existente = atual || {};
        await env.LOJAS.put("loja:" + slug, JSON.stringify({
          dono,
          t: b.t,
          d,
          em: Date.now(),
          visitas: existente.visitas || 0
        }), { expirationTtl: LOJA_TTL });

        return J({ slug, url: u.origin + "/" + slug });
      }

      // 4) Entregar dados de uma loja publicada (+ MELHORIA 7: contador de visitas)
      if (path.startsWith("/api/loja/") && req.method === "GET") {
        const slug = decodeURIComponent(path.slice(10));
        const v = await env.LOJAS.get("loja:" + slug, "json");
        if (!v) return J({ erro: "Loja não encontrada" }, 404);

        const ck = "vis:" + slug;
        const visitas = +(await env.LOJAS.get(ck) || 0) + 1;
        env.LOJAS.put(ck, String(visitas));

        v.visitas = visitas;
        env.LOJAS.put("loja:" + slug, JSON.stringify(v), { expirationTtl: LOJA_TTL });

        return J({ t: v.t, d: v.d });
      }

      // MELHORIA 5: Painel de administração
      if (path === "/api/admin" && req.method === "GET") {
        if (!checkAdmin(req, env)) return J({ erro: "Não autorizado" }, 401);

        const list = await env.LOJAS.list({ prefix: "loja:" });
        const lojas = [];
        for (const k of list.keys) {
          const v = await env.LOJAS.get(k.name, "json");
          if (v) {
            const slug = k.name.slice(5);
            const visitas = +(await env.LOJAS.get("vis:" + slug) || 0);
            lojas.push({
              slug,
              dono: v.dono,
              nome: v.d?.nome || "(sem nome)",
              produtos: v.d?.produtos?.length || 0,
              visitas,
              atualizada: new Date(v.em).toLocaleString("pt-BR")
            });
          }
        }

        const pags = await env.LOJAS.list({ prefix: "pag:" });
        const ordens = await env.LOJAS.list({ prefix: "ord:" });

        return J({
          total_lojas: lojas.length,
          total_pagamentos: pags.keys.length,
          pedidos_abertos: ordens.keys.length,
          lojas
        });
      }

      // MELHORIA 5: Remover loja (admin)
      if (path.startsWith("/api/admin/loja/") && req.method === "DELETE") {
        if (!checkAdmin(req, env)) return J({ erro: "Não autorizado" }, 401);
        const slug = decodeURIComponent(path.slice(16));
        await env.LOJAS.delete("loja:" + slug);
        await env.LOJAS.delete("vis:" + slug);
        return J({ ok: true, removido: slug });
      }

      // 5) Health check
      if (path === "/api/health") {
        return J({ ok: true, timestamp: Date.now(), versao: "2.0" });
      }

    } catch (e) {
      return J({ erro: "Falha interna" }, 500);
    }

    return env.ASSETS ? env.ASSETS.fetch(req) : new Response("Não encontrado", { status: 404 });
  }
};
