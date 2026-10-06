// MiniLojaZap — servidor (Cloudflare Worker) — VERSÃO MELHORADA
// Rotas: POST /api/comprar • GET /api/licenca • POST /api/publicar • GET /api/loja/:slug
// Segredos: MP_ACCESS_TOKEN, LIC_PRIVATE_JWK • Opcional: PRECO (padrão 19) • KV: LOJAS

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*" } });
const te = new TextEncoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const slugify = s => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) || "minha-loja";
const ALG = { name: "ECDSA", namedCurve: "P-256" };
const SIG = { name: "ECDSA", hash: "SHA-256" };
const preco = env => +(env.PRECO || 19);

function cors(req) {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "Content-Type" } });
  }
  return null;
}

async function assina(env, label) {
  const k = await crypto.subtle.importKey("jwk", JSON.parse(env.LIC_PRIVATE_JWK), ALG, false, ["sign"]);
  const p = b64(te.encode(label));
  return "ML1." + p + "." + b64(await crypto.subtle.sign(SIG, k, te.encode("ML1." + p)));
}

async function verifica(env, code) {
  try {
    const V = JSON.parse(env.LIC_PRIVATE_JWK);
    const p = String(code || "").replace(/\s+/g, "").split(".");
    if (p.length !== 3 || p[0] !== "ML1") return null;
    const k = await crypto.subtle.importKey("jwk", { kty: V.kty, crv: V.crv, x: V.x, y: V.y }, ALG, false, ["verify"]);
    return (await crypto.subtle.verify(SIG, k, unb64(p[2]), te.encode("ML1." + p[1]))) ? p[1] : null;
  } catch (e) { return null; }
}

async function mp(env, url, opt = {}) {
  return fetch("https://api.mercadopago.com" + url, {
    ...opt,
    headers: { authorization: "Bearer " + env.MP_ACCESS_TOKEN, "content-type": "application/json" }
  });
}

export default {
  async fetch(req, env) {
    const corsResp = cors(req);
    if (corsResp) return corsResp;

    const u = new URL(req.url);
    const path = u.pathname;

    try {
      if (path === "/api/comprar" && req.method === "POST") {
        const ref = "ML-" + crypto.randomUUID();
        const r = await mp(env, "/checkout/preferences", {
          method: "POST",
          body: JSON.stringify({
            items: [{ title: "Miniloja Relâmpago - licença vitalícia", quantity: 1, currency_id: "BRL", unit_price: preco(env) }],
            external_reference: ref,
            back_urls: { success: u.origin + "/", pending: u.origin + "/", failure: u.origin + "/" },
            auto_return: "approved"
          })
        });
        const d = await r.json();
        if (!d.init_point) return J({ erro: "O Mercado Pago recusou o pedido" }, 502);
        await env.LOJAS.put("ord:" + ref, "1", { expirationTtl: 2592000 });
        return J({ url: d.init_point, ref });
      }

      if (path === "/api/licenca" && req.method === "GET") {
        const pid = u.searchParams.get("payment_id") || "";
        const ref = u.searchParams.get("ref") || "";
        if (!/^\d+$/.test(pid) || !ref) return J({ erro: "Dados inválidos" }, 400);

        const ja = await env.LOJAS.get("pag:" + pid, "json");
        if (ja) return ja.ref === ref ? J({ code: ja.code }) : J({ erro: "Pagamento já utilizado" }, 403);

        if (!(await env.LOJAS.get("ord:" + ref))) return J({ erro: "Pedido não encontrado" }, 404);

        const p = await (await mp(env, "/v1/payments/" + pid)).json();
        if (p.external_reference !== ref) return J({ erro: "Este pagamento não pertence ao pedido" }, 403);
        if (p.status !== "approved") return J({ pendente: true, status: p.status });
        if (+p.transaction_amount < preco(env)) return J({ erro: "Valor pago menor que o da licença" }, 403);

        const nome = (p.payer && (p.payer.first_name || (p.payer.email || "").split("@")[0])) || "cliente";
        const code = await assina(env, nome + " #" + pid.slice(-4));
        await env.LOJAS.put("pag:" + pid, JSON.stringify({ ref, code }));
        return J({ code });
      }

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

        await env.LOJAS.put("loja:" + slug, JSON.stringify({ dono, t: b.t, d, em: Date.now() }));
        return J({ slug, url: u.origin + "/" + slug });
      }

      if (path.startsWith("/api/loja/") && req.method === "GET") {
        const slug = decodeURIComponent(path.slice(10));
        const v = await env.LOJAS.get("loja:" + slug, "json");
        return v ? J({ t: v.t, d: v.d }) : J({ erro: "Loja não encontrada" }, 404);
      }

      if (path === "/api/health") {
        return J({ ok: true, timestamp: Date.now() });
      }

    } catch (e) {
      return J({ erro: "Falha interna" }, 500);
    }

    return env.ASSETS ? env.ASSETS.fetch(req) : new Response("Não encontrado", { status: 404 });
  }
};
