/* ============================================================
   PRINTMOTIVE — Cloudflare Worker Backend
   ============================================================
   KV Namespace: PM_KV
   R2 Bucket:    PM_R2
   Env Vars:     ADMIN_USERNAME, ADMIN_PASSWORD, JWT_SECRET,
                 ALLOWED_ORIGIN (your GitHub Pages URL)
   ============================================================ */

const RATE_LIMIT_WINDOW = 60;   // seconds
const RATE_LIMIT_MAX    = 5;    // max requests per window per IP
const JWT_EXPIRY        = 60 * 60 * 24 * 7; // 7 days in seconds
const MAX_UPLOAD_SIZE   = 40 * 1024 * 1024; // 40 MB

/* ──────────────────────────────────────
   MAIN HANDLER
────────────────────────────────────── */
export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "";
    const allowedOrigin = env.ALLOWED_ORIGIN || "";

    // CORS preflight
    if (request.method === "OPTIONS") {
      return corsResponse(null, 204, origin, allowedOrigin);
    }

    // Block requests not from allowed origin (except same-origin / direct)
    if (origin && allowedOrigin && !isAllowedOrigin(origin, allowedOrigin)) {
      return corsResponse(JSON.stringify({ error: "Forbidden" }), 403, origin, allowedOrigin);
    }

    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    try {
      // ── AUTH ──
      if (path === "/api/auth/login" && method === "POST") {
        return corsResponse(await handleLogin(request, env), 200, origin, allowedOrigin);
      }

      // ── PRODUCTS (public read) ──
      if (path === "/api/products" && method === "GET") {
        return corsResponse(await getProducts(env), 200, origin, allowedOrigin);
      }

      // ── PRODUCTS (admin write) ──
      if (path === "/api/admin/products" && method === "POST") {
        return await adminOnly(request, env, origin, allowedOrigin, () => addProducts(request, env));
      }
      if (path.startsWith("/api/admin/products/") && method === "PUT") {
        const id = path.split("/").pop();
        return await adminOnly(request, env, origin, allowedOrigin, () => editProduct(request, env, id));
      }
      if (path.startsWith("/api/admin/products/") && method === "DELETE") {
        const id = path.split("/").pop();
        return await adminOnly(request, env, origin, allowedOrigin, () => deleteProduct(env, id));
      }

      // ── IMAGE UPLOAD to R2 (admin — products) ──
      if (path === "/api/admin/upload" && method === "POST") {
        return await adminOnly(request, env, origin, allowedOrigin, () => uploadFile(request, env));
      }

      // ── PUBLIC MEDIA UPLOAD (reviews — no auth, rate limited) ──
      if (path === "/api/upload/review-media" && method === "POST") {
        const ip      = request.headers.get("CF-Connecting-IP") || "unknown";
        const limited = await checkRateLimit(env, ip, "upload");
        if (limited) return corsResponse(JSON.stringify({ error: "Too many uploads. Please wait." }), 429, origin, allowedOrigin);
        return corsResponse(await uploadFile(request, env, "reviews"), 200, origin, allowedOrigin);
      }
      if (path.startsWith("/api/admin/delete-file") && method === "DELETE") {
        return await adminOnly(request, env, origin, allowedOrigin, () => deleteFile(request, env));
      }

      // ── ORDERS (public write) ──
      if (path === "/api/orders" && method === "POST") {
        return corsResponse(await saveOrder(request, env), 200, origin, allowedOrigin);
      }
      if (path === "/api/admin/orders" && method === "GET") {
        return await adminOnly(request, env, origin, allowedOrigin, () => getOrders(env));
      }
      if (path.startsWith("/api/admin/orders/") && method === "DELETE") {
        const id = path.split("/").pop();
        return await adminOnly(request, env, origin, allowedOrigin, () => deleteOrder(env, id));
      }

      // ── REVIEWS (public write) ──
      if (path === "/api/reviews" && method === "POST") {
        return corsResponse(await addReview(request, env), 200, origin, allowedOrigin);
      }
      if (path === "/api/reviews" && method === "GET") {
        return corsResponse(await getReviews(env), 200, origin, allowedOrigin);
      }
      if (path.startsWith("/api/admin/reviews/") && method === "DELETE") {
        const id = path.split("/").pop();
        return await adminOnly(request, env, origin, allowedOrigin, () => deleteReview(env, id));
      }

      // ── R2 Public File Serve ──
      if (path.startsWith("/files/")) {
        return await serveFile(path, env);
      }

      return corsResponse(JSON.stringify({ error: "Not found" }), 404, origin, allowedOrigin);

    } catch (err) {
      console.error(err);
      return corsResponse(JSON.stringify({ error: "Internal server error" }), 500, origin, allowedOrigin);
    }
  }
};

/* ──────────────────────────────────────
   CORS HELPERS
────────────────────────────────────── */
function isAllowedOrigin(origin, allowed) {
  // allowed can be comma-separated list
  const list = allowed.split(",").map(s => s.trim());
  return list.some(a => origin === a || origin.startsWith(a));
}

function corsHeaders(origin, allowedOrigin) {
  const allow = (allowedOrigin && isAllowedOrigin(origin, allowedOrigin)) ? origin : allowedOrigin || "*";
  return {
    "Access-Control-Allow-Origin":  allow,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age":       "86400",
  };
}

function corsResponse(body, status, origin, allowedOrigin) {
  const headers = {
    ...corsHeaders(origin, allowedOrigin),
    "Content-Type": "application/json",
  };
  return new Response(body, { status, headers });
}

/* ──────────────────────────────────────
   AUTH — JWT (HS256 via WebCrypto)
────────────────────────────────────── */
async function signJWT(payload, secret) {
  const header  = { alg: "HS256", typ: "JWT" };
  const encode  = obj => btoa(JSON.stringify(obj)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const data    = `${encode(header)}.${encode(payload)}`;
  const key     = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${data}.${b64}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const data    = `${parts[0]}.${parts[1]}`;
    const key     = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const sig = Uint8Array.from(atob(parts[2].replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const ok  = await crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(data));
    if (!ok) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
    return JSON.stringify({ error: "Invalid credentials" });
  }
  const payload = { sub: username, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + JWT_EXPIRY };
  const token   = await signJWT(payload, env.JWT_SECRET);
  return JSON.stringify({ token });
}

async function adminOnly(request, env, origin, allowedOrigin, handler) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.replace("Bearer ", "").trim();
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) {
    return corsResponse(JSON.stringify({ error: "Unauthorized" }), 401, origin, allowedOrigin);
  }
  const result = await handler();
  return corsResponse(result, 200, origin, allowedOrigin);
}

/* ──────────────────────────────────────
   RATE LIMITING (KV based)
────────────────────────────────────── */
async function checkRateLimit(env, ip, key) {
  const rlKey = `rl:${key}:${ip}`;
  const now   = Math.floor(Date.now() / 1000);
  const data  = await env.PM_KV.get(rlKey, "json") || { count: 0, window: now };
  if (now - data.window > RATE_LIMIT_WINDOW) {
    // reset
    await env.PM_KV.put(rlKey, JSON.stringify({ count: 1, window: now }), { expirationTtl: RATE_LIMIT_WINDOW * 2 });
    return false;
  }
  if (data.count >= RATE_LIMIT_MAX) return true; // rate limited
  data.count++;
  await env.PM_KV.put(rlKey, JSON.stringify(data), { expirationTtl: RATE_LIMIT_WINDOW * 2 });
  return false;
}

/* ──────────────────────────────────────
   PRODUCTS
────────────────────────────────────── */
async function getProducts(env) {
  const data = await env.PM_KV.get("products", "json") || [];
  return JSON.stringify(data);
}

async function addProducts(request, env) {
  // Accepts array of products
  const incoming = await request.json(); // array
  const products = await env.PM_KV.get("products", "json") || [];
  const now      = Date.now();
  const newProds = (Array.isArray(incoming) ? incoming : [incoming]).map((p, i) => ({
    id:          `prod_${now}_${i}`,
    name:        p.name        || "",
    price:       p.price       || "",
    priceNum:    parseInt((p.price || "0").replace(/[^0-9]/g, "")) || 0,
    description: p.description || "",
    category:    p.category    || "accessories",
    badge:       p.badge       || "",
    imageUrl:    p.imageUrl    || "",
    r2Key:       p.r2Key       || extractR2Key(p.imageUrl) || null,
    createdAt:   now,
  }));
  const updated = [...products, ...newProds];
  await env.PM_KV.put("products", JSON.stringify(updated));
  return JSON.stringify({ success: true, added: newProds.length, products: newProds });
}

async function editProduct(request, env, id) {
  const products = await env.PM_KV.get("products", "json") || [];
  const idx      = products.findIndex(p => p.id === id);
  if (idx === -1) return JSON.stringify({ error: "Product not found" });
  const updates  = await request.json();
  products[idx]  = {
    ...products[idx],
    ...updates,
    id,
    priceNum: parseInt((updates.price || products[idx].price || "0").replace(/[^0-9]/g, "")) || 0,
    r2Key: updates.r2Key || extractR2Key(updates.imageUrl) || products[idx].r2Key || null,
  };
  await env.PM_KV.put("products", JSON.stringify(products));
  return JSON.stringify({ success: true, product: products[idx] });
}

async function deleteProduct(env, id) {
  const products = await env.PM_KV.get("products", "json") || [];
  const product  = products.find(p => p.id === id);
  if (!product) return JSON.stringify({ error: "Product not found" });

  // Extract R2 key from imageUrl if r2Key not stored
  // R2 URLs: https://assets.psychodead.qzz.io/products/file.jpg
  // Worker URLs: https://printmotive-worker.devpandey618.workers.dev/files/products/file.jpg
  const r2Key = product.r2Key || extractR2Key(product.imageUrl);
  if (r2Key) {
    try { await env.PM_R2.delete(r2Key); } catch {}
  }

  const updated = products.filter(p => p.id !== id);
  await env.PM_KV.put("products", JSON.stringify(updated));
  return JSON.stringify({ success: true });
}

/* ──────────────────────────────────────
   FILE UPLOAD (R2)
────────────────────────────────────── */
async function uploadFile(request, env, folderOverride) {
  const formData   = await request.formData();
  const file       = formData.get("file");
  const folder     = folderOverride || formData.get("folder") || "uploads";

  if (!file) return JSON.stringify({ error: "No file provided" });
  if (file.size > MAX_UPLOAD_SIZE) return JSON.stringify({ error: "File too large. Max 40MB." });

  const ext      = file.name.split(".").pop().toLowerCase();
  const key      = `${folder}/${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`;
  const buffer   = await file.arrayBuffer();

  await env.PM_R2.put(key, buffer, {
    httpMetadata: { contentType: file.type },
  });

  // Public URL via R2 custom domain
  const publicUrl = `https://assets.psychodead.qzz.io/${key}`;
  return JSON.stringify({ success: true, url: publicUrl, key });
}

async function deleteFile(request, env) {
  const { key } = await request.json();
  if (!key) return JSON.stringify({ error: "No key provided" });
  try {
    await env.PM_R2.delete(key);
    return JSON.stringify({ success: true });
  } catch {
    return JSON.stringify({ error: "Delete failed" });
  }
}

// Serve R2 files publicly via Worker
async function serveFile(path, env) {
  const key = path.replace("/files/", "");
  const obj = await env.PM_R2.get(key);
  if (!obj) return new Response("Not found", { status: 404 });
  const headers = new Headers();
  headers.set("Content-Type", obj.httpMetadata?.contentType || "application/octet-stream");
  headers.set("Cache-Control", "public, max-age=31536000");
  headers.set("Access-Control-Allow-Origin", "*");
  return new Response(obj.body, { headers });
}

/* ──────────────────────────────────────
   ORDERS
────────────────────────────────────── */
async function saveOrder(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const limited = await checkRateLimit(env, ip, "order");
  if (limited) return JSON.stringify({ error: "Too many requests. Please wait." });

  const body = await request.json();
  const { name, phone, address, items, total, type } = body;

  if (!name || !phone || !address) return JSON.stringify({ error: "Missing required fields" });

  const id    = `order_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const order = {
    id,
    name:      sanitize(name),
    phone:     sanitize(phone),
    address:   sanitize(address),
    items:     items || [],
    total:     total || 0,
    type:      type || "whatsapp",
    createdAt: Date.now(),
  };

  // Store individual order
  await env.PM_KV.put(`order:${id}`, JSON.stringify(order));

  // Update orders index
  const index = await env.PM_KV.get("orders:index", "json") || [];
  index.unshift(id); // newest first
  await env.PM_KV.put("orders:index", JSON.stringify(index));

  return JSON.stringify({ success: true, id });
}

async function getOrders(env) {
  const index  = await env.PM_KV.get("orders:index", "json") || [];
  const orders = await Promise.all(
    index.map(id => env.PM_KV.get(`order:${id}`, "json"))
  );
  return JSON.stringify(orders.filter(Boolean));
}

async function deleteOrder(env, id) {
  await env.PM_KV.delete(`order:${id}`);
  const index   = await env.PM_KV.get("orders:index", "json") || [];
  const updated = index.filter(i => i !== id);
  await env.PM_KV.put("orders:index", JSON.stringify(updated));
  return JSON.stringify({ success: true });
}

/* ──────────────────────────────────────
   REVIEWS
────────────────────────────────────── */
async function addReview(request, env) {
  const ip      = request.headers.get("CF-Connecting-IP") || "unknown";
  const limited = await checkRateLimit(env, ip, "review");
  if (limited) return JSON.stringify({ error: "Too many requests. Please wait a minute." });

  const body = await request.json();
  const { name, rating, text, mediaUrl, mediaKey, mediaType } = body;

  if (!name || !rating || !text) return JSON.stringify({ error: "Missing required fields" });
  if (rating < 1 || rating > 5)  return JSON.stringify({ error: "Rating must be 1-5" });

  const id     = `review_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const review = {
    id,
    name:      sanitize(name),
    rating:    parseInt(rating),
    text:      sanitize(text),
    mediaUrl:  mediaUrl  || null,
    mediaKey:  mediaKey  || null,
    mediaType: mediaType || null, // "image" or "video"
    createdAt: Date.now(),
  };

  await env.PM_KV.put(`review:${id}`, JSON.stringify(review));

  const index = await env.PM_KV.get("reviews:index", "json") || [];
  index.unshift(id);
  await env.PM_KV.put("reviews:index", JSON.stringify(index));

  return JSON.stringify({ success: true, review });
}

async function getReviews(env) {
  const index   = await env.PM_KV.get("reviews:index", "json") || [];
  const reviews = await Promise.all(
    index.map(id => env.PM_KV.get(`review:${id}`, "json"))
  );
  return JSON.stringify(reviews.filter(Boolean));
}

async function deleteReview(env, id) {
  const review = await env.PM_KV.get(`review:${id}`, "json");
  if (!review) return JSON.stringify({ error: "Review not found" });

  // Extract R2 key from mediaUrl if mediaKey not stored
  const r2Key = review.mediaKey || extractR2Key(review.mediaUrl);
  if (r2Key) {
    try { await env.PM_R2.delete(r2Key); } catch {}
  }

  await env.PM_KV.delete(`review:${id}`);
  const index   = await env.PM_KV.get("reviews:index", "json") || [];
  const updated = index.filter(i => i !== id);
  await env.PM_KV.put("reviews:index", JSON.stringify(updated));
  return JSON.stringify({ success: true });
}

/* ──────────────────────────────────────
   SANITIZE
────────────────────────────────────── */
function sanitize(str) {
  if (typeof str !== "string") return "";
  return str.replace(/</g, "&lt;").replace(/>/g, "&gt;").trim().slice(0, 500);
}

/* ──────────────────────────────────────
   EXTRACT R2 KEY FROM URL
   Handles both:
   - https://assets.psychodead.qzz.io/products/file.jpg  → products/file.jpg
   - https://printmotive-worker.devpandey618.workers.dev/files/products/file.jpg → products/file.jpg
────────────────────────────────────── */
function extractR2Key(url) {
  if (!url) return null;
  // Custom domain: assets.psychodead.qzz.io/KEY
  const customMatch = url.match(/assets\.psychodead\.qzz\.io\/(.+)/);
  if (customMatch) return customMatch[1];
  // Worker /files/ endpoint: /files/KEY
  const workerMatch = url.match(/\/files\/(.+)/);
  if (workerMatch) return workerMatch[1];
  return null;
}
