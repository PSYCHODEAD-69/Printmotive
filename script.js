/* ============================================================
   PRINTMOTIVE — script.js  (Updated: Dynamic Products + API)
   ============================================================ */

/* ── CONFIG ── */
const WA_NUMBER  = "916267159304";
const EMAIL      = "printmotive.in@gmail.com";
const BRAND_NAME = "PrintMotive.in";
const WEBSITE    = "printmotive.in";

/* ── API URL — Replace with your Cloudflare Worker URL ── */
const PM_API = "https://printmotive-worker.devpandey618.workers.dev";

/* ══════════════════════════════════════
   PRODUCTS — Dynamic load from API
   ══════════════════════════════════════ */
let allProducts     = [];
let currentCategory = "all";

async function loadProducts() {
  try {
    const res      = await fetch(`${PM_API}/api/products`);
    const products = await res.json();
    allProducts    = Array.isArray(products) ? products : [];
    renderProducts(allProducts);
    updateCategoryBadges(allProducts);
  } catch (err) {
    console.error("Failed to load products:", err);
    document.getElementById("productsGrid").innerHTML = "";
    document.getElementById("noProducts").style.display = "block";
    document.getElementById("noProducts").innerHTML =
      `<p style="font-size:1.1rem;">Could not load products. Please refresh.</p>`;
  }
}

function renderProducts(products) {
  const grid      = document.getElementById("productsGrid");
  const noProds   = document.getElementById("noProducts");
  if (!grid) return;

  const filtered = currentCategory === "all"
    ? products
    : products.filter(p => p.category === currentCategory);

  if (!filtered.length) {
    grid.innerHTML   = "";
    noProds.style.display = "block";
    return;
  }
  noProds.style.display = "none";

  grid.innerHTML = filtered.map(p => `
    <div class="product-card fade-up" data-cat="${p.category}" data-id="${p.id}">
      ${p.badge ? `<div class="pc-badge">${p.badge}</div>` : ""}
      <div class="pc-img-wrap">
        <img
          src="${p.imageUrl || "https://via.placeholder.com/300x300?text=No+Image"}"
          alt="${escapeHtml(p.name)}"
          loading="lazy"
          onerror="this.src='https://via.placeholder.com/300x300?text=No+Image'"
        />
      </div>
      <div class="pc-body">
        <div class="pc-cat">${categoryLabel(p.category)}</div>
        <div class="pc-name">${escapeHtml(p.name)}</div>
        ${p.description ? `<div class="pc-desc">${escapeHtml(p.description)}</div>` : ""}
        <div class="pc-price-row">
          <span class="pc-price">${escapeHtml(p.price)}</span>
          <span class="pc-price-tag">Starting price</span>
        </div>
        <div class="pc-btns">
          <button class="pc-btn-cart"
            data-product="${escapeHtml(p.name)}"
            data-price="${escapeHtml(p.price)}"
            data-desc="${escapeHtml(p.description || p.name)}"
            onclick="addToCart(this)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" width="15" height="15"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/></svg>
            Add to Cart
          </button>
          <button class="pc-btn-order"
            data-product="${escapeHtml(p.name)}"
            data-price="${escapeHtml(p.price)}"
            data-desc="${escapeHtml(p.description || p.name)}"
            onclick="orderProduct(this)">
            Order Now
          </button>
        </div>
      </div>
    </div>
  `).join("");

  // Re-init tilt and scroll reveal on new cards
  initCardTilt();
  initScrollReveal();
}

function filterCategory(cat) {
  currentCategory = cat;
  document.querySelectorAll(".cat-card").forEach(c => {
    c.classList.toggle("active", c.dataset.cat === cat);
  });
  renderProducts(allProducts);
}

function updateCategoryBadges(products) {
  const counts = { all: products.length };
  products.forEach(p => {
    counts[p.category] = (counts[p.category] || 0) + 1;
  });
  Object.entries(counts).forEach(([cat, count]) => {
    const badge = document.getElementById(`badge-${cat}`);
    if (badge) badge.textContent = count;
  });
}

function categoryLabel(cat) {
  const map = {
    mugs:       "Mugs",
    tshirts:    "T-Shirts",
    caps:       "Caps",
    homeDecor:  "Home Decor",
    covers:     "Phone Covers",
    accessories:"Accessories",
  };
  return map[cat] || cat;
}

/* ══════════════════════════════════════
   FEATURED REVIEWS — Latest 3 on homepage
   ══════════════════════════════════════ */
async function loadFeaturedReviews() {
  const container = document.getElementById("featuredReviews");
  if (!container) return;

  try {
    const res     = await fetch(`${PM_API}/api/reviews`);
    const reviews = await res.json();
    const latest  = (Array.isArray(reviews) ? reviews : []).slice(0, 3);

    if (!latest.length) {
      container.innerHTML = `
        <div style="grid-column:1/-1;text-align:center;padding:2rem;color:var(--muted);">
          <p>No reviews yet. <a href="reviews.html?focus=add" style="color:var(--accent);">Be the first to review!</a></p>
        </div>`;
      return;
    }

    container.innerHTML = latest.map(r => {
      const stars    = "★".repeat(r.rating) + "☆".repeat(5 - r.rating);
      const initials = r.name.split(" ").map(w => w[0]).join("").toUpperCase().slice(0, 2);
      const date     = new Date(r.createdAt).toLocaleDateString("en-IN", { day:"numeric", month:"short", year:"numeric" });

      // Media preview button if review has attachment
      let mediaBtn = "";
      if (r.mediaUrl) {
        if (r.mediaType === "video") {
          mediaBtn = `<button class="tc-media-btn" onclick="openFeaturedMedia('${r.mediaUrl}','video')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            View Video
          </button>`;
        } else {
          mediaBtn = `<button class="tc-media-btn" onclick="openFeaturedMedia('${r.mediaUrl}','image')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
            View Photo
          </button>`;
        }
      }

      return `
        <div class="testi-card fade-up">
          <div class="tc-stars">${stars}</div>
          <p class="tc-text">"${escapeHtml(r.text)}"</p>
          ${mediaBtn}
          <div class="tc-author">
            <div class="tc-avatar">${initials}</div>
            <div>
              <div class="tc-name">${escapeHtml(r.name)}</div>
              <div class="tc-date">${date}</div>
            </div>
          </div>
        </div>
      `;
    }).join("");

    initScrollReveal();
  } catch {
    container.innerHTML = `
      <div style="grid-column:1/-1;text-align:center;padding:2rem;color:var(--muted);">
        <p>Could not load reviews.</p>
      </div>`;
  }
}

/* ══════════════════════════════════════
   FEATURED REVIEW MEDIA LIGHTBOX
   ══════════════════════════════════════ */
function openFeaturedMedia(url, type) {
  const old = document.getElementById("pm-media-lb");
  if (old) old.remove();

  const lb = document.createElement("div");
  lb.id = "pm-media-lb";
  lb.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.92);display:flex;align-items:center;justify-content:center;z-index:9999;opacity:0;transition:opacity .25s;";

  lb.innerHTML = type === "video"
    ? `<video src="${url}" controls autoplay playsinline style="max-width:92vw;max-height:92vh;border-radius:12px;"></video>`
    : `<img src="${url}" style="max-width:92vw;max-height:92vh;border-radius:12px;object-fit:contain;">`;

  const closeBtn = document.createElement("button");
  closeBtn.innerHTML = "&times;";
  closeBtn.style.cssText = "position:absolute;top:20px;right:24px;background:none;border:none;color:white;font-size:2.5rem;cursor:pointer;line-height:1;z-index:1;";
  lb.appendChild(closeBtn);

  document.body.appendChild(lb);
  document.body.style.overflow = "hidden";
  requestAnimationFrame(() => lb.style.opacity = "1");

  function close() {
    lb.style.opacity = "0";
    document.body.style.overflow = "";
    setTimeout(() => lb.remove(), 250);
  }
  closeBtn.addEventListener("click", close);
  lb.addEventListener("click", e => { if (e.target === lb) close(); });
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
  });
}

// Inject tc-media-btn CSS once
(function() {
  const s = document.createElement("style");
  s.textContent = `
    .tc-media-btn {
      display: inline-flex; align-items: center; gap: 6px;
      background: none; border: 1.5px solid var(--border);
      border-radius: 20px; padding: 5px 12px;
      font-family: 'DM Sans', sans-serif; font-size: 0.78rem;
      font-weight: 600; color: var(--ink2); cursor: pointer;
      margin-bottom: 12px; transition: all .2s;
    }
    .tc-media-btn:hover { border-color: var(--accent); color: var(--accent); }
  `;
  document.head.appendChild(s);
})();
function buildWALink(product, price, desc) {
  const msg = [
    `Hello ${BRAND_NAME}!`,
    ``,
    `I want to place an order for:`,
    `Product: ${product}`,
    `Starting Price: ${price}`,
    `Details: ${desc}`,
    ``,
    `Please help me with customisation and order details.`,
    ``,
    `(Sent from ${WEBSITE})`
  ].join("\n");
  return `https://wa.me/${WA_NUMBER}?text=${encodeURIComponent(msg)}`;
}

function buildEmailLink(product, price, desc) {
  const subject = `Order Enquiry: ${product} — ${BRAND_NAME}`;
  const body = [
    `Hello ${BRAND_NAME},`,
    ``,
    `I would like to place an order for the following:`,
    ``,
    `Product     : ${product}`,
    `Starting Price : ${price}`,
    `Details     : ${desc}`,
    ``,
    `Please share customisation options and confirm the order.`,
    ``,
    `Thank you!`,
    ``,
    `(Sent from ${WEBSITE})`
  ].join("\n");
  return `mailto:${EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

function buildGeneralWALink() {
  const msg = [
    `Hello ${BRAND_NAME}!`,
    ``,
    `I'd like to enquire about your custom printing services.`,
    `Please help me get started!`,
    ``,
    `(Sent from ${WEBSITE})`
  ].join("\n");
  return `https://wa.me/${WA_NUMBER}?text=${encodeURIComponent(msg)}`;
}

/* ══════════════════════════════════════
   ORDER POPUP MODAL
   ══════════════════════════════════════ */
function orderProduct(el) {
  const product = el.dataset.product || "Custom Product";
  const price   = el.dataset.price   || "Contact for pricing";
  const desc    = el.dataset.desc    || "Custom print order";
  addRipple(el);
  showOrderModal(product, price, desc);
}

function showOrderModal(product, price, desc) {
  const old = document.getElementById("pm-modal");
  if (old) old.remove();

  const modal = document.createElement("div");
  modal.id = "pm-modal";
  modal.innerHTML = `
    <div class="pm-modal-backdrop"></div>
    <div class="pm-modal-box">
      <button class="pm-modal-close" aria-label="Close">&times;</button>
      <div class="pm-modal-tag">Place Your Order</div>
      <div class="pm-modal-product">${escapeHtml(product)}</div>
      <div class="pm-modal-price">${escapeHtml(price)}</div>
      <p class="pm-modal-desc">Choose how you'd like to connect with us:</p>
      <div class="pm-modal-btns">
        <a href="#" target="_blank" class="pm-btn-wa" id="pmBtnWA">
          <svg viewBox="0 0 24 24" fill="white" width="20" height="20"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
          Order via WhatsApp
        </a>
        <a href="${buildEmailLink(product, price, desc)}" class="pm-btn-email">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          Order via Email
        </a>
      </div>
      <div class="pm-modal-or"><span>or</span></div>
      <a href="https://instagram.com/printmotive.in" target="_blank" class="pm-btn-ig">
        <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/></svg>
        DM on Instagram
      </a>
    </div>
  `;

  document.body.appendChild(modal);
  document.body.style.overflow = "hidden";
  requestAnimationFrame(() => requestAnimationFrame(() => modal.classList.add("pm-modal-open")));

  function closeModal() {
    modal.classList.remove("pm-modal-open");
    document.body.style.overflow = "";
    setTimeout(() => modal.remove(), 300);
  }

  modal.querySelector(".pm-modal-backdrop").addEventListener("click", closeModal);
  modal.querySelector(".pm-modal-close").addEventListener("click", closeModal);
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { closeModal(); document.removeEventListener("keydown", esc); }
  });

  modal.querySelector("#pmBtnWA").addEventListener("click", function(e) {
    e.preventDefault();
    showDeliveryPopup("wa", buildWALink(product, price, desc), null, product, price);
    closeModal();
  });

  modal.querySelector(".pm-btn-email").addEventListener("click", function(e) {
    e.preventDefault();
    showDeliveryPopup("email", null, buildEmailLink(product, price, desc), product, price);
    closeModal();
  });

  modal.querySelectorAll("a:not(#pmBtnWA):not(.pm-btn-email)").forEach(a => {
    a.addEventListener("click", () => setTimeout(closeModal, 400));
  });
}

/* ══════════════════════════════════════
   WA LINK INIT
   ══════════════════════════════════════ */
function initWALinks() {
  const general = buildGeneralWALink();
  ["floatWA", "waGeneralBtn", "footerWA", "footerWA2"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.href = general;
  });
}

/* ══════════════════════════════════════
   TOAST
   ══════════════════════════════════════ */
let _toastTimer;
function showToast(msg) {
  let t = document.getElementById("pm-toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "pm-toast"; t.className = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove("show"), 2400);
}

/* ══════════════════════════════════════
   RIPPLE
   ══════════════════════════════════════ */
function addRipple(el) {
  const old = el.querySelector(".pm-ripple");
  if (old) old.remove();
  const r = document.createElement("span");
  r.className = "pm-ripple";
  Object.assign(r.style, {
    position:"absolute", borderRadius:"50%",
    background:"rgba(255,255,255,0.3)",
    width:"160px", height:"160px",
    top:"50%", left:"50%",
    transform:"translate(-50%,-50%) scale(0)",
    animation:"pmRipple 0.5s ease-out forwards",
    pointerEvents:"none", zIndex:"10"
  });
  if (getComputedStyle(el).position === "static") el.style.position = "relative";
  el.style.overflow = "hidden";
  el.appendChild(r);
  setTimeout(() => r.remove(), 520);
}

/* ══════════════════════════════════════
   NAVBAR SCROLL
   ══════════════════════════════════════ */
function initNavbar() {
  const nav = document.getElementById("navbar");
  if (!nav) return;
  const update = () => nav.classList.toggle("scrolled", window.scrollY > 50);
  window.addEventListener("scroll", update, { passive: true });
  update();
}

/* ══════════════════════════════════════
   HAMBURGER DRAWER
   ══════════════════════════════════════ */
function initHamburger() {
  const btn      = document.getElementById("hamburger");
  const drawer   = document.getElementById("drawer");
  const backdrop = document.getElementById("drawerBackdrop");
  const closeBtn = document.getElementById("drawerClose");
  if (!btn || !drawer || !backdrop) return;

  function open() {
    drawer.classList.add("open"); backdrop.classList.add("open");
    btn.classList.add("open"); document.body.style.overflow = "hidden";
  }
  function close() {
    drawer.classList.remove("open"); backdrop.classList.remove("open");
    btn.classList.remove("open"); document.body.style.overflow = "";
  }

  btn.addEventListener("click", () => drawer.classList.contains("open") ? close() : open());
  backdrop.addEventListener("click", close);
  if (closeBtn) closeBtn.addEventListener("click", close);
  document.querySelectorAll(".dl").forEach(a => a.addEventListener("click", close));
  document.addEventListener("keydown", e => { if (e.key === "Escape") close(); });
}

/* ══════════════════════════════════════
   SCROLL REVEAL
   ══════════════════════════════════════ */
function initScrollReveal() {
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) { e.target.classList.add("visible"); io.unobserve(e.target); }
    });
  }, { threshold: 0.08 });
  document.querySelectorAll(".fade-up:not(.visible)").forEach(el => io.observe(el));

  const stepsIO = new IntersectionObserver(entries => {
    if (entries[0].isIntersecting) {
      document.querySelectorAll(".step-card").forEach(c => c.classList.add("visible"));
      stepsIO.disconnect();
    }
  }, { threshold: 0.15 });
  const sg = document.querySelector(".steps-grid");
  if (sg) stepsIO.observe(sg);
}

/* ══════════════════════════════════════
   MARQUEE
   ══════════════════════════════════════ */
function initMarquee() {
  const m = document.getElementById("marquee");
  if (m) m.innerHTML += m.innerHTML;
}

/* ══════════════════════════════════════
   SMOOTH SCROLL
   ══════════════════════════════════════ */
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener("click", e => {
      const target = document.querySelector(a.getAttribute("href"));
      if (!target) return;
      e.preventDefault();
      window.scrollTo({ top: target.getBoundingClientRect().top + window.scrollY - 72, behavior: "smooth" });
    });
  });
}

/* ══════════════════════════════════════
   COUNTER ANIMATION
   ══════════════════════════════════════ */
function animateCount(el, target, suffix) {
  let start;
  const dur = 1500;
  const step = ts => {
    if (!start) start = ts;
    const p    = Math.min((ts - start) / dur, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.floor(ease * target) + suffix;
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function initCounters() {
  let done = false;
  const io = new IntersectionObserver(entries => {
    if (entries[0].isIntersecting && !done) {
      done = true;
      document.querySelectorAll(".stat-num[data-target]").forEach(el => {
        animateCount(el, parseInt(el.dataset.target), el.dataset.suffix || "");
      });
      io.disconnect();
    }
  }, { threshold: 0.5 });
  const hero = document.getElementById("hero");
  if (hero) io.observe(hero);
}

/* ══════════════════════════════════════
   PRODUCT CARD TILT
   ══════════════════════════════════════ */
function initCardTilt() {
  document.querySelectorAll(".product-card").forEach(card => {
    card.addEventListener("mousemove", e => {
      const r = card.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width  - 0.5;
      const y = (e.clientY - r.top)  / r.height - 0.5;
      card.style.transform = `translateY(-8px) rotateY(${x * 6}deg) rotateX(${-y * 6}deg)`;
    });
    card.addEventListener("mouseleave", () => { card.style.transform = ""; });
  });
}

/* ══════════════════════════════════════
   CART SYSTEM
   ══════════════════════════════════════ */
let cart = [];

function saveCart() {
  localStorage.setItem("pm_cart", JSON.stringify(cart));
}

function loadCart() {
  try {
    const saved = localStorage.getItem("pm_cart");
    if (saved) cart = JSON.parse(saved);
  } catch { cart = []; }
}

function addToCart(el) {
  const product  = el.dataset.product;
  const price    = el.dataset.price;
  const desc     = el.dataset.desc;
  const priceNum = parseInt(price.replace(/[^0-9]/g, "")) || 0;

  const existing = cart.find(i => i.product === product);
  if (existing) {
    existing.qty++;
  } else {
    cart.push({ product, price, priceNum, desc, qty: 1 });
  }
  saveCart();
  updateCartBadge();
  addRipple(el);
  showToast(`✓ ${product} added to cart!`);
}

function updateCartBadge() {
  const total = cart.reduce((s, i) => s + i.qty, 0);
  const badge = document.getElementById("cartCount");
  if (!badge) return;
  badge.textContent = total;
  badge.classList.toggle("has-items", total > 0);
}

function renderCartItems() {
  const itemsEl  = document.getElementById("cartItems");
  const footerEl = document.getElementById("cartFooter");
  const totalEl  = document.getElementById("cartTotal");
  if (!itemsEl) return;

  if (cart.length === 0) {
    itemsEl.innerHTML = `
      <div class="cart-empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="#ccc" stroke-width="1.5" width="52" height="52">
          <circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/>
          <path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/>
        </svg>
        <p>Your cart is empty!</p>
        <small>Add products to get started</small>
      </div>`;
    if (footerEl) footerEl.style.display = "none";
    return;
  }

  const grandTotal = cart.reduce((s, i) => s + i.priceNum * i.qty, 0);
  if (footerEl) footerEl.style.display = "block";
  if (totalEl)  totalEl.textContent = `Rs.${grandTotal}`;

  itemsEl.innerHTML = cart.map((item, idx) => `
    <div class="cart-item">
      <div class="ci-info">
        <div class="ci-name">${escapeHtml(item.product)}</div>
        <div class="ci-price">${escapeHtml(item.price)} each &nbsp;·&nbsp;
          <span class="ci-subtotal">Rs.${item.priceNum * item.qty}</span>
        </div>
      </div>
      <div class="ci-qty">
        <button onclick="cartChangeQty(${idx}, -1)">&#8722;</button>
        <span>${item.qty}</span>
        <button onclick="cartChangeQty(${idx}, 1)">&#43;</button>
      </div>
      <button class="ci-remove" onclick="cartRemove(${idx})" title="Remove">&times;</button>
    </div>
  `).join("");
}

function cartChangeQty(idx, delta) {
  cart[idx].qty += delta;
  if (cart[idx].qty <= 0) cart.splice(idx, 1);
  saveCart(); updateCartBadge(); renderCartItems();
}

function cartRemove(idx) {
  cart.splice(idx, 1);
  saveCart(); updateCartBadge(); renderCartItems();
}

function openCart() {
  renderCartItems();
  document.getElementById("cart-drawer").classList.add("open");
  document.getElementById("cart-backdrop").classList.add("open");
  document.body.style.overflow = "hidden";
}

function closeCart() {
  document.getElementById("cart-drawer").classList.remove("open");
  document.getElementById("cart-backdrop").classList.remove("open");
  document.body.style.overflow = "";
}

function buildCartMsg() {
  const total = cart.reduce((s, i) => s + i.priceNum * i.qty, 0);
  return [
    `Hello ${BRAND_NAME}!`,
    ``,
    `I want to place an order for the following items:`,
    ``,
    ...cart.map(i => `• ${i.product} x${i.qty}  —  ${i.price} each  =  Rs.${i.priceNum * i.qty}`),
    ``,
    `Grand Total: Rs.${total}`,
    ``,
    `Please help me with customisation and order details.`,
    ``,
    `(Sent from ${WEBSITE})`
  ].join("\n");
}

function cartOrderWA() {
  if (cart.length === 0) { showToast("Cart is empty!"); return; }
  const total = cart.reduce((s, i) => s + i.priceNum * i.qty, 0);
  const cartMsg = buildCartMsg();
  closeCart();
  showDeliveryPopup("wa", `https://wa.me/${WA_NUMBER}?text=${encodeURIComponent(cartMsg)}`, null, null, null, true);
}

function cartOrderEmail() {
  if (cart.length === 0) { showToast("Cart is empty!"); return; }
  const total      = cart.reduce((s, i) => s + i.priceNum * i.qty, 0);
  const subject    = `Cart Order — ${BRAND_NAME} (Rs.${total})`;
  const emailLink  = `mailto:${EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(buildCartMsg())}`;
  closeCart();
  showDeliveryPopup("email", null, emailLink, null, null, true);
}

/* ══════════════════════════════════════
   DELIVERY POPUP — naam/phone/address
   Saves to KV via API before redirecting
   ══════════════════════════════════════ */
function showDeliveryPopup(type, waLink, emailLink, product, price, isCart) {
  const old = document.getElementById("pm-delivery-popup");
  if (old) old.remove();

  const popup = document.createElement("div");
  popup.id = "pm-delivery-popup";
  popup.innerHTML = `
    <div class="pm-dp-backdrop"></div>
    <div class="pm-dp-box">
      <div class="pm-dp-title">📦 Delivery Details</div>
      <p class="pm-dp-sub">Fill in your details so we know where to deliver</p>
      <input type="text"  id="dpName"    class="pm-dp-input" placeholder="Your Name *"         maxlength="60"/>
      <input type="tel"   id="dpPhone"   class="pm-dp-input" placeholder="Phone Number *"      maxlength="15"/>
      <textarea           id="dpAddress" class="pm-dp-input pm-dp-textarea" rows="2"
        placeholder="Delivery Address *" maxlength="200"></textarea>
      <div class="pm-dp-btns">
        <button class="pm-dp-cancel"  id="dpCancel">Cancel</button>
        <button class="pm-dp-confirm" id="dpConfirm">Confirm &amp; Order</button>
      </div>
    </div>
  `;

  document.body.appendChild(popup);
  document.body.style.overflow = "hidden";
  requestAnimationFrame(() => requestAnimationFrame(() => popup.classList.add("pm-dp-open")));

  setTimeout(() => document.getElementById("dpName")?.focus(), 350);

  function closePopup() {
    popup.classList.remove("pm-dp-open");
    document.body.style.overflow = "";
    setTimeout(() => popup.remove(), 300);
  }

  popup.querySelector("#dpCancel").addEventListener("click", closePopup);
  popup.querySelector(".pm-dp-backdrop").addEventListener("click", closePopup);
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { closePopup(); document.removeEventListener("keydown", esc); }
  });

  popup.querySelector("#dpConfirm").addEventListener("click", async function() {
    const name    = (document.getElementById("dpName")?.value    || "").trim();
    const phone   = (document.getElementById("dpPhone")?.value   || "").trim();
    const address = (document.getElementById("dpAddress")?.value || "").trim();

    if (!name)    { showToast("Please enter your name!");             document.getElementById("dpName")?.focus();    return; }
    if (!phone)   { showToast("Please enter your phone number!");     document.getElementById("dpPhone")?.focus();   return; }
    if (!address) { showToast("Please enter your delivery address!"); document.getElementById("dpAddress")?.focus(); return; }

    // Build items array
    let items = [];
    let total = 0;
    if (isCart) {
      items = cart.map(i => ({ product: i.product, price: i.price, qty: i.qty }));
      total = cart.reduce((s, i) => s + i.priceNum * i.qty, 0);
    } else if (product) {
      items = [{ product, price, qty: 1 }];
      total = parseInt((price || "0").replace(/[^0-9]/g, "")) || 0;
    }

    // Save order to KV (non-blocking — don't wait for it to open WA/email)
    saveOrderToAPI({ name, phone, address, items, total, type }).catch(() => {});

    // Append delivery details to message
    function appendDetails(link) {
      const details = `\n---\nOrder by: ${name}\nPhone: ${phone}\nDelivery Address: ${address}`;
      if (link.startsWith("https://wa.me/")) {
        const u = new URL(link);
        u.searchParams.set("text", decodeURIComponent(u.searchParams.get("text") || "") + details);
        return u.toString();
      } else if (link.startsWith("mailto:")) {
        const u = new URL(link);
        u.searchParams.set("body", decodeURIComponent(u.searchParams.get("body") || "") + details);
        return u.toString();
      }
      return link;
    }

    if (type === "wa"    && waLink)    window.open(appendDetails(waLink), "_blank");
    if (type === "email" && emailLink) window.open(appendDetails(emailLink));

    if (isCart) { cart = []; saveCart(); updateCartBadge(); }
    closePopup();
  });
}

/* ══════════════════════════════════════
   SAVE ORDER TO API
   ══════════════════════════════════════ */
async function saveOrderToAPI(orderData) {
  try {
    await fetch(`${PM_API}/api/orders`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(orderData)
    });
  } catch { /* silently fail — WhatsApp/email still opened */ }
}

/* ══════════════════════════════════════
   HELPER — HTML escape
   ══════════════════════════════════════ */
function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ══════════════════════════════════════
   BOOT
   ══════════════════════════════════════ */
document.addEventListener("DOMContentLoaded", () => {
  loadCart();
  updateCartBadge();
  initWALinks();
  initNavbar();
  initHamburger();
  initScrollReveal();
  initMarquee();
  initSmoothScroll();
  initCounters();

  // Dynamic data from API
  loadProducts();
  loadFeaturedReviews();

  console.log("%cPrintMotive loaded!", "color:#ff4d2e;font-weight:bold;font-size:14px");
});
