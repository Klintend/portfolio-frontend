/**
 * ============================================================
 *  security.js — Portfolio Security Layer
 *  Author  : Uffoh Chukwuka Clinton
 *  Purpose : Bot protection, input sanitisation, rate limiting,
 *            XSS defence, clickjacking guard, and honeypot traps.
 *
 *  HOW TO LINK:
 *  Add this line just before </body> in uffoh_portfolio.html:
 *  <script src="security.js"></script>
 * ============================================================
 */

(function () {
  "use strict";

  /* ============================================================
   *  1. ENVIRONMENT GUARD
   *  Blocks execution in non-browser contexts (e.g. Node scrapers
   *  that partially execute JS without a real DOM/window).
   * ============================================================ */
  if (typeof window === "undefined" || typeof document === "undefined") return;


  /* ============================================================
   *  2. CLICKJACKING DEFENCE
   *  If this page is loaded inside an <iframe> by another origin,
   *  break out immediately and redirect the top frame to us.
   *  Complements the X-Frame-Options / CSP headers your server
   *  should also send (see comments at bottom of file).
   * ============================================================ */
  (function guardFraming() {
    try {
      if (window.self !== window.top) {
        window.top.location.href = window.self.location.href;
      }
    } catch (e) {
      // Cross-origin access to window.top threw — we're inside a
      // sandboxed iframe. Hide content so it can't be used as a
      // clickjacking overlay.
      document.documentElement.style.display = "none";
    }
  })();


  /* ============================================================
   *  3. XSS INPUT SANITISER
   *  Strips HTML tags and dangerous characters from any string
   *  before it is rendered into the DOM or sent anywhere.
   *  Use: SecurityLayer.sanitise(userInput)
   * ============================================================ */
  function sanitise(str) {
    if (typeof str !== "string") return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;")
      .replace(/\//g, "&#x2F;")
      .replace(/`/g, "&#x60;")
      .replace(/=/g, "&#x3D;")
      .trim();
  }

  /* Validates an email address format */
  function isValidEmail(email) {
    return /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(email);
  }

  /* Validates a phone number (digits, spaces, +, -, parentheses) */
  function isValidPhone(phone) {
    return /^[\d\s\+\-\(\)]{7,20}$/.test(phone);
  }


  /* ============================================================
   *  4. CSRF TOKEN
   *  Generates a per-session token stored in sessionStorage.
   *  Attach it as a hidden field or header on any form submission
   *  to verify requests come from your own page.
   * ============================================================ */
  const CSRF = (function () {
    const KEY = "uc_csrf_token";

    function generate() {
      const arr = new Uint8Array(32);
      crypto.getRandomValues(arr);
      return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
    }

    function getOrCreate() {
      let token = sessionStorage.getItem(KEY);
      if (!token) {
        token = generate();
        sessionStorage.setItem(KEY, token);
      }
      return token;
    }

    function verify(token) {
      return token === sessionStorage.getItem(KEY);
    }

    return { getOrCreate, verify };
  })();


  /* ============================================================
   *  5. BOT DETECTION
   *  Uses several passive signals to score the likelihood of
   *  automated traffic:
   *    – Mouse movement (bots rarely move the mouse)
   *    – Keyboard events
   *    – Touch events (mobile humans)
   *    – Time-on-page before form interaction
   *    – Honeypot hidden field filled (bots auto-fill everything)
   *    – Navigator properties that headless browsers expose
   * ============================================================ */
  const BotDetector = (function () {
    let score = 0; // higher = more bot-like, starts neutral
    let mouseMoved = false;
    let keyPressed = false;
    let touchUsed = false;
    const pageLoadTime = Date.now();

    /* Passive interaction signals */
    document.addEventListener("mousemove", function onMove() {
      mouseMoved = true;
      score = Math.max(score - 2, 0);
      document.removeEventListener("mousemove", onMove);
    }, { passive: true });

    document.addEventListener("keydown", function onKey() {
      keyPressed = true;
      score = Math.max(score - 1, 0);
      document.removeEventListener("keydown", onKey);
    }, { passive: true });

    document.addEventListener("touchstart", function onTouch() {
      touchUsed = true;
      score = Math.max(score - 3, 0);
      document.removeEventListener("touchstart", onTouch);
    }, { passive: true });

    /* Headless browser fingerprinting */
    function checkHeadlessSignals() {
      const nav = navigator;
      let botPoints = 0;

      // Puppeteer / Playwright exposes this
      if (nav.webdriver) botPoints += 5;

      // Unusual plugin count (headless = 0)
      if (nav.plugins && nav.plugins.length === 0) botPoints += 2;

      // Languages missing in headless contexts
      if (!nav.languages || nav.languages.length === 0) botPoints += 2;

      // Screen size 0 — common in headless
      if (window.screen.width === 0 || window.screen.height === 0) botPoints += 3;

      // Permission API probe (Playwright often returns "denied" instantly)
      if (navigator.permissions) {
        navigator.permissions.query({ name: "notifications" }).then((p) => {
          if (p.state === "denied" && !mouseMoved) score += 2;
        }).catch(() => {});
      }

      score += botPoints;
    }

    checkHeadlessSignals();

    function isLikelyBot() {
      const humanInteracted = mouseMoved || keyPressed || touchUsed;
      const timeOnPage = (Date.now() - pageLoadTime) / 1000; // seconds
      const tooFast = timeOnPage < 2; // submitted in under 2 seconds

      if (!humanInteracted) score += 4;
      if (tooFast) score += 3;

      return score >= 6;
    }

    return { isLikelyBot, getScore: () => score };
  })();


  /* ============================================================
   *  6. HONEYPOT FIELD INJECTION
   *  Injects a hidden input into every form. Bots fill all
   *  fields; humans never see or touch this one.
   *  If it has a value on submit → reject the submission.
   * ============================================================ */
  function injectHoneypots() {
    document.querySelectorAll("form").forEach((form) => {
      if (form.querySelector("[data-honeypot]")) return; // already injected

      const trap = document.createElement("input");
      trap.type = "text";
      trap.name = "website_url"; // plausible field name bots fill
      trap.setAttribute("data-honeypot", "true");
      trap.setAttribute("autocomplete", "off");
      trap.setAttribute("tabindex", "-1");
      trap.setAttribute("aria-hidden", "true");

      // Visually hidden — not display:none (some bots skip those)
      Object.assign(trap.style, {
        position: "absolute",
        left: "-9999px",
        top: "-9999px",
        width: "1px",
        height: "1px",
        opacity: "0",
        pointerEvents: "none",
      });

      form.appendChild(trap);
    });
  }

  /* Run after DOM is ready */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", injectHoneypots);
  } else {
    injectHoneypots();
  }


  /* ============================================================
   *  7. RATE LIMITER
   *  Prevents the contact form from being submitted more than
   *  MAX_ATTEMPTS times within WINDOW_MS milliseconds.
   * ============================================================ */
  const RateLimiter = (function () {
    const WINDOW_MS = 60 * 1000; // 1 minute window
    const MAX_ATTEMPTS = 3;
    const STORAGE_KEY = "uc_form_attempts";

    function getAttempts() {
      try {
        const raw = sessionStorage.getItem(STORAGE_KEY);
        if (!raw) return [];
        return JSON.parse(raw).filter((t) => Date.now() - t < WINDOW_MS);
      } catch {
        return [];
      }
    }

    function recordAttempt() {
      const attempts = getAttempts();
      attempts.push(Date.now());
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(attempts));
    }

    function isAllowed() {
      return getAttempts().length < MAX_ATTEMPTS;
    }

    function remainingSeconds() {
      const attempts = getAttempts();
      if (attempts.length === 0) return 0;
      const oldest = Math.min(...attempts);
      return Math.ceil((WINDOW_MS - (Date.now() - oldest)) / 1000);
    }

    return { isAllowed, recordAttempt, remainingSeconds };
  })();


  /* ============================================================
   *  8. CONTACT FORM SECURITY WRAPPER
   *  Intercepts the send button, validates inputs, checks bot
   *  signals, enforces rate limiting, and sanitises everything
   *  before it would be sent to a backend.
   * ============================================================ */
  function secureContactForm() {
    const sendBtn = document.getElementById("sendBtn");
    if (!sendBtn) return;

    /* Inject CSRF token display (for debugging; remove in prod) */
    const csrfToken = CSRF.getOrCreate();

    sendBtn.addEventListener("click", function (e) {
      e.preventDefault();

      /* --- Collect inputs --- */
      const nameInput    = document.querySelector('.f-input[placeholder="Your full name"]');
      const emailInput   = document.querySelector('.f-input[type="email"]');
      const messageInput = document.querySelector(".f-textarea");
      const honeypot    = document.querySelector('[data-honeypot="true"]');

      const name    = nameInput    ? nameInput.value    : "";
      const email   = emailInput   ? emailInput.value   : "";
      const message = messageInput ? messageInput.value : "";
      const trapVal = honeypot     ? honeypot.value     : "";

      /* --- Honeypot check --- */
      if (trapVal.length > 0) {
        _silentBlock("Honeypot triggered");
        return;
      }

      /* --- Bot behaviour check --- */
      if (BotDetector.isLikelyBot()) {
        _silentBlock("Bot signals detected (score: " + BotDetector.getScore() + ")");
        return;
      }

      /* --- Rate limit check --- */
      if (!RateLimiter.isAllowed()) {
        const wait = RateLimiter.remainingSeconds();
        _showFormError(sendBtn, "Too many attempts. Please wait " + wait + "s.");
        return;
      }

      /* --- Input validation --- */
      const errors = [];
      if (sanitise(name).length < 2)         errors.push("Please enter your name.");
      if (!isValidEmail(email))               errors.push("Please enter a valid email.");
      if (sanitise(message).length < 10)      errors.push("Message is too short.");
      if (sanitise(message).length > 2000)    errors.push("Message exceeds 2000 characters.");

      if (errors.length > 0) {
        _showFormError(sendBtn, errors[0]);
        return;
      }

      /* --- All checks passed — safe payload --- */
      const safePayload = {
        name:    sanitise(name),
        email:   sanitise(email),
        message: sanitise(message),
        csrf:    csrfToken,
        ts:      Date.now(),
      };

      RateLimiter.recordAttempt();

      /* SUCCESS — replace this block with your real fetch() to a backend */
      console.info("[Security] Clean submission payload:", safePayload);
      _showSuccess(sendBtn);

      /* Clear fields */
      if (nameInput)    nameInput.value    = "";
      if (emailInput)   emailInput.value   = "";
      if (messageInput) messageInput.value = "";
    });
  }

  function _silentBlock(reason) {
    /* Do NOT alert the user — bots should not know they were caught */
    console.warn("[Security] Blocked submission:", reason);
  }

  function _showFormError(btn, msg) {
    btn.textContent = "⚠ " + msg;
    btn.style.background = "#B74040";
    btn.disabled = true;
    setTimeout(() => {
      btn.textContent = "Send message";
      btn.style.background = "";
      btn.disabled = false;
    }, 3500);
  }

  function _showSuccess(btn) {
    btn.textContent = "✓ Sent!";
    btn.style.background = "#3A7D44";
    btn.disabled = true;
    setTimeout(() => {
      btn.textContent = "Send message";
      btn.style.background = "";
      btn.disabled = false;
    }, 3000);
  }


  /* ============================================================
   *  9. CONTENT SECURITY POLICY — RUNTIME META TAG
   *  Injects a CSP meta tag if none is already present.
   *  ⚠ NOTE: Server-sent CSP headers are stronger. This is a
   *  fallback for static hosting (GitHub Pages, Netlify, etc.).
   *  Replace 'your-backend.com' with your real API endpoint.
   * ============================================================ */
  (function injectCSP() {
    if (document.querySelector('meta[http-equiv="Content-Security-Policy"]')) return;

    const csp = document.createElement("meta");
    csp.setAttribute("http-equiv", "Content-Security-Policy");
    csp.setAttribute("content", [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",          // tighten once inline scripts are extracted
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "media-src 'self' data:",
      "connect-src 'self' http://127.0.0.1:3002 https://portfolio-backend-production-8bc9.up.railway.app",
      "frame-ancestors 'none'",                      // reinforces clickjacking guard
      "form-action 'self'",
      "base-uri 'self'",
    ].join("; "));

    document.head.prepend(csp);
  })();


  /* ============================================================
   *  10. DEVTOOLS / COPY-PASTE GUARD (light touch)
   *  Logs a friendly warning in the console for anyone who opens
   *  DevTools — doesn't block legitimate developers, just deters
   *  casual scrapers who follow copy-paste tutorials.
   * ============================================================ */
  (function consoleWarning() {
    const style = "color:#B0723A;font-size:14px;font-weight:bold;";
    const msg   = "color:#4A4845;font-size:12px;";
    console.log("%c⚠ Hey there!", style);
    console.log("%cThis is Uffoh Chukwuka's portfolio. If you're a developer, cool — say hi at uffohchukwuka@gmail.com.\nIf you're scraping or testing exploits, you're being logged.", msg);
  })();


  /* ============================================================
   *  11. BOOT SEQUENCE — run everything when DOM is ready
   * ============================================================ */
  function boot() {
    injectHoneypots();
    secureContactForm();
    CSRF.getOrCreate(); // initialise token early
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }


  /* ============================================================
   *  PUBLIC API — expose utilities for future backend integration
   * ============================================================ */
  window.SecurityLayer = {
    sanitise,
    isValidEmail,
    isValidPhone,
    csrf: CSRF,
    botDetector: BotDetector,
    rateLimiter: RateLimiter,
  };


})(); // end IIFE


/* ============================================================
 *  SERVER-SIDE HEADERS (set these on your hosting platform)
 *  ─────────────────────────────────────────────────────────
 *  These cannot be set from JS — they must come from your
 *  server, CDN (Cloudflare, Netlify, Vercel), or .htaccess.
 *
 *  Recommended headers:
 *
 *  X-Frame-Options: DENY
 *  X-Content-Type-Options: nosniff
 *  X-XSS-Protection: 1; mode=block
 *  Referrer-Policy: strict-origin-when-cross-origin
 *  Permissions-Policy: geolocation=(), microphone=(), camera=()
 *  Strict-Transport-Security: max-age=31536000; includeSubDomains
 *
 *  Netlify  → netlify.toml [[headers]] block
 *  Vercel   → vercel.json "headers" array
 *  Apache   → .htaccess Header set ...
 *  Nginx    → add_header ... in server{} block
 * ============================================================ */