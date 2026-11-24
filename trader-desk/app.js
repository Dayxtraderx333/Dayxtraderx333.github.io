/* Trader Desk — static r1 creation (no secrets in this file).
 *
 * The page is self-hosted on GitHub Pages, so it cannot reach Anthony's Linux
 * box directly. It talks to a small daemon on that box
 * (bridge/traderdesk_bridge.py) through a public Piping Server on HTTPS 443,
 * https://ppng.io:
 *
 *   page    --GET (blocking)-->  https://ppng.io/<reply channel for id>
 *   page    --POST-->            https://ppng.io/<request channel>
 *   bridge runs ONE allowlisted command and POSTs the encrypted answer.
 *
 * Security (protocol v2): a 256-bit device key K is typed in once on the
 * pairing screen and kept in creationStorage on the r1. Nothing secret is in
 * this file. Channels are HMAC-SHA256(K, "req-v1") and HMAC(K, "res-v1"+id),
 * truncated to 128 bits; every message is AES-256-GCM with key
 * HMAC(K, "aes-v1") and AAD "req|2|id|ts" / "res|2|id|ts". The command is
 * only inside the ciphertext; request plaintext is padded to 64 bytes and
 * replies to fixed size buckets. The key lives in r1 creationStorage
 * (secure first, verified plain fallback); browser localStorage only with ?test=1.
 * Without WebCrypto the page refuses to run (no plaintext fallback).
 */
(function () {
  "use strict";

  // --- relay channels (must match bridge/bridge.json) ---------------------
  var RELAY = "https://ppng.io";
  var PROTO = 2;
  var REQ_PAD = 64;
  var TEST_MODE = /[?&]test=1(&|$)/.test(location.search);
  var B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";   // Crockford base32

  var PT_ZONE = "America/Los_Angeles";
  var IDLE_MS = 45000;
  var WAIT_MS = 140000;      // how long the page waits for the desk to answer
  var QUICK = ["SPY", "QQQ", "NVDA", "CRWV", "AAPL", "TSLA", "MSFT", "META"];

  var LABELS = {
    brief: "MORNING BRIEF",
    pulse: "MARKET PULSE",
    spy: "SPY / 0DTE",
    options: "OPTIONS DESK",
    quote: "TICKER LOOKUP",
    scorecard: "SCORECARD",
    botstatus: "BOT STATUS",
    top3: "TOP 3",
    optbrief: "OPTIONS BRIEF",
    tape: "TAPE 0DTE",
    whales: "WHALES",
    oversold: "OVERSOLD",
    research: "RESEARCH"
  };

  // --- elements -----------------------------------------------------------
  var $ = function (id) { return document.getElementById(id); };
  var saver = $("saver"), menu = $("menu"), ticker = $("ticker"), output = $("output");
  var saverClock = $("saverClock"), refreshClock = $("refreshClock");
  var buttons = $("buttons"), menuScroll = $("menuScroll");
  var outBody = $("outputBody"), outTitle = $("outTitle");
  var tickerInput = $("tickerInput"), goBtn = $("goBtn"), chipsEl = $("chips");
  var recentList = $("recentList"), recentLabel = $("recentLabel");
  var pairScreen = $("pair"), pairInput = $("pairInput"), pairBtn = $("pairBtn");
  var pairStatus = $("pairStatus"), unpairBtn = $("unpairBtn");

  // --- state --------------------------------------------------------------
  var screen = "saver";
  var busy = false;
  var selected = 0;
  var lastRefresh = null;
  var recent = [];
  var idleTimer = null;
  var pollAbort = 0;

  // ------------------------------------------------------------------ store
  function b64encode(s) {
    try { return btoa(unescape(encodeURIComponent(s))); } catch (e) { return null; }
  }
  function b64decode(s) {
    try { return decodeURIComponent(escape(atob(s))); } catch (e) { return null; }
  }
  var store = {
    get: function (key) {
      try {
        if (window.creationStorage && window.creationStorage.plain) {
          return window.creationStorage.plain.getItem(key).then(function (raw) {
            return raw ? b64decode(raw) : null;
          }).catch(function () { return null; });
        }
      } catch (e) { /* fall through */ }
      try {
        var r = localStorage.getItem(key);
        return Promise.resolve(r ? b64decode(r) : null);
      } catch (e2) {
        return Promise.resolve(null);
      }
    },
    set: function (key, value) {
      var enc = b64encode(value);
      if (enc === null) return Promise.resolve();
      try {
        if (window.creationStorage && window.creationStorage.plain) {
          return window.creationStorage.plain.setItem(key, enc).catch(function () {});
        }
      } catch (e) { /* fall through */ }
      try { localStorage.setItem(key, enc); } catch (e2) {}
      return Promise.resolve();
    }
  };

  // ------------------------------------------------------------------ clock
  function ptParts(d) {
    try {
      var fmt = new Intl.DateTimeFormat("en-US", {
        timeZone: PT_ZONE, hour: "2-digit", minute: "2-digit", second: "2-digit",
        hour12: false
      });
      var o = {};
      fmt.formatToParts(d).forEach(function (p) { o[p.type] = p.value; });
      return { hh: o.hour === "24" ? "00" : o.hour, mm: o.minute, ss: o.second };
    } catch (e) {
      var h = String(d.getUTCHours() - 8);
      return { hh: h.padStart(2, "0"), mm: String(d.getUTCMinutes()).padStart(2, "0"), ss: String(d.getUTCSeconds()).padStart(2, "0") };
    }
  }

  function tickClocks() {
    var now = new Date();
    var p = ptParts(now);
    saverClock.textContent = p.hh + ":" + p.mm + ":" + p.ss;
    if (lastRefresh) {
      var q = ptParts(lastRefresh);
      refreshClock.textContent = q.hh + ":" + q.mm;
    } else {
      refreshClock.textContent = "--:--";
    }
  }

  // ------------------------------------------------------------- screensaver
  function showSaver() {
    if (busy || !K) return;
    screen = "saver";
    pairScreen.classList.add("hidden");
    ticker.classList.add("hidden");
    menu.classList.add("hidden");
    output.classList.add("hidden");
    saver.classList.remove("hidden");
  }

  function wake() {
    if (screen === "saver") showMenu();
    resetIdle();
  }

  function resetIdle() {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(function () {
      if (!busy && screen !== "pair") showSaver();
    }, IDLE_MS);
  }

  function showMenu() {
    screen = "menu";
    pairScreen.classList.add("hidden");
    saver.classList.add("hidden");
    ticker.classList.add("hidden");
    output.classList.add("hidden");
    menu.classList.remove("hidden");
    selectButton(selected);
  }

  function selectButton(i) {
    var list = buttons.querySelectorAll(".cmd");
    if (!list.length) return;
    selected = ((i % list.length) + list.length) % list.length;
    for (var k = 0; k < list.length; k++) {
      list[k].classList.toggle("sel", k === selected);
    }
    scrollSelectedIntoView();
  }

  function scrollSelectedIntoView() {
    var list = buttons.querySelectorAll(".cmd");
    var el = list[selected];
    if (!el) return;
    var top = el.offsetTop;
    var bottom = top + el.offsetHeight;
    var view = menuScroll.scrollTop;
    var h = menuScroll.clientHeight;
    if (top < view) menuScroll.scrollTop = top;
    else if (bottom > view + h) menuScroll.scrollTop = bottom - h;
  }

  // ----------------------------------------------------------------- speech
  // Exact numbers matter more than voice, and r1 speech goes through the r1
  // assistant, which can paraphrase or round. So by default the r1 says only a
  // short fixed cue ("Market Pulse ready"); the exact text is on screen.
  //
  // Voice modes (tap the VOICE button on a result screen, or the TRADER DESK
  // title on the menu, to cycle). The SPEAK button reads the current screen.
  //   CUE   (default) speak "<button> ready" / "<TICKER> ready" — no numbers
  //   FULL  read the first ~200 chars of the result (may be reworded by the r1)
  //   OFF   silent
  // Speech call = the OS3-proven shape: PluginMessageHandler.postMessage(
  //   JSON.stringify({message, useLLM:false, wantsR1Response:true,
  //   wantsJournalEntry:false})), looked up at speak time (the r1 may inject
  //   it after load). No TTS stop exists in the SDK; on leaving the creation
  //   the page tries CreationVoiceHandler start/stop (grabs audio focus, if
  //   present) and closeWebView.
  var SPEAK_MAX = 200;
  var VOICE_MODES = ["cue", "full", "off"];
  var VOICE_NAMES = { cue: "VOICE: CUE ONLY", full: "VOICE: READ FULL", off: "VOICE: OFF" };
  var CUES = {
    brief: "Morning brief ready", pulse: "Market pulse ready", spy: "SPY desk ready",
    options: "Options desk ready", scorecard: "Scorecard ready", botstatus: "Bot status ready",
    top3: "Top 3 ready", optbrief: "Options brief ready", tape: "Tape ready",
    whales: "Whales ready", oversold: "Oversold ready", research: "Research ready"
  };
  var voiceMode = "cue";
  try {
    var qv = (location.search.match(/[?&]voice=(cue|full|off)(&|$)/) || [])[1];
    if (qv) voiceMode = qv;
  } catch (e) {}
  var SPEAK_NOW_MAX = 400;   // SPEAK button: first ~400 chars of the screen
  var SHORT_NAMES = { cue: "VOICE: CUE", full: "VOICE: FULL", off: "VOICE: OFF" };
  var speechGen = 0;
  var lastSpeakAt = 0;
  var lastBody = "";         // plain text of the result on screen (for SPEAK)

  function hasBridge() {
    try {
      return typeof window.PluginMessageHandler !== "undefined" && window.PluginMessageHandler &&
        typeof window.PluginMessageHandler.postMessage === "function";
    } catch (e) { return false; }
  }
  function hasWeb() {
    return !!(window.speechSynthesis && typeof SpeechSynthesisUtterance !== "undefined");
  }
  function voiceStatus(text) {
    var el = document.getElementById("voiceStatus");
    if (el) el.textContent = text;
  }

  function speechSummary(text, max) {
    max = max || SPEAK_MAX;
    var clean = String(text || "").replace(/\s+/g, " ").trim();
    if (clean.length <= max) return clean;
    var cut = clean.slice(0, max);
    var m = cut.match(/^[\s\S]*[.!?](?=\s|$)/);
    if (m && m[0].length > 60) return m[0];
    return cut.replace(/\s+\S*$/, "") + ".";
  }

  function cueFor(cmd, arg, ok) {
    var c = cmd === "quote" ? (String(arg || "").toUpperCase().split("").join(" ") + " ready") : (CUES[cmd] || "Ready");
    return ok === false ? c.replace(/ready$/, "partial result") : c;
  }

  function stopSpeech() {
    speechGen++;
    try { if (window.speechSynthesis) window.speechSynthesis.cancel(); } catch (e) {}
  }

  function sayR1(text) {
    window.PluginMessageHandler.postMessage(JSON.stringify({
      message: text, useLLM: false, wantsR1Response: true, wantsJournalEntry: false
    }));
  }

  // speak(text, cmd, arg, ok): called the moment a result arrives
  function speak(text, cmd, arg, ok) {
    stopSpeech();
    if (voiceMode === "off") { voiceStatus("VOICE OFF · TAP SPEAK TO HEAR THIS SCREEN"); return; }
    var say = voiceMode === "full" ? speechSummary(text) : cueFor(cmd, arg, ok);
    sendSpeech(say, VOICE_NAMES[voiceMode]);
  }

  // sendSpeech(say, label): one OS3-shaped message to the r1 speaker
  function sendSpeech(say, label) {
    if (!say) return false;
    try {
      if (hasBridge()) {
        sayR1(say);
      } else if (hasWeb()) {
        var u = new SpeechSynthesisUtterance(say);
        window.speechSynthesis.speak(u);
      } else {
        voiceStatus(label + " · NO SPEECH CHANNEL IN THIS VIEW");
        return false;
      }
      lastSpeakAt = Date.now();
      var tapMs = lastTapAt ? (lastSpeakAt - lastTapAt) : 0;
      window.__tdLastTapToSpeakMs = tapMs;
      voiceStatus(label + " · SENT " + say.length + " CHARS");
      return true;
    } catch (e) {
      voiceStatus(label + " · FAILED · " + String(e && e.message || e).toUpperCase().slice(0, 50));
      return false;
    }
  }

  // SPEAK button / wheel-free action: read the current screen right now,
  // whatever the voice mode (OFF only silences automatic speech).
  function speakNow() {
    stopSpeech();
    lastTapAt = Date.now();
    var text = lastBody;
    if (!text) {
      var raw = outBody ? (outBody.innerText || outBody.textContent || "") : "";
      text = raw.replace(/^(UPDATED|PARTIAL)[^\n]*\n?/, "");
    }
    var say = speechSummary(text, SPEAK_NOW_MAX);
    if (!say || /^(READY|CONNECTING…|WORKING…)$/.test(say)) {
      toast("NOTHING TO READ YET");
      return;
    }
    if (sendSpeech(say, "SPEAKING")) toast("SPEAKING…");
  }

  function toast(text) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = text;
    el.classList.remove("hidden");
    if (toast.t) clearTimeout(toast.t);
    toast.t = setTimeout(function () { el.classList.add("hidden"); }, 1400);
  }

  function renderVoiceBtn() {
    var b = document.getElementById("voiceBtn");
    if (!b) return;
    b.textContent = SHORT_NAMES[voiceMode] || "VOICE";
    b.classList.toggle("off", voiceMode === "off");
  }

  // fast, robust tap binding for the r1 WebView: pointerup/touchend/click,
  // whichever fires first wins; the others are swallowed by a debounce.
  function bindTap(el, fn) {
    if (!el) return;
    var last = 0;
    var fire = function (ev) {
      if (ev) { ev.stopPropagation(); if (ev.type !== "pointerup" && ev.cancelable) ev.preventDefault(); }
      var now = Date.now();
      if (now - last < 450) return;
      last = now;
      el.classList.add("pressed");
      setTimeout(function () { el.classList.remove("pressed"); }, 150);
      resetIdle();
      fn();
    };
    el.addEventListener("pointerup", fire);
    el.addEventListener("touchend", fire);
    el.addEventListener("click", fire);
  }

  // r1 replies after a speak request arrive here; voice input is not used
  window.onPluginMessage = function (data) {
    if (!lastSpeakAt || (data && data.type === "sttEnded")) return;
    voiceStatus(VOICE_NAMES[voiceMode] + " · r1 REPLIED +" + ((Date.now() - lastSpeakAt) / 1000).toFixed(1) + "S");
  };

  // leaving the creation: best-effort stop of r1 audio, then close the view
  var leaving = false;
  function onLeave(why) {
    if (leaving) return;
    leaving = true;
    stopSpeech();
    try {
      if (typeof window.CreationVoiceHandler !== "undefined" && window.CreationVoiceHandler &&
          typeof window.CreationVoiceHandler.postMessage === "function") {
        window.CreationVoiceHandler.postMessage("start");   // grab audio focus…
        window.CreationVoiceHandler.postMessage("stop");    // …and release at once
      }
    } catch (e) {}
    try {
      if (why !== "pagehide" && typeof window.closeWebView !== "undefined" && window.closeWebView &&
          typeof window.closeWebView.postMessage === "function") {
        window.closeWebView.postMessage("");
      }
    } catch (e) {}
  }
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") onLeave("hidden");
    else leaving = false;
  });
  window.addEventListener("pagehide", function () { onLeave("pagehide"); });
  window.addEventListener("pageshow", function () { leaving = false; });

  function flashHint(text) {
    var hint = document.querySelector(".menu-hint");
    if (!hint || !text) return;
    var orig = hint.getAttribute("data-orig") || hint.textContent;
    hint.setAttribute("data-orig", orig);
    hint.textContent = text;
    setTimeout(function () { hint.textContent = orig; }, 6000);
  }

  function cycleVoice() {
    stopSpeech();
    var k = VOICE_MODES.indexOf(voiceMode);
    voiceMode = VOICE_MODES[(k + 1) % VOICE_MODES.length];
    store.set("voice3", voiceMode);
    renderVoiceBtn();
    toast(VOICE_NAMES[voiceMode]);
    voiceStatus(VOICE_NAMES[voiceMode] + " SELECTED" + (voiceMode === "full" ? " · TAP SPEAK TO HEAR NOW" : ""));
    var hint = document.querySelector(".menu-hint");
    if (hint) {
      var orig = hint.getAttribute("data-orig") || hint.textContent;
      hint.setAttribute("data-orig", orig);
      hint.textContent = VOICE_NAMES[voiceMode].replace("VOICE: ", "");
      setTimeout(function () { hint.textContent = orig; }, 1800);
    }
  }

  // ------------------------------------------------------------- colouring
  function renderText(raw) {
    var esc = String(raw)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

    return esc.replace(
      /\b(up|gain(?:s|ed)?|higher|rally(?:ing)?|bullish|positive|beat|rose|rising|advanc(?:e|ed|ing))\b/gi,
      '<span class="up">$1</span>'
    ).replace(
      /\b(down|loss|drop(?:ped|s)?|lower|sell-?off|bearish|negative|miss(?:ed)?|fell|falling|declin(?:e|ed|ing))\b/gi,
      '<span class="down">$1</span>'
    );
  }

  function setOutput(title, bodyHtml, metaHtml) {
    outTitle.textContent = title;
    outBody.innerHTML = (metaHtml ? '<div class="meta">' + metaHtml + "</div>" : "") +
      '<div class="line">' + bodyHtml + "</div>";
    outBody.scrollTop = 0;
  }

  function openOutput(title) {
    screen = "output";
    pairScreen.classList.add("hidden");
    saver.classList.add("hidden");
    menu.classList.add("hidden");
    ticker.classList.add("hidden");
    output.classList.remove("hidden");
    outTitle.textContent = title;
  }

  // ----------------------------------------------------------------- crypto
  var subtle = (window.crypto && window.crypto.subtle) ? window.crypto.subtle : null;
  var enc = new TextEncoder(), dec = new TextDecoder();
  var K = null;            // { hmac: CryptoKey, aes: CryptoKey, req: "td-…" }

  function hex(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return s;
  }
  function unhex(s) {
    var out = new Uint8Array(s.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }
  function b64(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  function unb64(s) {
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function randHex(n) {
    var b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return hex(b);
  }
  function hmacHex(text) {
    return subtle.sign("HMAC", K.hmac, enc.encode(text)).then(hex);
  }

  // pairing code: 52 Crockford chars (256-bit key + 4 zero pad bits) + 4 check chars
  function parsePairCode(input) {
    var s = String(input || "").toUpperCase()
      .replace(/[IL]/g, "1").replace(/O/g, "0").replace(/[^0-9A-Z]/g, "");
    if (s.length !== 56) return Promise.reject(new Error("Need 56 characters, got " + s.length + "."));
    var vals = [];
    for (var i = 0; i < 56; i++) {
      var v = B32.indexOf(s[i]);
      if (v < 0) return Promise.reject(new Error("'" + s[i] + "' is not a valid character."));
      vals.push(v);
    }
    var key = new Uint8Array(32), acc = 0, nbits = 0, k = 0;
    for (var j = 0; j < 52; j++) {
      acc = (acc << 5) | vals[j]; nbits += 5;
      if (nbits >= 8) { nbits -= 8; key[k++] = (acc >> nbits) & 255; acc &= (1 << nbits) - 1; }
    }
    if (acc !== 0 || k !== 32) return Promise.reject(new Error("Typo somewhere: the key does not check out."));
    var chk = (vals[52] << 15) | (vals[53] << 10) | (vals[54] << 5) | vals[55];
    var data = new Uint8Array(10 + 32);
    data.set(enc.encode("td-pair-v1"), 0); data.set(key, 10);
    return subtle.digest("SHA-256", data).then(function (d) {
      var h = new Uint8Array(d);
      var want = ((h[0] << 16) | (h[1] << 8) | h[2]) >> 4;
      if (want !== chk) throw new Error("Typo somewhere: the key does not check out.");
      return hex(key);
    });
  }

  function loadKeys(keyHex) {
    var raw = unhex(keyHex);
    return subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
      .then(function (hk) {
        return subtle.sign("HMAC", hk, enc.encode("aes-v1")).then(function (aesRaw) {
          return subtle.importKey("raw", aesRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        }).then(function (ak) {
          return subtle.sign("HMAC", hk, enc.encode("req-v1")).then(function (r) {
            K = { hmac: hk, aes: ak, req: "td-" + hex(r).slice(0, 32) };
            return K;
          });
        });
      });
  }

  // device key storage on the r1: window.creationStorage (async, values must be
  // base64). Secure first, plain creationStorage if secure fails. Every save is
  // read back and compared before "PAIRED" is shown. On launch the page waits
  // for the r1 to inject creationStorage before deciding whether to ask for the
  // key (an early read used to miss it and fall back to empty localStorage).
  var KEY_NAME = "tdDeviceKey";
  var storageNote = "";          // shown on screen; never contains the key
  function validKey(v) { return typeof v === "string" && /^[0-9a-f]{64}$/.test(v); }
  function withTimeout(p, ms) {
    return new Promise(function (resolve, reject) {
      var t = setTimeout(function () { reject(new Error("storage timeout")); }, ms);
      Promise.resolve(p).then(function (v) { clearTimeout(t); resolve(v); },
                              function (e) { clearTimeout(t); reject(e); });
    });
  }
  function waitForStorage(ms) {
    return new Promise(function (resolve) {
      var t0 = Date.now();
      (function poll() {
        if (window.creationStorage && (window.creationStorage.secure || window.creationStorage.plain)) {
          return resolve(window.creationStorage);
        }
        if (Date.now() - t0 >= ms) return resolve(null);
        setTimeout(poll, 100);
      })();
    });
  }
  // getItem may hand back base64 (documented), base64 with line breaks, or an
  // already-decoded string on some builds: accept any of those.
  function decodeStored(raw) {
    if (raw === null || raw === undefined) return null;
    if (typeof raw === "object") raw = raw.value || raw.data || raw.item || "";
    var s = String(raw).replace(/^"|"$/g, "");
    var compact = s.replace(/\s+/g, "");
    if (validKey(compact)) return compact;
    var d1 = null;
    try { d1 = atob(compact); } catch (e) {}
    if (d1 && validKey(d1.trim())) return d1.trim();
    try { var d2 = atob(String(d1 || "").replace(/\s+/g, "")); if (validKey(d2.trim())) return d2.trim(); } catch (e) {}
    return null;
  }
  function area(name) {
    try { var cs = window.creationStorage; return cs && cs[name] ? cs[name] : null; } catch (e) { return null; }
  }
  function readArea(name) {
    var a = area(name);
    if (!a) return Promise.resolve(null);
    try {
      return withTimeout(a.getItem(KEY_NAME), 4000).then(decodeStored, function () { return null; });
    } catch (e) { return Promise.resolve(null); }
  }
  function writeArea(name, value) {
    var a = area(name);
    if (!a) return Promise.resolve(false);
    try {
      return withTimeout(a.setItem(KEY_NAME, btoa(value)), 4000)
        .then(function () { return readArea(name); })
        .then(function (back) { return back === value; }, function () { return false; });
    } catch (e) { return Promise.resolve(false); }
  }
  var LABEL = { secure: "SECURE STORAGE", plain: "PLAIN CREATION STORAGE", local: "BROWSER LOCALSTORAGE" };
  var keyStore = {
    get: function () {
      return waitForStorage(3000).then(function (cs) {
        var tried = [];
        var next = function (names) {
          if (!names.length) {
            var legacy = null;
            try { legacy = decodeStored(localStorage.getItem(KEY_NAME)); } catch (e) {}
            if (legacy && !cs && TEST_MODE) { storageNote = "KEY FROM " + LABEL.local + " (TEST)"; return legacy; }
            if (legacy && cs) {
              // a key from an older version in browser storage: move it into r1 storage
              return keyStore.set(legacy).then(function () {
                try { localStorage.removeItem(KEY_NAME); } catch (e) {}
                storageNote = storageNote.replace("SAVED TO", "MOVED TO");
                return legacy;
              }, function () { return null; });
            }
            storageNote = "NO SAVED KEY · STORAGE " + (cs ? "PRESENT (" +
              ["secure", "plain"].filter(function (n) { return area(n); }).join("+").toUpperCase() + ")" : "MISSING") +
              (tried.length ? " · CHECKED " + tried.join(", ").toUpperCase() : "");
            return null;
          }
          var n = names[0];
          if (!area(n)) return next(names.slice(1));
          tried.push(n);
          return readArea(n).then(function (v) {
            if (v) { storageNote = "KEY FROM " + LABEL[n]; return v; }
            return next(names.slice(1));
          });
        };
        return next(["secure", "plain"]);
      });
    },
    set: function (value) {
      return waitForStorage(3000).then(function (cs) {
        if (!cs) {
          if (!TEST_MODE) return Promise.reject(new Error("r1 creation storage is not available here; pairing refused. Open Trader Desk as an r1 creation."));
          try {
            localStorage.setItem(KEY_NAME, btoa(value));
            if (decodeStored(localStorage.getItem(KEY_NAME)) === value) {
              storageNote = "SAVED TO " + LABEL.local + " (NOT AN r1 CREATION)";
              return "local";
            }
          } catch (e) {}
          throw new Error("Could not save the key on this device.");
        }
        return writeArea("secure", value).then(function (ok) {
          if (ok) {
            try { localStorage.removeItem(KEY_NAME); } catch (e) {}
            storageNote = "SAVED TO " + LABEL.secure + " · VERIFIED"; return "secure";
          }
          return writeArea("plain", value).then(function (ok2) {
            if (ok2) { storageNote = "SAVED TO " + LABEL.plain + " · VERIFIED (SECURE FAILED)"; return "plain"; }
            throw new Error("The r1 did not keep the key (secure and plain storage both failed). Not paired.");
          });
        });
      });
    },
    clear: function () {
      var jobs = ["secure", "plain"].map(function (n) {
        var a = area(n);
        if (!a) return Promise.resolve();
        try { return withTimeout(a.removeItem(KEY_NAME), 4000).catch(function () {}); } catch (e) { return Promise.resolve(); }
      });
      try { localStorage.removeItem(KEY_NAME); } catch (e) {}
      return Promise.all(jobs);
    }
  };

  // ---------------------------------------------------------------- relay
  function newId() { return randHex(16); }

  function postRequest(id, ts, cmd, arg, token) {
    var iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    var aad = enc.encode("req|" + PROTO + "|" + id + "|" + ts);
    var raw = enc.encode(JSON.stringify({ cmd: cmd, arg: arg || "" }));
    if (raw.length > REQ_PAD) return Promise.reject(new Error("request too long"));
    var pt = new Uint8Array(REQ_PAD);
    pt.fill(32);                 // pad with spaces: still valid JSON
    pt.set(raw, 0);
    return subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: aad }, K.aes, pt)
      .then(function (ct) {
        var body = JSON.stringify({ v: PROTO, id: id, ts: ts, iv: b64(iv), ct: b64(ct) });
        // The relay allows one sender per channel at a time, so a quick second
        // tap can be refused while the first is still being handed over.
        // Retry briefly; a duplicate delivery is dropped by the bridge as a replay.
        var tries = 0;
        var send = function () {
          if (token !== undefined && token !== pollAbort) return null;
          return fetch(RELAY + "/" + K.req, {
            method: "POST",
            headers: { "Content-Type": "text/plain;charset=UTF-8" },
            body: body,
            cache: "no-store"
          }).then(function (r) {
            if (!r.ok) throw new Error("relay " + r.status);
            return true;
          }).catch(function (e) {
            if (++tries >= 12 || (token !== undefined && token !== pollAbort)) throw e;
            return new Promise(function (res) { setTimeout(res, 600); }).then(send);
          });
        };
        return send();
      });
  }

  function openReply(id, cmd, txt) {
    var env = JSON.parse(txt);
    if (!env || env.v !== PROTO || env.id !== id || typeof env.ts !== "number") throw new Error("bad reply");
    var aad = enc.encode("res|" + PROTO + "|" + id + "|" + env.ts);
    return subtle.decrypt({ name: "AES-GCM", iv: unb64(env.iv), additionalData: aad }, K.aes, unb64(env.ct))
      .then(function (pt) {
        var res = JSON.parse(dec.decode(pt));
        if (!res || res.id !== id || res.cmd !== cmd) throw new Error("reply not bound to this request");
        return res;
      });
  }

  // Hold a blocking GET on this request's own reply channel. It resolves as
  // soon as the desk POSTs the answer, and gives up after WAIT_MS.
  function awaitResult(id, cmd, token, channelP) {
    var ctl = null;
    var timer = null;

    var read = function () {
      return channelP.then(function (ch) {
        var opts = { cache: "no-store" };
        if (typeof AbortController !== "undefined") {
          ctl = new AbortController();
          opts.signal = ctl.signal;
        }
        return fetch(RELAY + "/" + ch, opts);
      }).then(function (r) { return r.text(); });
    };

    var wait = new Promise(function (resolve, reject) {
      timer = setTimeout(function () {
        try { if (ctl) ctl.abort(); } catch (e) {}
        reject(new Error("timeout"));
      }, WAIT_MS);
      read().then(resolve, reject);
    });

    var guard = new Promise(function (resolve, reject) {
      // a superseded request stops waiting
      var iv = setInterval(function () {
        if (token !== pollAbort) { clearInterval(iv); try { if (ctl) ctl.abort(); } catch (e) {} resolve(null); }
      }, 300);
      wait.then(function (v) { clearInterval(iv); resolve(v); },
                function (e) { clearInterval(iv); reject(e); });
    });

    return guard.then(
      function (txt) {
        clearTimeout(timer);
        if (txt === null || txt === undefined) return null;
        return openReply(id, cmd, txt);
      },
      function (err) {
        clearTimeout(timer);
        if (token !== pollAbort) return null;
        throw err;
      }
    );
  }

  var lastTapAt = 0;
  function runCommand(cmd, arg, label) {
    lastTapAt = Date.now();
    stopSpeech();
    if (!K) { showPair(); return; }
    busy = true;
    lastBody = "";
    var id = newId();
    var token = ++pollAbort;      // supersedes any request still in flight
    openOutput(label);
    setOutput(label, '<span class="dim blink">CONNECTING…</span>',
      "REQUESTING " + label + " FROM THE DESK");

    var ts = Math.floor(Date.now() / 1000);
    var channelP = hmacHex("res-v1" + id).then(function (h) { return "td-" + h.slice(0, 32); });
    var answered = awaitResult(id, cmd, token, channelP);

    channelP.then(function () { return postRequest(id, ts, cmd, arg, token); })
      .then(function () {
        if (token !== pollAbort) return null;
        setOutput(label, '<span class="dim blink">WORKING…</span>',
          "RUNNING ON THE DESK");
        return answered;
      })
      .then(function (res) {
        if (token !== pollAbort) return;          // late answer to an old tap
        if (!res) { busy = false; resetIdle(); return; }
        lastRefresh = new Date();
        tickClocks();
        var body = res.text || "(no output)";
        lastBody = body;
        speak(body, cmd, res.arg || arg, res.ok);  // cue first, then render
        setOutput(
          label,
          renderText(body),
          (res.ok ? "" : "PARTIAL · ") + "UPDATED " + clockLabel(lastRefresh)
        );
        if (cmd === "quote" && res.ok) rememberTicker((res.arg || arg || "").toUpperCase());
      })
      .catch(function () {
        if (token !== pollAbort) return;
        setOutput(label,
          '<span class="down">NO RESPONSE FROM THE DESK.</span>\n' +
          '<span class="dim">The desk machine did not answer. Tap the button again to retry. ' +
          'If this keeps happening, check the r1 clock is right or re-pair the device.</span>',
          "OFFLINE");
      })
      .then(function () {
        if (token !== pollAbort) return;
        busy = false;
        resetIdle();
      });
  }

  function clockLabel(d) {
    var p = ptParts(d);
    return p.hh + ":" + p.mm + " PT";
  }

  // -------------------------------------------------------------- tickers
  function renderChips() {
    chipsEl.innerHTML = "";
    QUICK.forEach(function (sym) {
      var b = document.createElement("button");
      b.type = "button";
      b.textContent = sym;
      b.addEventListener("click", function (ev) {
        ev.stopPropagation();
        resetIdle();
        tickerInput.value = sym;
        runCommand("quote", sym, "QUOTE " + sym);
      });
      chipsEl.appendChild(b);
    });
  }

  function renderRecent() {
    recentList.innerHTML = "";
    if (!recent.length) {
      recentLabel.textContent = "";
      return;
    }
    recentLabel.textContent = "RECENT";
    recent.forEach(function (sym) {
      var b = document.createElement("button");
      b.type = "button";
      b.textContent = sym;
      b.addEventListener("click", function (ev) {
        ev.stopPropagation();
        resetIdle();
        runCommand("quote", sym, "QUOTE " + sym);
      });
      recentList.appendChild(b);
    });
  }

  function rememberTicker(sym) {
    if (!sym || !/^[A-Z0-9.\-^]{1,12}$/.test(sym)) return;
    recent = [sym].concat(recent.filter(function (s) { return s !== sym; })).slice(0, 5);
    store.set("recent", JSON.stringify(recent));
    renderRecent();
  }

  function openTicker() {
    screen = "ticker";
    pairScreen.classList.add("hidden");
    saver.classList.add("hidden");
    menu.classList.add("hidden");
    output.classList.add("hidden");
    ticker.classList.remove("hidden");
    tickerInput.value = "";
    tickerInput.placeholder = "SYMBOL";
    renderRecent();
    try { tickerInput.focus(); } catch (e) {}
  }

  function submitTicker(value) {
    var sym = String(value || "").trim().toUpperCase();
    if (!sym) return;
    if (!/^[A-Z0-9.\-^]{1,12}$/.test(sym)) {
      tickerInput.value = "";
      tickerInput.placeholder = "LETTERS ONLY";
      return;
    }
    runCommand("quote", sym, "QUOTE " + sym);
  }

  // -------------------------------------------------------------- pairing
  function showPair(msg, bad) {
    screen = "pair";
    saver.classList.add("hidden");
    menu.classList.add("hidden");
    ticker.classList.add("hidden");
    output.classList.add("hidden");
    pairScreen.classList.remove("hidden");
    pairStatus.textContent = msg || "";
    pairStatus.className = "pair-status" + (bad ? " bad" : "");
    if (!subtle) {
      pairStatus.textContent = "SECURE CRYPTO (WEBCRYPTO) IS NOT AVAILABLE IN THIS VIEW. " +
        "TRADER DESK WILL NOT RUN WITHOUT IT.";
      pairStatus.className = "pair-status bad";
      pairBtn.disabled = true;
      pairInput.disabled = true;
    }
  }

  function doPair() {
    if (!subtle) return;
    pairStatus.textContent = "CHECKING…";
    pairStatus.className = "pair-status";
    pairBtn.disabled = true;
    parsePairCode(pairInput.value).then(function (keyHex) {
      // save and verify FIRST; only a key the r1 actually kept counts as paired
      pairStatus.textContent = "SAVING…";
      return keyStore.set(keyHex).then(function () { return loadKeys(keyHex); });
    }).then(function () {
      pairBtn.disabled = false;
      pairInput.value = "";
      pairStatus.textContent = "PAIRED. " + storageNote + ".";
      pairStatus.className = "pair-status good";
      try { pairInput.blur(); } catch (e0) {}
      setTimeout(function () {
        try { showMenu(); flashHint(storageNote); }
        catch (e1) { showPair("PAIRED, BUT THE MENU FAILED TO OPEN: " + String(e1 && e1.message || e1).toUpperCase(), true); }
      }, 1800);
    }).catch(function (e) {
      pairBtn.disabled = false;
      pairStatus.textContent = String((e && e.message) || "That key did not work.").toUpperCase();
      pairStatus.className = "pair-status bad";
    });
  }

  pairBtn.addEventListener("click", function (ev) { ev.stopPropagation(); doPair(); });
  pairInput.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter") { ev.preventDefault(); doPair(); }
  });

  var unpairArmed = null;
  unpairBtn.addEventListener("click", function (ev) {
    ev.stopPropagation();
    if (!unpairArmed) {
      unpairBtn.classList.add("armed");
      unpairBtn.textContent = "TAP AGAIN TO UNPAIR";
      unpairArmed = setTimeout(function () {
        unpairArmed = null;
        unpairBtn.classList.remove("armed");
        unpairBtn.textContent = "UNPAIR THIS DEVICE";
      }, 3000);
      return;
    }
    clearTimeout(unpairArmed); unpairArmed = null;
    unpairBtn.classList.remove("armed");
    unpairBtn.textContent = "UNPAIR THIS DEVICE";
    stopSpeech();
    pollAbort++; busy = false; K = null;
    keyStore.clear().then(function () { showPair("UNPAIRED. TYPE A KEY TO PAIR AGAIN."); });
  });

  // ---------------------------------------------------------------- input
  buttons.addEventListener("click", function (ev) {
    var btn = ev.target.closest(".cmd");
    if (!btn) return;
    stopSpeech();
    resetIdle();
    var cmd = btn.dataset.cmd;
    if (cmd === "quote") { openTicker(); return; }
    runCommand(cmd, "", LABELS[cmd] || cmd.toUpperCase());
  });

  $("backBtn").addEventListener("click", function () {
    stopSpeech();
    pollAbort++; busy = false;
    resetIdle();
    showMenu();
  });
  $("tickerBack").addEventListener("click", function () {
    stopSpeech();
    resetIdle();
    showMenu();
  });

  goBtn.addEventListener("click", function (ev) {
    ev.stopPropagation();
    resetIdle();
    submitTicker(tickerInput.value);
  });

  tickerInput.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter") {
      ev.preventDefault();
      submitTicker(tickerInput.value);
    }
  });
  tickerInput.addEventListener("input", function () {
    tickerInput.value = tickerInput.value.toUpperCase().replace(/[^A-Z0-9.\-^]/g, "");
    resetIdle();
  });

  // --------------------------------------------------- wheel + side button
  function scrollyTarget() {
    if (screen === "output") return outBody;
    if (screen === "ticker") return recent.length ? recentList : null;
    if (screen === "menu") return menuScroll;
    return null;
  }

  function onScrollDelta(dir) {
    if (screen === "pair") return;
    if (screen === "saver") { showMenu(); resetIdle(); return; }
    resetIdle();
    if (screen === "menu") {
      selectButton(selected + dir);
      return;
    }
    var t = scrollyTarget();
    if (t) t.scrollBy({ top: dir * 46, behavior: "auto" });
  }

  window.addEventListener("scrollDown", function () { onScrollDelta(1); });
  window.addEventListener("scrollUp", function () { onScrollDelta(-1); });

  window.addEventListener("sideClick", function () {
    stopSpeech();
    if (screen === "pair") { doPair(); return; }
    if (screen === "saver") { showMenu(); resetIdle(); return; }
    resetIdle();
    if (screen === "menu") {
      var list = buttons.querySelectorAll(".cmd");
      if (list[selected]) list[selected].click();
    } else {
      pollAbort++; busy = false;
      showMenu();
    }
  });

  // keyboard stand-ins for desktop testing
  window.addEventListener("keydown", function (ev) {
    if (ev.target === pairInput) return;
    if (ev.target === tickerInput) {
      if (ev.key === "Escape") showMenu();
      return;
    }
    if (ev.key === " " || ev.key === "Escape") stopSpeech();
    if (ev.key === " ") {
      ev.preventDefault();
      if (screen === "menu") {
        var list = buttons.querySelectorAll(".cmd");
        if (list[selected]) list[selected].click();
      } else if (screen === "saver") {
        showMenu();
        resetIdle();
      }
    } else if (ev.key === "ArrowDown") {
      onScrollDelta(1);
    } else if (ev.key === "ArrowUp") {
      onScrollDelta(-1);
    } else if (ev.key === "Escape") {
      if (screen !== "menu") { pollAbort++; busy = false; showMenu(); }
      else onLeave("back");
    }
  });

  // tap anywhere wakes / resets idle
  document.addEventListener("pointerdown", function () {
    stopSpeech();
    if (screen === "pair") return;
    if (screen === "saver") { showMenu(); }
    resetIdle();
  }, true);

  // ------------------------------------------------------------------ boot
  function boot() {
    tickClocks();
    setInterval(tickClocks, 1000);
    renderChips();
    var title = document.querySelector("#menu .hdr-title");
    if (title) title.addEventListener("click", function (ev) { ev.stopPropagation(); cycleVoice(); });
    bindTap($("voiceBtn"), cycleVoice);
    bindTap($("speakBtn"), speakNow);
    bindTap($("voiceStatus"), speakNow);   // the grey line under the buttons speaks too
    renderVoiceBtn();
    // "voice2": earlier versions could save WEB VOICE when the r1 bridge was
    // injected late, which made the r1 silent; old choices are ignored.
    store.get("voice3").then(function (v) {
      if (v && VOICE_MODES.indexOf(v) >= 0 && !/[?&]voice=/.test(location.search)) voiceMode = v;
      renderVoiceBtn();
    });
    store.get("recent").then(function (raw) {
      if (!raw) return;
      try {
        var arr = JSON.parse(raw);
        if (Array.isArray(arr)) recent = arr.slice(0, 5);
      } catch (e) {}
      renderRecent();
    });
    if (!subtle) { showPair(); return; }
    // wait for the r1 storage read before deciding whether to ask for the key
    keyStore.get().then(function (keyHex) {
      if (!validKey(keyHex)) { showPair(storageNote); return; }
      return loadKeys(keyHex).then(function () {
        flashHint(storageNote);
        showSaver();
        setTimeout(function () {
          if (screen === "saver") showMenu();
        }, 6000);
        resetIdle();
      });
    }).catch(function () { showPair("STORED KEY COULD NOT BE LOADED. PAIR AGAIN. " + storageNote, true); });
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", boot);
    } else {
      boot();
    }
  }
})();
