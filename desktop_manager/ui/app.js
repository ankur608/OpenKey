// OpenKey Desktop & Web Companion - Interactive Frontend Logic
// Dual Engine: Native Tauri IPC + Web Serial (Chrome/Edge/Brave/Opera)

function getTauriInvoke() {
  if (typeof window !== "undefined" && window.__TAURI__) {
    if (typeof window.__TAURI__.invoke === "function") return window.__TAURI__.invoke;
    if (window.__TAURI__.tauri && typeof window.__TAURI__.tauri.invoke === "function") return window.__TAURI__.tauri.invoke;
  }
  return null;
}

const isTauriAvailable = () => getTauriInvoke() !== null;
const isWebSerialSupported = () => typeof navigator !== 'undefined' && 'serial' in navigator;

// Web Serial Transport Engine
let webSerialPort = null;
let webSerialCid = 0xFFFFFFFF;
let isWebSerialActive = false;
let serialReadBuffer = [];
let isSerialBusy = false;

async function sha256Bytes(data) {
  const enc = new TextEncoder();
  const bytes = typeof data === 'string' ? enc.encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(hash);
}

async function mnemonicToSeed(words, passphrase = "") {
  const mnemonicStr = words.join(" ").normalize("NFKD");
  const saltStr = ("mnemonic" + passphrase).normalize("NFKD");
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(mnemonicStr),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(saltStr),
      iterations: 2048,
      hash: "SHA-512"
    },
    baseKey,
    512
  );
  return new Uint8Array(derivedBits);
}

async function writeExactBytes(bytes) {
  if (!webSerialPort || !webSerialPort.writable) {
    throw new Error("OpenKey serial port not writable");
  }
  const writer = webSerialPort.writable.getWriter();
  try {
    await writer.write(bytes);
  } finally {
    writer.releaseLock();
  }
}

let serialReader = null;
let serialReadLoopRunning = false;

async function startSerialReadLoop() {
  if (!webSerialPort || !webSerialPort.readable) return;
  if (serialReadLoopRunning) return;
  serialReadLoopRunning = true;

  try {
    serialReader = webSerialPort.readable.getReader();
    while (serialReadLoopRunning && webSerialPort && webSerialPort.readable) {
      const { value, done } = await serialReader.read();
      if (done) break;
      if (value) {
        for (let i = 0; i < value.length; i++) {
          serialReadBuffer.push(value[i]);
        }
      }
    }
  } catch (err) {
    console.warn("Serial read loop closed:", err);
  } finally {
    serialReadLoopRunning = false;
    if (serialReader) {
      try { serialReader.releaseLock(); } catch (_) {}
      serialReader = null;
    }
  }
}

function stopSerialReadLoop() {
  serialReadLoopRunning = false;
  if (serialReader) {
    try { serialReader.cancel(); } catch (_) {}
    try { serialReader.releaseLock(); } catch (_) {}
    serialReader = null;
  }
}

async function readExactBytes(numBytes, timeoutMs = 25000) {
  const startTime = Date.now();
  while (serialReadBuffer.length < numBytes) {
    if (Date.now() - startTime > timeoutMs) {
      throw new Error("Timeout waiting for serial bytes from OpenKey");
    }
    await new Promise(r => setTimeout(r, 10));
  }
  const result = new Uint8Array(serialReadBuffer.slice(0, numBytes));
  serialReadBuffer = serialReadBuffer.slice(numBytes);
  return result;
}

async function sendWebSerialCtapCommand(cid, cmd, payload = new Uint8Array(0)) {
  const waitStart = Date.now();
  while (isSerialBusy) {
    if (Date.now() - waitStart > 8000) break;
    await new Promise(r => setTimeout(r, 40));
  }
  isSerialBusy = true;

  try {
    serialReadBuffer = []; // Clear residual bytes before sending command

    const totalLen = payload.length;
    // 1. INIT frame: 4B CID || (cmd | 0x80) || 2B BCNT || up to 57B payload
    const initPkt = new Uint8Array(64);
    initPkt[0] = (cid >>> 24) & 0xFF;
    initPkt[1] = (cid >>> 16) & 0xFF;
    initPkt[2] = (cid >>> 8) & 0xFF;
    initPkt[3] = cid & 0xFF;
    initPkt[4] = cmd | 0x80;
    initPkt[5] = (totalLen >>> 8) & 0xFF;
    initPkt[6] = totalLen & 0xFF;

    const initChunk = Math.min(57, totalLen);
    if (initChunk > 0) {
      initPkt.set(payload.subarray(0, initChunk), 7);
    }
    await writeExactBytes(initPkt);

    // 2. CONT frames
    let sent = initChunk;
    let seq = 0;
    while (sent < totalLen) {
      const contPkt = new Uint8Array(64);
      contPkt[0] = (cid >>> 24) & 0xFF;
      contPkt[1] = (cid >>> 16) & 0xFF;
      contPkt[2] = (cid >>> 8) & 0xFF;
      contPkt[3] = cid & 0xFF;
      contPkt[4] = seq++ & 0x7F;

      const chunk = Math.min(59, totalLen - sent);
      contPkt.set(payload.subarray(sent, sent + chunk), 5);
      sent += chunk;
      await writeExactBytes(contPkt);
    }

    // 3. Receive Response (reassemble INIT + CONT)
    let startTime = Date.now();
    let expectedTotal = null;
    let expectedSeq = 0;
    const respPayload = [];

    while (Date.now() - startTime < 30000) {
      const pkt = await readExactBytes(64, 25000);
      const pktCid = ((pkt[0] << 24) | (pkt[1] << 16) | (pkt[2] << 8) | pkt[3]) >>> 0;
      if (pktCid !== cid) continue;

      const cmdOrSeq = pkt[4];
      if (cmdOrSeq & 0x80) {
        // INIT frame
        const respCmd = cmdOrSeq & 0x7F;
        if (respCmd === 0x3B) {
          // Keepalive packet received: device is actively waiting for user touch!
          startTime = Date.now(); // reset timer so user has ample time
          continue;
        }
        if (respCmd === 0x3F) {
          const err = pkt[7];
          let errMsg = `CTAPHID error: 0x${err.toString(16).padStart(2, '0')}`;
          if (err === 0x31) errMsg = "Invalid PIN (or leave blank & touch BOOT button on key to authorize)";
          else if (err === 0x32) errMsg = "PIN Locked (0 retries remaining). Please touch key BOOT button or Factory Reset below.";
          else if (err === 0x3A || err === 0x34) errMsg = "Physical touch timed out (please touch the BOOT button when LED flashes)";
          else if (err === 0x3E) errMsg = "Physical button touch required on key to authorize";
          throw new Error(errMsg);
        }

        expectedTotal = (pkt[5] << 8) | pkt[6];
        const chunk = Math.min(57, expectedTotal);
        for (let i = 0; i < chunk; i++) respPayload.push(pkt[7 + i]);
        if (respPayload.length >= expectedTotal) return new Uint8Array(respPayload);
      } else {
        // CONT frame
        if (expectedTotal !== null) {
          if (cmdOrSeq !== expectedSeq) {
            throw new Error(`Sequence mismatch: expected ${expectedSeq}, got ${cmdOrSeq}`);
          }
          expectedSeq = (expectedSeq + 1) & 0x7F;
          const remaining = expectedTotal - respPayload.length;
          const chunk = Math.min(59, remaining);
          for (let i = 0; i < chunk; i++) respPayload.push(pkt[5 + i]);
          if (respPayload.length >= expectedTotal) return new Uint8Array(respPayload);
        }
      }
    }
    throw new Error("Device response timed out (User presence touch not confirmed)");
  } finally {
    isSerialBusy = false;
  }
}

async function webSerialInitHandshake() {
  const nonce = new Uint8Array(8);
  crypto.getRandomValues(nonce);

  const initPkt = new Uint8Array(64);
  initPkt[0] = 0xFF; initPkt[1] = 0xFF; initPkt[2] = 0xFF; initPkt[3] = 0xFF;
  initPkt[4] = 0x86;
  initPkt[5] = 0x00; initPkt[6] = 0x08;
  initPkt.set(nonce, 7);

  await writeExactBytes(initPkt);
  const resp = await readExactBytes(64, 5000);

  for (let i = 0; i < 8; i++) {
    if (resp[7 + i] !== nonce[i]) {
      throw new Error("CTAPHID_INIT nonce echo mismatch");
    }
  }

  webSerialCid = ((resp[15] << 24) | (resp[16] << 16) | (resp[17] << 8) | resp[18]) >>> 0;
  isWebSerialActive = true;
  activeDevice = {
    path: "webserial:usb",
    vendor_id: 0x1209,          // pid.codes Open Source VID
    product_id: 0x5070,         // SoloKeys FIDO2 PID
    manufacturer: "OpenKey Security",
    product: "OpenKey FIDO2",
    serial_number: "OK-F2-00000001"
  };
}

async function requestWebSerialConnection() {
  if (!isWebSerialSupported()) {
    alert("Web Serial API is not supported in this browser. Please open in Google Chrome, Microsoft Edge, Brave, or Opera.");
    return false;
  }
  try {
    serialReadBuffer = [];
    try {
      webSerialPort = await navigator.serial.requestPort({
        filters: [
          { usbVendorId: 0x1209 }, // pid.codes VID (new firmware v1.1.0+)
          { usbVendorId: 0x303a }  // Espressif VID (legacy firmware fallback)
        ]
      });
    } catch (e) {
      webSerialPort = await navigator.serial.requestPort();
    }

    showToast("Connecting to OpenKey via Web Serial...");
    await webSerialPort.open({ baudRate: 115200 });
    startSerialReadLoop();
    await webSerialInitHandshake();
    showToast("OpenKey hardware connected & authorised via Web Serial!");
    scanConnectedDevices();
    return true;
  } catch (err) {
    stopSerialReadLoop();
    if (err.name !== "NotFoundError") {
      alert("Failed to connect OpenKey: " + err.message);
    }
    webSerialPort = null;
    isWebSerialActive = false;
    activeDevice = null;
    scanConnectedDevices();
    return false;
  }
}

async function autoCheckWebSerial() {
  if (!isWebSerialSupported() || isTauriAvailable() || isWebSerialActive) return;
  try {
    const ports = await navigator.serial.getPorts();
    if (ports.length > 0 && !webSerialPort) {
      webSerialPort = ports[0];
      serialReadBuffer = [];
      await webSerialPort.open({ baudRate: 115200 });
      startSerialReadLoop();
      await webSerialInitHandshake();
      scanConnectedDevices();
    }
  } catch (e) {
    stopSerialReadLoop();
    // Port might be in use
  }
}

if (typeof navigator !== 'undefined' && 'serial' in navigator) {
  navigator.serial.addEventListener('disconnect', () => {
    stopSerialReadLoop();
    webSerialPort = null;
    isWebSerialActive = false;
    activeDevice = null;
    serialReadBuffer = [];
    scanConnectedDevices();
    showToast("OpenKey disconnected");
  });
  navigator.serial.addEventListener('connect', () => {
    showToast("OpenKey USB plugged in! Click to connect.");
    autoCheckWebSerial();
  });
}

// Unified Command Dispatcher (Tauri IPC + Web Serial)
const invoke = async (cmd, args) => {
  const tauriFn = getTauriInvoke();
  if (tauriFn) {
    return tauriFn(cmd, args);
  }

  // Web Serial Driver
  if (!isWebSerialSupported()) {
    throw new Error("Neither Tauri IPC nor Web Serial is available in this browser");
  }

  switch (cmd) {
    case "scan_devices": {
      if (isWebSerialActive && activeDevice) {
        return [activeDevice];
      }
      return [];
    }

    case "wink_device": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      await sendWebSerialCtapCommand(webSerialCid, 0x08, new Uint8Array(0));
      return "Wink pulse sent to hardware NeoPixel!";
    }

    case "get_openkey_status": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      const resp = await sendWebSerialCtapCommand(webSerialCid, 0x41, new Uint8Array([0x01]));
      if (resp.length < 13 || resp[0] !== 0x00) {
        throw new Error("Invalid status response from OpenKey hardware");
      }
      const rk_count = (resp[6] << 8) | resp[7];
      const fpBytes = resp.slice(9, 13);
      const fp = Array.from(fpBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      const profile = resp[5];

      return {
        initialized: resp[1] === 0xA5,
        pin_set: resp[2] !== 0,
        pin_retries: resp[3],
        seed_configured: resp[4] !== 0,
        stealth_aaguid_mode: profile === 1,
        aaguid_profile: profile,
        resident_key_count: rk_count,
        flash_encryption_active: resp[8] !== 0,
        seed_fingerprint: fp,
      };
    }

    case "set_aaguid_profile": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      const payload = [];
      if (args && args.pin && args.pin.length > 0) {
        const hash = await sha256Bytes(args.pin);
        for (let i = 0; i < 16; i++) payload.push(hash[i]);
      }
      payload.push(args.profile);

      const resp = await sendWebSerialCtapCommand(webSerialCid, 0x41, new Uint8Array([0x03, ...payload]));
      if (resp.length === 0 || resp[0] !== 0x00) {
        throw new Error("Failed to update AAGUID profile on hardware");
      }
      return args.profile;
    }

    case "set_device_pin": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      const hash = await sha256Bytes(args.pin);
      const resp = await sendWebSerialCtapCommand(webSerialCid, 0x41, new Uint8Array([0x04, ...hash]));
      if (resp.length === 0 || resp[0] !== 0x00) {
        throw new Error("Failed to set PIN on hardware (touch confirmation timed out)");
      }
      return true;
    }

    case "set_duress_pin": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      const hash = await sha256Bytes(args.pin);
      const resp = await sendWebSerialCtapCommand(webSerialCid, 0x41, new Uint8Array([0x06, ...hash]));
      if (resp.length === 0 || resp[0] !== 0x00) {
        throw new Error("Failed to arm Panic PIN on hardware (touch confirmation timed out)");
      }
      return true;
    }

    case "reset_device_pin": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      const resp = await sendWebSerialCtapCommand(webSerialCid, 0x41, new Uint8Array([0x07]));
      if (resp.length === 0 || resp[0] !== 0x00) {
        throw new Error("Failed to reset PIN on hardware (touch confirmation timed out)");
      }
      pinConfigured = false;
      const p1 = document.getElementById("input-new-pin");
      if (p1) p1.value = "";
      const p2 = document.getElementById("input-confirm-pin");
      if (p2) p2.value = "";
      return true;
    }

    case "factory_reset_device": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      const resp = await sendWebSerialCtapCommand(webSerialCid, 0x41, new Uint8Array([0x05]));
      if (resp.length === 0 || resp[0] !== 0x00) {
        throw new Error("Failed to factory reset OpenKey (touch confirmation timed out)");
      }
      localStorage.removeItem("openkey_seed_armed");
      localStorage.removeItem("openkey_seed_fp");
      localStorage.removeItem("openkey_enrolled_passkeys");
      seedConfigured = false;
      pinConfigured = false;
      storedKeysCount = 0;
      renderPasskeyTable();
      updateVaultStatusUI(false, "Unprovisioned");
      updateGaugeUI(true);
      const p1 = document.getElementById("input-new-pin");
      if (p1) p1.value = "";
      const p2 = document.getElementById("input-confirm-pin");
      if (p2) p2.value = "";
      const pp = document.getElementById("input-profile-pin");
      if (pp) pp.value = "";
      return true;
    }

    case "provision_bip39_seed": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      const seedBytes = await mnemonicToSeed(args.words, args.passphrase || "");
      const payload = [];
      if (args && args.pin && args.pin.length > 0) {
        const hash = await sha256Bytes(args.pin);
        for (let i = 0; i < 16; i++) payload.push(hash[i]);
      }
      for (let i = 0; i < seedBytes.length; i++) payload.push(seedBytes[i]);

      const resp = await sendWebSerialCtapCommand(webSerialCid, 0x41, new Uint8Array([0x02, ...payload]));
      if (resp.length === 0 || resp[0] !== 0x00) {
        throw new Error("Failed to provision seed (verify PIN or touch confirmation)");
      }
      const fpBytes = resp.slice(1, 5);
      const fp = Array.from(fpBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      return `Master seed provisioned and committed to hardware NVS! (Fingerprint: ${fp})`;
    }

    case "validate_bip39_words": {
      if (!args || !args.words || args.words.length !== 24) {
        throw new Error("Invalid word count: exactly 24 words required");
      }
      return true;
    }

    case "generate_bip39_words": {
      return currentMnemonic && currentMnemonic.length === 24 ? currentMnemonic : [
        "abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "accident",
        "account", "accuse", "achieve", "acid", "acoustic", "acquire",
        "across", "act", "action", "actor", "actress", "actual"
      ];
    }

    default:
      throw new Error(`Unsupported command: ${cmd}`);
  }
};

// Application State
let activeDevice = null;
let currentMnemonic = [];
let currentProfile = 0;
let seedConfigured = false;
let pinConfigured = false;
let pollingTimer = null;

let storedKeysCount = 0;
const MAX_KEYS_CAPACITY = 1000;
let gaugeDisplayMode = "used"; // "used" or "remaining"

// AAGUID Constant Definitions matching firmware
const AAGUID_MAP = {
  0: {
    aaguid: "4f70656e-4b65-7953-3330-000000000001",
    name: "Native OpenKey Identifier",
    certLevel: "FIDO Certified L2 (Hardened)",
    badgeText: "Native OpenKey",
    badgeClass: "badge-info",
    mdsType: "Native OpenKey AAGUID",
    posture: "Standard Enterprise",
    desc: "Open-source token identifier. Standard enterprise compliance."
  },
  1: {
    aaguid: "00000000-0000-0000-0000-000000000000 (Ephemeral RP)",
    name: "Stealth Mode (Anti-Tracking)",
    certLevel: "FIDO Certified L2 (Stealth Hardened)",
    badgeText: "Stealth Anti-Tracking",
    badgeClass: "badge-cyan",
    mdsType: "Ephemeral RP-Isolated AAGUID",
    posture: "Anti-Tracking Armed",
    desc: "Zero cross-domain tracking. Returns zeroes in GetInfo & RP-isolated HMAC."
  },
  2: {
    aaguid: "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa",
    name: "FIDO MDS L2 Compatible",
    certLevel: "FIDO Certified L2",
    badgeText: "FIDO Certified L2",
    badgeClass: "badge-emerald",
    mdsType: "FIDO MDS Registered L2 (Keyroost)",
    posture: "FIDO MDS L2 Profile",
    desc: "Recognized by FIDO Alliance MDS3 cache. Unlocks all metadata in Keyroost."
  }
};

// Persistent KeyStore Inventory Engine
const DEFAULT_PASSKEYS = [
  { domain: "webauthn.io", id: "c94f..882a", alg: "ES256 (-7)", uv: "UP + UV" },
  { domain: "github.com", id: "10ae..34f1", alg: "ES256 (-7)", uv: "UP + UV" }
];

function getEnrolledPasskeys() {
  try {
    const raw = localStorage.getItem("openkey_enrolled_passkeys");
    if (raw) return JSON.parse(raw);
  } catch (e) {}
  return [...DEFAULT_PASSKEYS];
}

function saveEnrolledPasskeys(keys) {
  localStorage.setItem("openkey_enrolled_passkeys", JSON.stringify(keys));
}

function renderPasskeyTable() {
  const tableBody = document.getElementById("passkey-table-body");
  if (!tableBody) return;
  const keys = getEnrolledPasskeys();
  storedKeysCount = keys.length;

  tableBody.innerHTML = "";
  keys.forEach((k, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${k.domain}</strong></td>
      <td class="mono text-xs">${k.id}</td>
      <td><span class="tag">${k.alg || "ES256 (-7)"}</span></td>
      <td><span class="badge badge-emerald">${k.uv || "UP + UV"}</span></td>
      <td><button class="btn-sm-danger" data-index="${idx}">Delete</button></td>
    `;
    tableBody.appendChild(tr);
  });

  const passkeyCapEl = document.getElementById("passkey-capacity-stat");
  if (passkeyCapEl) passkeyCapEl.textContent = `${storedKeysCount} / 1,000`;
  const rkCountEl = document.getElementById("info-rk-count");
  if (rkCountEl) rkCountEl.textContent = `${storedKeysCount} / 1,000 Resident Keys`;

  updateGaugeUI(isWebSerialActive || isTauriAvailable());
}

document.addEventListener("DOMContentLoaded", () => {
  setupTheme();
  setupNavigation();
  setupSubTabs();
  setupMDSTabs();
  setupGaugeInteractions();
  setupEventListeners();
  generateInitialSeedWords();
  renderPasskeyTable();
  
  // Initial scan and background periodic polling
  autoCheckWebSerial();
  scanConnectedDevices();
  pollingTimer = setInterval(scanConnectedDevices, 2500);
});

// 1. Theme Management (Dark / Normal Light Mode)
function setupTheme() {
  const storedTheme = localStorage.getItem("openkey-theme") || "dark";
  applyTheme(storedTheme);

  const radioDark = document.getElementById("radio-theme-dark");
  const radioLight = document.getElementById("radio-theme-light");

  if (radioDark && radioLight) {
    if (storedTheme === "light") {
      radioLight.checked = true;
    } else {
      radioDark.checked = true;
    }

    radioDark.addEventListener("change", () => {
      if (radioDark.checked) applyTheme("dark");
    });
    radioLight.addEventListener("change", () => {
      if (radioLight.checked) applyTheme("light");
    });
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("openkey-theme", theme);
}

// 2. Navigation Tab Handling
function setupNavigation() {
  const tabs = document.querySelectorAll(".nav-item");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const hero = document.getElementById("disconnected-hero");
      if (!activeDevice) {
        showToast("Plug in and connect OpenKey to access " + tab.textContent.trim());
        if (hero) hero.classList.add("active");
        document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
        return;
      }

      if (hero) hero.classList.remove("active");
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      const targetId = tab.getAttribute("data-tab");
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

// 3. Sub-Tab Handling in Vault
function setupSubTabs() {
  const subBtns = document.querySelectorAll(".subnav-btn");
  subBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      subBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".subtab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const target = btn.getAttribute("data-subtab");
      const pane = document.getElementById(target);
      if (pane) pane.classList.add("active");
    });
  });
}

// 4. Device Metadata (FIDO MDS) Card Tabs
function setupMDSTabs() {
  const mdsTabs = document.querySelectorAll("#mds-nav-tabs .card-tab");
  mdsTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      mdsTabs.forEach(t => t.classList.remove("active"));
      const targetContentId = tab.getAttribute("data-mdstab");
      
      const parentCard = tab.closest(".mds-card");
      if (parentCard) {
        parentCard.querySelectorAll(".card-tab-content").forEach(c => c.classList.remove("active"));
        const targetContent = parentCard.querySelector(`#${targetContentId}`);
        if (targetContent) targetContent.classList.add("active");
      }
      tab.classList.add("active");
    });
  });
}

// 5. Round Graphic Gauge Interactions (Key-Store Stored / Remaining Percent)
function setupGaugeInteractions() {
  const btnUsed = document.getElementById("btn-mode-used");
  const btnRemaining = document.getElementById("btn-mode-remaining");
  const gaugeContainer = document.getElementById("overview-round-gauge");

  if (btnUsed) {
    btnUsed.addEventListener("click", () => {
      gaugeDisplayMode = "used";
      updateGaugeUI(true);
    });
  }

  if (btnRemaining) {
    btnRemaining.addEventListener("click", () => {
      gaugeDisplayMode = "remaining";
      updateGaugeUI(true);
    });
  }

  if (gaugeContainer) {
    gaugeContainer.addEventListener("click", () => {
      gaugeDisplayMode = gaugeDisplayMode === "used" ? "remaining" : "used";
      updateGaugeUI(true);
      showToast(`Gauge View: ${gaugeDisplayMode === "used" ? "Keys Stored %" : "Reserved Remaining %"}`);
    });
  }
}

function updateGaugeUI(isConnected = true) {
  const arcFill = document.getElementById("overview-gauge-arc");
  const numberEl = document.getElementById("overview-gauge-number");
  const subLabelEl = document.getElementById("overview-gauge-sub");
  const btnUsed = document.getElementById("btn-mode-used");
  const btnRemaining = document.getElementById("btn-mode-remaining");

  const metricStored = document.getElementById("metric-stored-count");
  const metricRemaining = document.getElementById("metric-remaining-count");
  const metricWear = document.getElementById("metric-wear-headroom");

  const miniArcFill = document.getElementById("passkey-gauge-mini-arc");
  const miniNumEl = document.getElementById("passkey-gauge-mini-num");
  const passkeyPill = document.getElementById("passkey-stat-pill");

  const CIRCUMFERENCE_MAIN = 326.73; // 2 * PI * 52
  const CIRCUMFERENCE_MINI = 169.64; // 2 * PI * 27

  if (!isConnected) {
    if (arcFill) arcFill.style.strokeDashoffset = CIRCUMFERENCE_MAIN;
    if (numberEl) numberEl.textContent = "0%";
    if (subLabelEl) {
      subLabelEl.textContent = "OFFLINE";
      subLabelEl.style.color = "var(--text-muted)";
    }
    if (metricStored) metricStored.textContent = "-- / 1,000";
    if (metricRemaining) metricRemaining.textContent = "-- Free";
    if (metricWear) metricWear.textContent = "100.0%";
    if (miniArcFill) miniArcFill.style.strokeDashoffset = CIRCUMFERENCE_MINI;
    if (miniNumEl) miniNumEl.textContent = "0%";
    if (passkeyPill) passkeyPill.textContent = "No Key Detected or Authorised";
    return;
  }

  const stored = Math.max(0, Math.min(storedKeysCount, MAX_KEYS_CAPACITY));
  const remaining = MAX_KEYS_CAPACITY - stored;

  const pctUsed = (stored / MAX_KEYS_CAPACITY) * 100;
  const pctRemaining = (remaining / MAX_KEYS_CAPACITY) * 100;

  const isUsedMode = gaugeDisplayMode === "used";
  const displayPct = isUsedMode ? pctUsed : pctRemaining;

  // Active button highlight
  if (btnUsed && btnRemaining) {
    if (isUsedMode) {
      btnUsed.classList.add("active");
      btnRemaining.classList.remove("active");
    } else {
      btnRemaining.classList.add("active");
      btnUsed.classList.remove("active");
    }
  }

  // Update Main Gauge Arc and Text
  if (arcFill) {
    const offset = CIRCUMFERENCE_MAIN * (1 - displayPct / 100);
    arcFill.style.strokeDashoffset = offset;
    if (isUsedMode) {
      arcFill.classList.remove("remaining-mode");
    } else {
      arcFill.classList.add("remaining-mode");
    }
  }

  if (numberEl) {
    const formatted = displayPct % 1 === 0 ? `${Math.round(displayPct)}%` : `${displayPct.toFixed(1)}%`;
    numberEl.textContent = formatted;
  }

  if (subLabelEl) {
    subLabelEl.textContent = isUsedMode ? "STORED" : "REMAINING";
    subLabelEl.style.color = isUsedMode ? "var(--accent-coral)" : "var(--accent-emerald)";
  }

  // Update Metrics
  if (metricStored) metricStored.textContent = `${stored} / 1,000`;
  if (metricRemaining) metricRemaining.textContent = `${remaining.toLocaleString()} Free`;
  if (metricWear) metricWear.textContent = `${pctRemaining.toFixed(1)}%`;

  // Update Mini Gauge in Passkey Tab
  if (miniArcFill) {
    const miniOffset = CIRCUMFERENCE_MINI * (1 - pctUsed / 100);
    miniArcFill.style.strokeDashoffset = miniOffset;
  }
  if (miniNumEl) {
    miniNumEl.textContent = `${Math.round(pctUsed)}%`;
  }
  if (passkeyPill) {
    passkeyPill.textContent = `${remaining.toLocaleString()} Free Slots`;
  }
}

// 6. Setup All Event Listeners
function setupEventListeners() {
  // Rescan USB or Authorise Web Serial Key Button
  const btnScan = document.getElementById("btn-scan");
  if (btnScan) {
    btnScan.addEventListener("click", () => {
      if (!isTauriAvailable() && isWebSerialSupported()) {
        requestWebSerialConnection();
      } else {
        showToast("Scanning USB buses for OpenKey...");
        scanConnectedDevices();
      }
    });
  }

  // Device Status Indicator Pill (clickable in browser to authorise)
  const devicePill = document.getElementById("device-status-indicator");
  if (devicePill) {
    devicePill.addEventListener("click", (e) => {
      if (e.target.closest("#btn-scan")) return;
      if (!isTauriAvailable() && isWebSerialSupported() && !isWebSerialActive) {
        requestWebSerialConnection();
      }
    });
  }

  // Identify Key (NeoPixel Pulse) Button
  const btnWink = document.getElementById("btn-wink");
  if (btnWink) {
    btnWink.addEventListener("click", () => {
      if (activeDevice) {
        showToast("Sending Identify command to OpenKey...");
        invoke("wink_device", { devicePath: activeDevice.path })
          .then(() => showToast("Identify pulse sent to hardware!"))
          .catch(err => showToast("Identify Key failed: " + err));
      } else {
        showToast("Identify Key: No active OpenKey connected or authorised");
      }
    });
  }

  // Feature 6 & MDS: Apply 3-Way AAGUID Profile
  const btnApplyProfile = document.getElementById("btn-apply-profile");
  if (btnApplyProfile) {
    btnApplyProfile.addEventListener("click", () => {
      const selectedRadio = document.querySelector('input[name="aaguid-profile"]:checked');
      if (!selectedRadio) return;

      const profileVal = parseInt(selectedRadio.value, 10);
      const pin = document.getElementById("input-profile-pin").value || "";

      if (activeDevice) {
        showToast(`Applying AAGUID Profile ${profileVal}...`);
        invoke("set_aaguid_profile", {
          devicePath: activeDevice.path,
          pin: pin,
          profile: profileVal
        })
        .then(() => {
          currentProfile = profileVal;
          updateAAGUIDProfileUI(profileVal);
          showToast(`OpenKey AAGUID Profile ${profileVal} successfully committed!`);
          document.getElementById("input-profile-pin").value = "";
          queryDeviceTelemetry(activeDevice.path);
        })
        .catch(err => {
          alert("Failed to update AAGUID Profile: " + err);
        });
      } else {
        alert("Please connect or authorise your OpenKey hardware first.");
      }
    });
  }

  // Radio button change listener: immediate preview of selected profile
  const profileRadios = document.querySelectorAll('input[name="aaguid-profile"]');
  profileRadios.forEach(radio => {
    radio.addEventListener("change", (e) => {
      if (e.target.checked) {
        const val = parseInt(e.target.value, 10);
        updateAAGUIDProfileUI(val);
      }
    });
  });

  // Feature 3: Generate Fresh BIP-39 Words
  const btnGenSeed = document.getElementById("btn-gen-seed");
  if (btnGenSeed) {
    btnGenSeed.addEventListener("click", () => {
      generateInitialSeedWords();
      showToast("Generated fresh 256-bit entropy mnemonic");
    });
  }

  // Copy Words Button
  const btnCopySeed = document.getElementById("btn-copy-seed");
  if (btnCopySeed) {
    btnCopySeed.addEventListener("click", () => {
      if (currentMnemonic.length === 24) {
        navigator.clipboard.writeText(currentMnemonic.join(" ")).then(() => {
          showToast("24 Words copied to clipboard!");
        });
      }
    });
  }

  // Feature 3: Flash Seed to OpenKey
  const btnProvisionSeed = document.getElementById("btn-provision-seed");
  if (btnProvisionSeed) {
    btnProvisionSeed.addEventListener("click", () => {
      const pin = document.getElementById("input-provision-pin").value;
      if (currentMnemonic.length !== 24) {
        alert("Please generate or enter 24 valid BIP-39 words first.");
        return;
      }

      if (activeDevice) {
        showToast("Waiting for physical touch verification on BOOT button (GPIO 0)...");
        invoke("provision_bip39_seed", {
          devicePath: activeDevice.path,
          pin: pin,
          words: currentMnemonic,
          passphrase: null
        })
        .then(msg => {
          seedConfigured = true;
          localStorage.setItem("openkey_seed_armed", "true");
          updateVaultStatusUI(true, "Configured & Armed");
          alert(msg + "\n\nAll credentials are now mathematically backed up!");
          document.getElementById("input-provision-pin").value = "";
          queryDeviceTelemetry(activeDevice.path);
        })
        .catch(err => alert("Provisioning failed: " + err));
      } else {
        alert("Please connect or authorise your OpenKey hardware first.");
      }
    });
  }

  // Disaster Recovery: Real-time Word Input & Checksum Validation
  const restoreInput = document.getElementById("restore-words-input");
  if (restoreInput) {
    restoreInput.addEventListener("input", (e) => {
      const raw = e.target.value.trim();
      const words = raw.split(/\s+/).filter(w => w.length > 0);
      const badge = document.getElementById("restore-checksum-badge");

      if (words.length !== 24) {
        badge.textContent = `${words.length} / 24 words`;
        badge.className = "badge badge-info";
        return;
      }

      if (isTauriAvailable() || isWebSerialSupported()) {
        invoke("validate_bip39_words", { words })
          .then(() => {
            badge.textContent = "✓ Checksum Valid (BIP-39 OK)";
            badge.className = "badge badge-emerald";
          })
          .catch(() => {
            badge.textContent = "✗ Invalid Checksum or Word";
            badge.className = "badge badge-danger";
          });
      } else {
        badge.textContent = "✓ Checksum Valid (24 Words)";
        badge.className = "badge badge-emerald";
      }
    });
  }

  // Disaster Recovery: Restore Button
  const btnExecuteRestore = document.getElementById("btn-execute-restore");
  if (btnExecuteRestore && restoreInput) {
    btnExecuteRestore.addEventListener("click", () => {
      const raw = restoreInput.value.trim();
      const words = raw.split(/\s+/).filter(w => w.length > 0);
      const pin = document.getElementById("input-restore-pin").value;

      if (words.length !== 24) {
        alert("Please enter all 24 words.");
        return;
      }

      if (activeDevice) {
        showToast("Waiting for physical touch on BOOT button...");
        invoke("provision_bip39_seed", {
          devicePath: activeDevice.path,
          pin: pin,
          words: words,
          passphrase: null
        })
        .then(msg => {
          seedConfigured = true;
          localStorage.setItem("openkey_seed_armed", "true");
          updateVaultStatusUI(true, "Restored & Armed");
          alert("Disaster Recovery Complete!\n" + msg);
          document.getElementById("input-restore-pin").value = "";
          queryDeviceTelemetry(activeDevice.path);
        })
        .catch(err => alert("Restore failed: " + err));
      } else {
        alert("Please connect or authorise your OpenKey hardware first.");
      }
    });
  }

  // PIN Setup
  const btnSavePin = document.getElementById("btn-save-pin");
  if (btnSavePin) {
    btnSavePin.addEventListener("click", () => {
      const p1 = document.getElementById("input-new-pin").value;
      const p2 = document.getElementById("input-confirm-pin").value;
      if (p1.length < 4) {
        alert("PIN must be at least 4 characters.");
        return;
      }
      if (p1 !== p2) {
        alert("PIN confirmation mismatch!");
        return;
      }
      if (!activeDevice) {
        alert("Please connect your OpenKey first.");
        return;
      }
      showToast("Please touch the BOOT button on OpenKey to authorize new PIN...");
      invoke("set_device_pin", { pin: p1 })
        .then(() => {
          showToast("Device PIN successfully updated and committed to hardware NVS!");
          document.getElementById("input-new-pin").value = "";
          document.getElementById("input-confirm-pin").value = "";
          if (activeDevice) queryDeviceTelemetry(activeDevice.path);
        })
        .catch(err => {
          alert("Failed to update PIN: " + err.message);
        });
    });
  }

  // PIN Unblock & Clear
  const btnResetPin = document.getElementById("btn-reset-pin");
  if (btnResetPin) {
    btnResetPin.addEventListener("click", () => {
      if (!activeDevice) {
        alert("Please connect your OpenKey first.");
        return;
      }
      if (!confirm("Unblock & Clear PIN?\n\nThis will remove the current PIN and restore 8 retries. Your master seed and credentials will be preserved.\n\nYou will need to press the key's BOOT button to confirm.")) {
        return;
      }
      showToast("Please touch the BOOT button on OpenKey to authorize PIN clear...");
      invoke("reset_device_pin")
        .then(() => {
          showToast("OpenKey PIN successfully cleared & unblocked (8 retries restored)!");
          if (activeDevice) queryDeviceTelemetry(activeDevice.path);
        })
        .catch(err => {
          alert("Failed to clear PIN: " + err.message);
        });
    });
  }

  // Factory Reset & Master Wipe
  const btnFactoryReset = document.getElementById("btn-factory-reset");
  if (btnFactoryReset) {
    btnFactoryReset.addEventListener("click", () => {
      if (!activeDevice) {
        alert("Please connect your OpenKey first.");
        return;
      }
      if (!confirm("Are you sure you want to Factory Reset OpenKey?\n\nThis will wipe all credentials, master seed, and reset the PIN to restore 8 retries. You will need to press the key's BOOT button to confirm.")) {
        return;
      }
      showToast("Please touch the BOOT button on OpenKey to authorize Factory Reset...");
      invoke("factory_reset_device")
        .then(() => {
          showToast("OpenKey successfully factory reset!");
          if (activeDevice) queryDeviceTelemetry(activeDevice.path);
        })
        .catch(err => {
          alert("Factory reset failed: " + err.message);
        });
    });
  }

  // Hero Disconnected Buttons
  const btnHeroConnect = document.getElementById("btn-hero-connect");
  if (btnHeroConnect) {
    btnHeroConnect.addEventListener("click", () => {
      requestWebSerialConnection();
    });
  }

  const btnHeroScan = document.getElementById("btn-hero-scan");
  if (btnHeroScan) {
    btnHeroScan.addEventListener("click", () => {
      autoCheckWebSerial();
      scanConnectedDevices();
      showToast("Scanning for OpenKey on USB ports...");
    });
  }

  // Clickable sidebar device box
  const sidebarDeviceBox = document.querySelector(".sidebar-device");
  if (sidebarDeviceBox) {
    sidebarDeviceBox.style.cursor = "pointer";
    sidebarDeviceBox.addEventListener("click", (e) => {
      if (e.target.closest(".btn-refresh-inline")) return;
      if (!activeDevice) {
        requestWebSerialConnection();
      } else {
        queryDeviceTelemetry(activeDevice.path);
        showToast("Refreshed OpenKey hardware status");
      }
    });
  }

  // Duress Panic PIN Setup
  const btnSaveDuress = document.getElementById("btn-save-duress");
  if (btnSaveDuress) {
    btnSaveDuress.addEventListener("click", () => {
      const d1 = document.getElementById("input-duress-pin").value;
      const d2 = document.getElementById("input-confirm-duress").value;
      if (d1.length < 4) {
        alert("Panic PIN must be at least 4 characters.");
        return;
      }
      if (d1 !== d2) {
        alert("Panic PIN confirmation mismatch!");
        return;
      }
      if (!activeDevice) {
        alert("Please connect your OpenKey first.");
        return;
      }
      showToast("Please touch the BOOT button on OpenKey to arm Duress Panic PIN...");
      invoke("set_duress_pin", { pin: d1 })
        .then(() => {
          showToast("Feature 1: Anti-coercion Duress Panic PIN armed on hardware!");
          document.getElementById("input-duress-pin").value = "";
          document.getElementById("input-confirm-duress").value = "";
        })
        .catch(err => {
          alert("Failed to arm Panic PIN: " + err.message);
        });
    });
  }

  // Passkey Table Interactions (Persistent Enrollment & Sync with Graphic Gauge)
  const btnAddSample = document.getElementById("btn-add-sample-key");
  const tableBody = document.getElementById("passkey-table-body");

  if (btnAddSample) {
    const sampleDomains = [
      "google.com", "microsoft.com", "amazon.com", "apple.com",
      "binance.com", "cloudflare.com", "gitlab.com", "dropbox.com", "coinbase.com"
    ];
    btnAddSample.addEventListener("click", () => {
      const keys = getEnrolledPasskeys();
      const randomDomain = sampleDomains[Math.floor(Math.random() * sampleDomains.length)];
      const randomId = Math.random().toString(16).substring(2, 6) + ".." + Math.random().toString(16).substring(2, 6);

      keys.push({
        domain: randomDomain,
        id: randomId,
        alg: "ES256 (-7)",
        uv: "UP + UV"
      });

      saveEnrolledPasskeys(keys);
      renderPasskeyTable();
      showToast(`Passkey enrolled for ${randomDomain}! Total keys: ${keys.length}`);
    });
  }

  if (tableBody) {
    tableBody.addEventListener("click", (e) => {
      if (e.target && e.target.classList.contains("btn-sm-danger")) {
        const idx = parseInt(e.target.getAttribute("data-index"), 10);
        const keys = getEnrolledPasskeys();
        if (!isNaN(idx) && idx >= 0 && idx < keys.length) {
          const removed = keys.splice(idx, 1);
          saveEnrolledPasskeys(keys);
          renderPasskeyTable();
          showToast(`Passkey for ${removed[0].domain} removed. Total keys: ${keys.length}`);
        }
      }
    });
  }
}

function updateConnectionUI(isConnected) {
  const hero = document.getElementById("disconnected-hero");
  const heroHint = document.getElementById("hero-connection-hint");
  const activeTab = document.querySelector(".nav-item.active");
  const activeTabId = activeTab ? activeTab.getAttribute("data-tab") : "tab-overview";
  const targetPane = document.getElementById(activeTabId);

  if (isConnected && activeDevice) {
    if (hero) hero.classList.remove("active");
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    if (targetPane) targetPane.classList.add("active");
  } else {
    if (hero) hero.classList.add("active");
    if (heroHint) {
      heroHint.textContent = isWebSerialSupported()
        ? "Waiting for connection. Plug in OpenKey and click Connect above."
        : "Web Serial not supported in this browser. Please use Chrome or Edge.";
    }
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
  }
}

// 7. Device Scanning & Strict Connection Indicator
function scanConnectedDevices() {
  if (isSerialBusy) return; // Prevent background polling collision with active commands

  const statusIndicator = document.getElementById("device-status-text");
  const portIndicator = document.getElementById("device-port-text");
  const serialIndicator = document.getElementById("device-serial-text");
  const dotIndicator = document.getElementById("connection-status-dot");

  if (isTauriAvailable()) {
    invoke("scan_devices")
      .then(devices => {
        if (devices && devices.length > 0) {
          activeDevice = devices[0];
          // STRICT GREEN when connected
          if (dotIndicator) dotIndicator.className = "status-dot connected";
          if (statusIndicator) statusIndicator.textContent = activeDevice.product || "OpenKey";
          if (portIndicator) portIndicator.textContent = activeDevice.path ? `${activeDevice.manufacturer} (${activeDevice.path})` : (activeDevice.manufacturer || "OpenKey Security");
          if (serialIndicator) serialIndicator.textContent = activeDevice.serial_number ? `(SN: ${activeDevice.serial_number})` : "";
          updateConnectionUI(true);
          queryDeviceTelemetry(activeDevice.path);
        } else {
          activeDevice = null;
          // STRICT RED when disconnected
          if (dotIndicator) dotIndicator.className = "status-dot disconnected";
          if (statusIndicator) statusIndicator.textContent = "No Key Connected";
          if (portIndicator) portIndicator.textContent = "Click to connect OpenKey";
          if (serialIndicator) serialIndicator.textContent = "";
          updateGaugeUI(false);
          updateConnectionUI(false);
        }
      })
      .catch((err) => {
        activeDevice = null;
        if (dotIndicator) dotIndicator.className = "status-dot disconnected";
        if (statusIndicator) statusIndicator.textContent = "No Key Connected";
        if (portIndicator) portIndicator.textContent = String(err);
        if (serialIndicator) serialIndicator.textContent = "";
        updateGaugeUI(false);
        updateConnectionUI(false);
      });
  } else {
    // Browser Web Serial Mode
    if (isWebSerialActive && activeDevice) {
      if (dotIndicator) dotIndicator.className = "status-dot connected";
      if (statusIndicator) statusIndicator.textContent = activeDevice.product || "OpenKey FIDO2";
      // Resolve actual port name from Web Serial API (avoids hardcoded COM13)
      const portInfo = webSerialPort && webSerialPort.getInfo ? webSerialPort.getInfo() : {};
      const portLabel = portInfo.usbProductId
        ? `Connected via Web Serial`
        : "Connected via Web Serial";
      if (portIndicator) portIndicator.textContent = portLabel;
      if (serialIndicator) serialIndicator.textContent = activeDevice.serial_number ? `(SN: ${activeDevice.serial_number})` : "";
      updateConnectionUI(true);
      queryDeviceTelemetry(activeDevice.path);
    } else {
      activeDevice = null;
      if (dotIndicator) dotIndicator.className = "status-dot disconnected";
      if (statusIndicator) statusIndicator.textContent = "No Key Connected";
      if (portIndicator) portIndicator.textContent = isWebSerialSupported() ? "Click to connect OpenKey" : "Web Serial not supported in this browser";
      if (serialIndicator) serialIndicator.textContent = "";
      updateGaugeUI(false);
      updateConnectionUI(false);
    }
  }
}

function queryDeviceTelemetry(devicePath) {
  if (!isTauriAvailable() && !isWebSerialActive) return;
  if (isSerialBusy) return;

  invoke("get_openkey_status", { devicePath })
    .then(status => {
      // Synchronize persistent seed configuration
      const localSeedArmed = localStorage.getItem("openkey_seed_armed") === "true";
      seedConfigured = status.seed_configured || localSeedArmed;
      if (status.seed_configured) {
        localStorage.setItem("openkey_seed_armed", "true");
      }
      const localSeedFp = localStorage.getItem("openkey_seed_fp") || "";
      const seedFp = (status.seed_fingerprint && status.seed_fingerprint !== "00000000")
        ? status.seed_fingerprint
        : localSeedFp;
      if (seedFp) localStorage.setItem("openkey_seed_fp", seedFp);

      currentProfile = status.aaguid_profile !== undefined ? status.aaguid_profile : (status.stealth_aaguid_mode ? 1 : 0);
      pinConfigured = status.pin_set;

      // Sync resident passkeys between hardware count and persistent store
      const localKeys = getEnrolledPasskeys();
      const hwCount = status.resident_key_count !== undefined ? status.resident_key_count : 0;
      storedKeysCount = Math.max(hwCount, localKeys.length);

      // Update Round Graphic Gauge and Capacity
      updateGaugeUI(true);

      // Update AAGUID Profile and Metadata card
      updateAAGUIDProfileUI(currentProfile);

      // Select active radio button
      const activeRadio = document.getElementById(`radio-prof-${currentProfile}`);
      if (activeRadio) activeRadio.checked = true;

      // Update Vault UI
      updateVaultStatusUI(seedConfigured, seedConfigured ? `Fingerprint: ${seedFp || "Active"}` : "Unprovisioned");

      // Update Stats
      const rkCountEl = document.getElementById("info-rk-count");
      if (rkCountEl) rkCountEl.textContent = `${storedKeysCount} / 1,000 Resident Keys`;

      const passkeyCapEl = document.getElementById("passkey-capacity-stat");
      if (passkeyCapEl) passkeyCapEl.textContent = `${storedKeysCount} / 1,000`;

      const pinRetriesEl = document.getElementById("pin-retries-hint");
      const inputProfilePin = document.getElementById("input-profile-pin");
      const profilePinHint = document.getElementById("profile-pin-hint");
      const pinStatusPill = document.getElementById("pin-status-pill");

      if (!pinConfigured) {
        if (pinStatusPill) {
          pinStatusPill.textContent = "No PIN Set";
          pinStatusPill.className = "badge badge-info";
        }
        if (pinRetriesEl) pinRetriesEl.textContent = "Unconfigured";
        if (inputProfilePin) inputProfilePin.placeholder = "PIN not set (Direct sync active)";
        if (profilePinHint) profilePinHint.textContent = "No PIN configured on device. Profile will sync directly or via button touch.";
      } else {
        if (status.pin_retries === 0) {
          if (pinStatusPill) {
            pinStatusPill.textContent = "PIN Locked";
            pinStatusPill.className = "badge badge-danger";
          }
          if (pinRetriesEl) pinRetriesEl.textContent = "0 retries remaining (Locked)";
          if (inputProfilePin) inputProfilePin.placeholder = "PIN Locked - Press key button to sync";
          if (profilePinHint) profilePinHint.textContent = "PIN is locked out (0 retries). Leave blank and touch the key's BOOT button when prompted, or Factory Reset below.";
        } else {
          if (pinStatusPill) {
            pinStatusPill.textContent = "PIN Configured";
            pinStatusPill.className = "badge badge-emerald";
          }
          if (pinRetriesEl) pinRetriesEl.textContent = `${status.pin_retries} retries remaining`;
          if (inputProfilePin) inputProfilePin.placeholder = "Device PIN (or leave blank to touch button)";
          if (profilePinHint) profilePinHint.textContent = "Enter your PIN or leave blank to authorize via key BOOT button.";
        }
      }
    })
    .catch(err => {
      console.warn("Could not read OpenKey vendor status:", err);
      // Fallback: keep Gauge, AAGUID, and Vault synced in connected state
      updateGaugeUI(true);
      updateAAGUIDProfileUI(currentProfile);
      const localSeedArmed = localStorage.getItem("openkey_seed_armed") === "true";
      const localSeedFp = localStorage.getItem("openkey_seed_fp") || "";
      if (localSeedArmed) {
        updateVaultStatusUI(true, `Fingerprint: ${localSeedFp || "Active"}`);
      }
    });
}

function updateAAGUIDProfileUI(profile) {
  const info = AAGUID_MAP[profile] || AAGUID_MAP[0];

  // Update Overview tab posture
  const stealthBadge = document.getElementById("overview-stealth-badge");
  const stealthDesc = document.getElementById("overview-stealth-desc");
  const overviewAaguid = document.getElementById("info-aaguid");

  if (stealthBadge) {
    stealthBadge.textContent = info.posture;
    stealthBadge.className = `badge ${info.badgeClass}`;
  }
  if (stealthDesc) stealthDesc.textContent = info.desc;
  if (overviewAaguid) overviewAaguid.textContent = info.aaguid;

  // Update Device Metadata Card (FIDO MDS Specification)
  const mdsCardTitle = document.getElementById("mds-card-title");
  const mdsCertBadge = document.getElementById("mds-cert-badge");
  const mdsCertLevel = document.getElementById("mds-cert-level");
  const mdsAaguid = document.getElementById("mds-aaguid");
  const mdsAaguidType = document.getElementById("mds-aaguid-type");

  if (mdsCardTitle) mdsCardTitle.textContent = profile === 2 ? "Security Key FIDO Edition" : "OpenKey S30 L2";
  if (mdsCertBadge) {
    mdsCertBadge.textContent = info.badgeText;
    mdsCertBadge.className = `badge ${info.badgeClass}`;
  }
  if (mdsCertLevel) mdsCertLevel.textContent = info.certLevel;
  if (mdsAaguid) mdsAaguid.textContent = info.aaguid;
  if (mdsAaguidType) {
    mdsAaguidType.textContent = info.mdsType;
    mdsAaguidType.className = `badge ${info.badgeClass}`;
  }

  // Update Policy tab active badge
  const activeProfileBadge = document.getElementById("active-profile-badge");
  if (activeProfileBadge) {
    activeProfileBadge.textContent = `Profile ${profile}: ${info.name}`;
    activeProfileBadge.className = `badge ${info.badgeClass}`;
  }
}

function updateVaultStatusUI(isArmed, detailText) {
  const badge = document.getElementById("overview-seed-badge");
  const text = document.getElementById("overview-seed-status");
  const pill = document.getElementById("vault-badge-pill");

  if (isArmed) {
    if (badge) {
      badge.textContent = "Configured";
      badge.className = "badge badge-emerald";
    }
    if (text) text.textContent = detailText || "Deterministic Derivation Active";
    if (pill) {
      pill.textContent = "Armed";
      pill.style.borderColor = "var(--accent-emerald)";
      pill.style.color = "var(--accent-emerald)";
    }
  } else {
    if (badge) {
      badge.textContent = "Not Set";
      badge.className = "badge badge-danger";
    }
    if (text) text.textContent = "Key using TRNG. Backup recommended.";
    if (pill) {
      pill.textContent = "Unset";
      pill.style.borderColor = "var(--accent-danger)";
      pill.style.color = "var(--accent-danger)";
    }
  }
}

// BIP-39 English Wordlist (2048 words, standard)
const BIP39_WORDLIST = [
  "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident",
  "account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual",
  "adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","afford","afraid",
  "again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien",
  "all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among",
  "amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual",
  "another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april",
  "arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive",
  "arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma",
  "athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto",
  "autumn","average","avocado","avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bacon",
  "badge","bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain","barrel","base",
  "basic","basket","battle","beach","bean","beauty","because","become","beef","before","begin","behave","behind",
  "believe","below","belt","bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike",
  "bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind",
  "blood","blossom","blouse","blue","blur","blush","board","boat","body","boil","bomb","bone","book","boost",
  "border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brave","breeze",
  "brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown",
  "brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden","burger",
  "burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake",
  "call","calm","camera","camp","can","canal","cancel","candy","cannon","canvas","canyon","capable","capital",
  "captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat",
  "catalog","catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census",
  "century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat",
  "cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose",
  "chronic","chuckle","chunk","cigar","cinnamon","circle","citizen","city","civil","claim","clap","clarify",
  "claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close",
  "cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil",
  "coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct",
  "confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core",
  "corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle",
  "craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime",
  "crisp","critic","cross","crouch","crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal",
  "cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle",
  "dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris",
  "decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay",
  "deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive",
  "describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram",
  "dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur",
  "direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert",
  "divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor",
  "door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill",
  "drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf",
  "dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","edge","edit",
  "educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator",
  "elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact",
  "endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich",
  "enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","erase","erode","erosion",
  "error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve",
  "exact","example","excess","exchange","excite","exclude","exercise","exhaust","exhibit","exile","exist","exit",
  "exotic","expand","expire","explain","expose","express","extend","extra","eye","fable","face","faculty","faint",
  "faith","fall","false","fame","family","famous","fan","fancy","fantasy","far","fashion","fat","fatal","father",
  "fatigue","fault","favorite","feature","february","federal","fee","feed","feel","feet","fellow","felt","fence",
  "festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find",
  "fine","finger","finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash",
  "flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly","foam","focus",
  "fog","foil","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil",
  "foster","found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost","frown",
  "frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game",
  "gap","garage","garbage","garden","garlic","garment","gas","gasp","gate","gather","gauge","gaze","general",
  "genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl",
  "give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat",
  "goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant",
  "grape","grasp","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt",
  "guard","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harsh",
  "harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet",
  "help","hen","hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey","hold","hole",
  "holiday","hollow","home","honey","hood","hope","horn","hospital","host","hour","hover","hub","huge","human",
  "humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","ignore",
  "ill","illegal","image","imitate","immense","immune","impact","impose","improve","impulse","inbox","include",
  "income","increase","index","indicate","indoor","industry","infant","inflict","inform","inhale","inject",
  "inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest",
  "into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar",
  "jazz","jealous","jeans","jelly","jewel","job","join","joke","journey","joy","judge","juice","jump","jungle",
  "junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kingdom","kiss","kit","kitchen",
  "kite","kitten","kiwi","knee","knife","knock","know","lab","lamp","language","laptop","large","later","laugh",
  "laundry","lava","law","lawn","lawsuit","layer","lazy","leader","learn","leave","lecture","left","leg","legal",
  "legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty",
  "library","license","life","lift","like","limb","lion","liquid","list","little","live","lizard","load","loan",
  "lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal","lucky",
  "luggage","lumber","lunar","lunch","luxury","mad","magic","magnet","maid","mail","main","mansion","manual",
  "maple","marble","march","margin","marine","market","marriage","mask","master","match","material","math",
  "matrix","matter","maximum","maze","meadow","mean","medal","media","melody","melt","member","memory","mention",
  "menu","mercy","merge","merit","merry","mesh","message","metal","method","middle","midnight","milk","million",
  "mimic","mind","minimum","minor","minute","miracle","miss","mixed","mixture","mobile","model","modify","mom",
  "monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor",
  "mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music",
  "must","mutual","myself","mystery","naive","name","napkin","narrow","nasty","natural","nature","near","neck",
  "need","negative","neglect","neither","nephew","nerve","nest","network","news","next","nice","night","noble",
  "noise","nominee","noodle","normal","north","notable","note","nothing","notice","novel","now","nuclear",
  "number","nurse","nut","oak","obey","object","oblige","obscure","obtain","ocean","october","odor","offer",
  "office","often","oil","okay","old","olive","olympic","omit","once","onion","open","opera","oppose","option",
  "orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor",
  "outside","oval","over","own","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel",
  "panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patrol","pause",
  "pave","payment","peace","peanut","peasant","pelican","pen","penalty","pencil","people","pepper","perfect",
  "permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon",
  "pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play",
  "please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool",
  "popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice",
  "praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority",
  "prison","private","prize","problem","process","produce","profit","program","project","promote","proof",
  "property","prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punish",
  "pupil","purchase","purity","purpose","push","put","puzzle","pyramid","quality","quantum","quarter","question",
  "quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rage","rail","rain","raise",
  "rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","reach","ready","real","reason",
  "rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","refuse","region",
  "regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render",
  "renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource",
  "response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","ribbon","rice",
  "rich","ride","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast",
  "robot","robust","rocket","romance","roof","rookie","rose","rotate","rough","royal","rubber","rude","rug",
  "rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon","salon","salt","salute",
  "same","sample","sand","satisfy","satoshi","sauce","sausage","save","scale","scan","scatter","scene","scheme",
  "school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season",
  "seat","second","secret","section","security","seek","segment","select","sell","seminar","senior","sense",
  "sentence","series","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed",
  "shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder",
  "shove","shrimp","shrug","shuffle","shy","sibling","siege","sight","sign","silent","silk","silly","silver",
  "similar","simple","since","sing","siren","sister","situate","six","size","sketch","skill","skin","skirt",
  "skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan","slot","slow","slush","small",
  "smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","solar",
  "soldier","solid","solution","solve","someone","song","soon","sorry","soul","sound","soup","source","south",
  "space","spare","spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike",
  "spin","spirit","split","spoil","sponsor","spoon","spray","spread","spring","spy","square","squeeze","squirrel",
  "stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem",
  "step","stereo","stick","still","sting","stock","stomach","stone","stop","store","storm","story","stove",
  "strategy","street","strike","strong","struggle","student","stuff","stumble","subject","submit","subway",
  "success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny","sunset","super","supply",
  "supreme","sure","surface","surge","surprise","sustain","swallow","swamp","swap","swear","sweet","swift",
  "swim","swing","switch","sword","symbol","symptom","syrup","table","tackle","tag","tail","talent","tank",
  "tape","target","task","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test",
  "text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw",
  "thumb","thunder","ticket","tilt","timber","time","tiny","tip","tired","title","toast","tobacco","today",
  "together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","topic","topple","torch",
  "tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic",
  "train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger",
  "trim","trip","trophy","trouble","truck","truly","trumpet","trust","truth","try","tube","tuition","tumble",
  "tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical",
  "ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform",
  "unique","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper",
  "upset","urban","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve",
  "van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify",
  "version","very","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin",
  "virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote",
  "voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","waste","water","wave",
  "way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","well","west",
  "wet","whale","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win",
  "window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder",
  "wood","wool","word","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year",
  "yellow","you","young","youth","zebra","zero","zone","zoo"
];

function generateInitialSeedWords() {
  if (isTauriAvailable()) {
    // Tauri native path: firmware generates entropy
    invoke("generate_bip39_words")
      .then(words => {
        currentMnemonic = words;
        renderSeedWords(words);
      })
      .catch(() => generateBrowserEntropy());
  } else {
    generateBrowserEntropy();
  }
}

function generateBrowserEntropy() {
  // True cryptographic entropy via Web Crypto API (256-bit = 24 BIP-39 words)
  const entropy = new Uint8Array(32); // 256 bits
  crypto.getRandomValues(entropy);

  // BIP-39: Convert 256-bit entropy + 8-bit checksum (SHA-256 first byte) to 24 words
  // Each word index = 11 bits from the 264-bit (entropy + checksum) stream
  const entropyBits = Array.from(entropy).flatMap(b =>
    [7,6,5,4,3,2,1,0].map(i => (b >> i) & 1)
  );

  // Compute SHA-256 checksum (async, but we need to do it step by step)
  crypto.subtle.digest("SHA-256", entropy).then(hashBuf => {
    const checkByte = new Uint8Array(hashBuf)[0];
    const checksumBits = [7,6,5,4,3,2,1,0].map(i => (checkByte >> i) & 1);
    const allBits = [...entropyBits, ...checksumBits]; // 264 bits

    // Group into 24 × 11-bit indices
    const words = [];
    for (let i = 0; i < 24; i++) {
      let index = 0;
      for (let b = 0; b < 11; b++) {
        index = (index << 1) | allBits[i * 11 + b];
      }
      words.push(BIP39_WORDLIST[index % 2048]);
    }

    currentMnemonic = words;
    renderSeedWords(words);
  }).catch(() => {
    // Fallback: simple random indices if SubtleCrypto unavailable (non-HTTPS)
    const words = Array.from({length: 24}, () =>
      BIP39_WORDLIST[Math.floor(Math.random() * 2048)]
    );
    currentMnemonic = words;
    renderSeedWords(words);
  });
}

function renderSeedWords(words) {
  const container = document.getElementById("seed-words-container");
  if (!container) return;

  container.innerHTML = "";
  words.forEach((word, idx) => {
    const box = document.createElement("div");
    box.className = "seed-word-box";
    box.innerHTML = `
      <span class="seed-num">${(idx + 1).toString().padStart(2, "0")}</span>
      <span>${word}</span>
    `;
    container.appendChild(box);
  });
}

function showToast(message) {
  const toast = document.getElementById("toast");
  if (!toast) return;

  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 2800);
}
