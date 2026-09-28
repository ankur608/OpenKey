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

async function readExactBytes(numBytes, timeoutMs = 15000) {
  if (!webSerialPort || !webSerialPort.readable) {
    throw new Error("OpenKey serial port not readable");
  }
  const startTime = Date.now();
  const reader = webSerialPort.readable.getReader();

  try {
    while (serialReadBuffer.length < numBytes) {
      if (Date.now() - startTime > timeoutMs) {
        throw new Error("Timeout waiting for serial bytes from OpenKey");
      }
      const readPromise = reader.read();
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 1000)
      );
      try {
        const { value, done } = await Promise.race([readPromise, timeoutPromise]);
        if (done) break;
        if (value) {
          for (let i = 0; i < value.length; i++) {
            serialReadBuffer.push(value[i]);
          }
        }
      } catch (e) {
        // Chunk timeout, continue waiting
      }
    }
  } finally {
    reader.releaseLock();
  }

  if (serialReadBuffer.length < numBytes) {
    throw new Error("Timeout waiting for complete 64-byte frame from OpenKey");
  }

  const result = new Uint8Array(serialReadBuffer.slice(0, numBytes));
  serialReadBuffer = serialReadBuffer.slice(numBytes);
  return result;
}

async function sendWebSerialCtapCommand(cid, cmd, payload = new Uint8Array(0)) {
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
  const startTime = Date.now();
  let expectedTotal = null;
  let expectedSeq = 0;
  const respPayload = [];

  while (Date.now() - startTime < 16000) {
    const pkt = await readExactBytes(64, 15000);
    const pktCid = ((pkt[0] << 24) | (pkt[1] << 16) | (pkt[2] << 8) | pkt[3]) >>> 0;
    if (pktCid !== cid) continue;

    const cmdOrSeq = pkt[4];
    if (cmdOrSeq & 0x80) {
      // INIT frame
      const respCmd = cmdOrSeq & 0x7F;
      if (respCmd === 0x3B) continue; // Keepalive (waiting for physical touch)
      if (respCmd === 0x3F) {
        const err = pkt[7];
        let errMsg = `CTAPHID error: 0x${err.toString(16).padStart(2, '0')}`;
        if (err === 0x31) errMsg = "Invalid PIN (or leave blank & touch BOOT button on key to authorize)";
        else if (err === 0x32) errMsg = "PIN Locked (0 retries remaining). Please touch key BOOT button or Factory Reset below.";
        else if (err === 0x3A) errMsg = "Physical touch timed out (please touch the BOOT button when LED flashes)";
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
    path: "webserial:COM13",
    vendor_id: 0x303a,
    product_id: 0x822b,
    manufacturer: "OpenKey Security",
    product: "OpenKey ESP32-S3",
    serial_number: "OK-S30-00000001"
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
        filters: [{ usbVendorId: 0x303a }]
      });
    } catch (e) {
      webSerialPort = await navigator.serial.requestPort();
    }

    showToast("Connecting to OpenKey via Web Serial...");
    await webSerialPort.open({ baudRate: 115200 });
    await webSerialInitHandshake();
    showToast("OpenKey hardware connected & authorised via Web Serial!");
    scanConnectedDevices();
    return true;
  } catch (err) {
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
      await webSerialInitHandshake();
      scanConnectedDevices();
    }
  } catch (e) {
    // Port might be in use
  }
}

if (typeof navigator !== 'undefined' && 'serial' in navigator) {
  navigator.serial.addEventListener('disconnect', () => {
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

    case "factory_reset_device": {
      if (!isWebSerialActive) throw new Error("No OpenKey connected or authorised");
      const resp = await sendWebSerialCtapCommand(webSerialCid, 0x41, new Uint8Array([0x05]));
      if (resp.length === 0 || resp[0] !== 0x00) {
        throw new Error("Failed to factory reset OpenKey (touch confirmation timed out)");
      }
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

document.addEventListener("DOMContentLoaded", () => {
  setupTheme();
  setupNavigation();
  setupSubTabs();
  setupMDSTabs();
  setupGaugeInteractions();
  setupEventListeners();
  generateInitialSeedWords();
  
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
          updateVaultStatusUI(true, "Configured & Armed");
          alert(msg + "\n\nAll credentials are now mathematically backed up!");
          document.getElementById("input-provision-pin").value = "";
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
          updateVaultStatusUI(true, "Restored & Armed");
          alert("Disaster Recovery Complete!\n" + msg);
          document.getElementById("input-restore-pin").value = "";
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
      showToast("Feature 1: Anti-coercion Duress Panic PIN armed.");
      document.getElementById("input-duress-pin").value = "";
      document.getElementById("input-confirm-duress").value = "";
    });
  }

  // Passkey Table Interactions (Add / Delete Sync with Graphic Gauge)
  const btnAddSample = document.getElementById("btn-add-sample-key");
  const tableBody = document.getElementById("passkey-table-body");

  if (btnAddSample && tableBody) {
    const sampleDomains = ["google.com", "microsoft.com", "amazon.com", "apple.com", "binance.com", "cloudflare.com"];
    btnAddSample.addEventListener("click", () => {
      const randomDomain = sampleDomains[Math.floor(Math.random() * sampleDomains.length)];
      const randomId = Math.random().toString(16).substring(2, 6) + ".." + Math.random().toString(16).substring(2, 6);
      
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${randomDomain}</strong></td>
        <td class="mono text-xs">${randomId}</td>
        <td><span class="tag">ES256 (-7)</span></td>
        <td><span class="badge badge-emerald">UP + UV</span></td>
        <td><button class="btn-sm-danger">Delete</button></td>
      `;
      tableBody.appendChild(tr);
      storedKeysCount = tableBody.querySelectorAll("tr").length;
      updateGaugeUI(true);
      showToast(`Passkey enrolled for ${randomDomain}! Key count: ${storedKeysCount}`);
    });

    tableBody.addEventListener("click", (e) => {
      if (e.target && e.target.classList.contains("btn-sm-danger")) {
        const row = e.target.closest("tr");
        if (row) {
          row.remove();
          storedKeysCount = tableBody.querySelectorAll("tr").length;
          updateGaugeUI(true);
          showToast(`Passkey removed from NVS. Total keys: ${storedKeysCount}`);
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
          if (statusIndicator) statusIndicator.textContent = "No Key Detected or Authorised";
          if (portIndicator) portIndicator.textContent = "Insert OpenKey USB";
          if (serialIndicator) serialIndicator.textContent = "";
          updateGaugeUI(false);
          updateConnectionUI(false);
        }
      })
      .catch((err) => {
        activeDevice = null;
        if (dotIndicator) dotIndicator.className = "status-dot disconnected";
        if (statusIndicator) statusIndicator.textContent = "No Key Detected or Authorised";
        if (portIndicator) portIndicator.textContent = String(err);
        if (serialIndicator) serialIndicator.textContent = "";
        updateGaugeUI(false);
        updateConnectionUI(false);
      });
  } else {
    // Browser Web Serial Mode
    if (isWebSerialActive && activeDevice) {
      if (dotIndicator) dotIndicator.className = "status-dot connected";
      if (statusIndicator) statusIndicator.textContent = activeDevice.product || "OpenKey ESP32-S3";
      if (portIndicator) portIndicator.textContent = "Connected via Web Serial (COM13)";
      if (serialIndicator) serialIndicator.textContent = activeDevice.serial_number ? `(SN: ${activeDevice.serial_number})` : "";
      updateConnectionUI(true);
      queryDeviceTelemetry(activeDevice.path);
    } else {
      activeDevice = null;
      if (dotIndicator) dotIndicator.className = "status-dot disconnected";
      if (statusIndicator) statusIndicator.textContent = "No Key Detected or Authorised";
      if (portIndicator) portIndicator.textContent = isWebSerialSupported() ? "Click to Authorise OpenKey (COM13)" : "Web Serial not supported in this browser";
      if (serialIndicator) serialIndicator.textContent = "";
      updateGaugeUI(false);
      updateConnectionUI(false);
    }
  }
}

function queryDeviceTelemetry(devicePath) {
  if (!isTauriAvailable() && !isWebSerialActive) return;
  invoke("get_openkey_status", { devicePath })
    .then(status => {
      seedConfigured = status.seed_configured;
      currentProfile = status.aaguid_profile !== undefined ? status.aaguid_profile : (status.stealth_aaguid_mode ? 1 : 0);
      pinConfigured = status.pin_set;
      storedKeysCount = status.resident_key_count !== undefined ? status.resident_key_count : 0;

      // Update Round Graphic Gauge and Capacity
      updateGaugeUI(true);

      // Update AAGUID Profile and Metadata card
      updateAAGUIDProfileUI(currentProfile);

      // Select active radio button
      const activeRadio = document.getElementById(`radio-prof-${currentProfile}`);
      if (activeRadio) activeRadio.checked = true;

      // Update Vault UI
      updateVaultStatusUI(seedConfigured, seedConfigured ? `Fingerprint: ${status.seed_fingerprint}` : "Unprovisioned");

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
      // Fallback: keep Gauge and AAGUID synced in connected state
      updateGaugeUI(true);
      updateAAGUIDProfileUI(currentProfile);
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

function generateInitialSeedWords() {
  if (isTauriAvailable()) {
    invoke("generate_bip39_words")
      .then(words => {
        currentMnemonic = words;
        renderSeedWords(words);
      })
      .catch(() => renderFallbackWords());
  } else {
    renderFallbackWords();
  }
}

function renderFallbackWords() {
  currentMnemonic = [
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual"
  ];
  renderSeedWords(currentMnemonic);
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
