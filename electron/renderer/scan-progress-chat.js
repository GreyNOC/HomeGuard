(() => {
  const scanButton = document.getElementById("scanButton");
  const activeScan = document.getElementById("activeScan");
  const probeAll = document.getElementById("probeAll");
  const chatMessages = document.getElementById("chatMessages");
  const output = document.getElementById("output");
  const statusText = document.getElementById("statusText");

  if (!scanButton || !chatMessages || !window.homeguard?.onScanProgress) {
    return;
  }

  const HEARTBEAT_MS = 10000;
  const MAX_CHAT_LINES = 18;

  let scanState = null;
  let heartbeatTimer = null;
  let stopWatcher = null;

  function nowLabel() {
    return new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function elapsedLabel(startedAt) {
    const totalSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  }

  function scrollChat() {
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function createScanMessage() {
    const article = document.createElement("article");
    article.className = "message assistant-message scan-progress-message";

    const avatar = document.createElement("div");
    avatar.className = "avatar scan-progress-avatar";
    avatar.textContent = "HG";

    const card = document.createElement("div");
    card.className = "message-card scan-progress-card";

    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.textContent = "Live scan progress";

    const title = document.createElement("h2");
    title.textContent = "HomeGuard is scanning";

    const summary = document.createElement("p");
    summary.className = "scan-progress-summary";

    const log = document.createElement("div");
    log.className = "scan-progress-log";

    card.appendChild(eyebrow);
    card.appendChild(title);
    card.appendChild(summary);
    card.appendChild(log);
    article.appendChild(avatar);
    article.appendChild(card);
    chatMessages.appendChild(article);
    scrollChat();
    return { article, title, summary, log };
  }

  function setStatus(message) {
    if (statusText) {
      statusText.textContent = message;
    }
  }

  function appendOutputLine(line) {
    if (!output) {
      return;
    }
    const existing = output.textContent && output.textContent !== "No command output yet." ? output.textContent.trimEnd() : "";
    output.textContent = `${existing}${existing ? "\n" : ""}${line}`;
    output.scrollTop = output.scrollHeight;
  }

  function phaseFromMessage(message) {
    const text = String(message || "").toLowerCase();
    if (/prepar|queued/.test(text)) return "Preparing scan";
    if (/interface|arp|neighbor|ping|tcp|service|network scan/.test(text)) return "Discovering local devices";
    if (/found \d+ local device/.test(text)) return "Reviewing discovered devices";
    if (/known-device|baseline|trust/.test(text)) return "Checking device trust";
    if (/detection|finding|risk rule|delta|changed/.test(text)) return "Evaluating risk";
    if (/endpoint|malware|defender|process|startup|powershell/.test(text)) return "Scanning endpoint signals";
    if (/writing|report|html|pdf|json|csv/.test(text)) return "Writing reports";
    if (/history|saving/.test(text)) return "Saving scan history";
    if (/complete|ready/.test(text)) return "Complete";
    return "Working";
  }

  function updateChatCard(done = false) {
    if (!scanState?.nodes) {
      return;
    }
    const elapsed = elapsedLabel(scanState.startedAt);
    const activeMode = scanState.active ? "active bounded probing" : "passive local discovery";
    const probeMode = scanState.probeAll ? "all bounded hosts" : "standard host set";
    scanState.nodes.title.textContent = done ? "HomeGuard scan complete" : "HomeGuard is scanning";
    scanState.nodes.summary.textContent = done
      ? `Finished after ${elapsed}. Final stage: ${scanState.phase}.`
      : `Elapsed ${elapsed}. Mode: ${activeMode}; target scope: ${probeMode}. Current stage: ${scanState.phase}.`;
    scanState.nodes.log.textContent = scanState.lines.slice(-MAX_CHAT_LINES).join("\n");
    scrollChat();
  }

  function appendScanLine(message, { heartbeat = false } = {}) {
    if (!scanState) {
      return;
    }
    const clean = String(message || "").trim();
    if (!clean) {
      return;
    }
    scanState.phase = phaseFromMessage(clean);
    scanState.lastMessage = clean;
    scanState.lastUpdateAt = Date.now();
    const prefix = heartbeat ? "status" : "scan";
    const line = `[${nowLabel()}] ${prefix}: ${clean}`;
    scanState.lines.push(line);
    scanState.lines = scanState.lines.slice(-64);
    appendOutputLine(line);
    setStatus(clean);
    updateChatCard(false);
  }

  function heartbeat() {
    if (!scanState) {
      return;
    }
    const quietFor = Math.floor((Date.now() - scanState.lastUpdateAt) / 1000);
    const last = scanState.lastMessage || "HomeGuard scan is still running.";
    appendScanLine(`${scanState.phase}. Still running; last scanner update was ${quietFor}s ago. Last update: ${last}`, {
      heartbeat: true,
    });
  }

  function stopScanProgress(reason = "Reports are ready.") {
    if (!scanState) {
      return;
    }
    appendScanLine(reason, { heartbeat: true });
    updateChatCard(true);
    clearInterval(heartbeatTimer);
    clearInterval(stopWatcher);
    heartbeatTimer = null;
    stopWatcher = null;
    scanState = null;
  }

  function startScanProgress() {
    clearInterval(heartbeatTimer);
    clearInterval(stopWatcher);
    scanState = {
      startedAt: Date.now(),
      active: Boolean(activeScan?.checked),
      probeAll: Boolean(probeAll?.checked),
      phase: "Queued",
      lastMessage: "Scan queued.",
      lastUpdateAt: Date.now(),
      lines: [],
      nodes: createScanMessage(),
    };
    appendScanLine(scanState.active ? "Active scan queued with bounded local probing." : "Passive scan queued with local network discovery.");
    heartbeatTimer = setInterval(heartbeat, HEARTBEAT_MS);
    stopWatcher = setInterval(() => {
      const status = String(statusText?.textContent || "").toLowerCase();
      const text = String(output?.textContent || "").toLowerCase();
      const complete = /scan complete/.test(status) || /reports are ready|final scan output/.test(text);
      const failed = /scan failed/.test(status);
      if (complete || failed) {
        stopScanProgress(failed ? "Scan stopped with an error. Review the activity output." : "Reports are ready.");
      }
    }, 1000);
  }

  scanButton.addEventListener("click", () => {
    setTimeout(startScanProgress, 0);
  });

  window.homeguard.onScanProgress((payload) => {
    appendScanLine(payload?.message || "Scan progress updated.");
  });

  window.addEventListener("beforeunload", () => {
    clearInterval(heartbeatTimer);
    clearInterval(stopWatcher);
  });
})();
