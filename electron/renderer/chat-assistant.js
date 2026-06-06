(() => {
  const chatMessages = document.getElementById("chatMessages");
  const chatForm = document.getElementById("chatForm");
  const chatInput = document.getElementById("chatInput");
  const newChatButton = document.getElementById("newChatButton");

  if (!chatMessages || !chatForm || !chatInput) {
    return;
  }

  const chatList = document.getElementById("chatList");
  const chatListEmpty = document.getElementById("chatListEmpty");
  const welcomeMessage = chatMessages.querySelector(".message.assistant-message");
  const chatsApi = window.homeguard?.chats || null;

  // ----- Chat persistence state -----
  // currentChatId is "" before the first message of a fresh chat; it gets
  // assigned the moment the backend persists the chat via chats.save.
  let currentChatId = "";
  let currentMessages = [];
  let cachedSummaries = [];
  let saveTimer = null;
  let saveInFlight = false;
  let saveDirty = false;
  const SAVE_DEBOUNCE_MS = 350;
  const MAX_LIVE_MESSAGES = 200;

  function showWelcome(show) {
    if (welcomeMessage) {
      welcomeMessage.classList.toggle("hidden", !show);
    }
  }

  function clearMessageDom() {
    // Remove every dynamically-added message but keep the welcome card so
    // its prompt-chip handlers stay bound; toggle its visibility separately.
    chatMessages.querySelectorAll(".message").forEach((node) => {
      if (node !== welcomeMessage) {
        node.remove();
      }
    });
  }

  function recordMessage(role, text) {
    currentMessages.push({ role, content: String(text || ""), ts: new Date().toISOString() });
    if (currentMessages.length > MAX_LIVE_MESSAGES) {
      currentMessages = currentMessages.slice(-MAX_LIVE_MESSAGES);
    }
    showWelcome(false);
    scheduleSave();
  }

  function updateLastMessage(text) {
    if (!currentMessages.length) {
      recordMessage("assistant", text);
      return;
    }
    const last = currentMessages[currentMessages.length - 1];
    last.content = String(text || "");
    last.ts = new Date().toISOString();
    scheduleSave();
  }

  function scheduleSave() {
    if (!chatsApi || !currentMessages.length) return;
    if (saveInFlight) {
      saveDirty = true;
      return;
    }
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveTimer = null;
      persistNow().catch(() => {});
    }, SAVE_DEBOUNCE_MS);
  }

  async function persistNow() {
    if (!chatsApi || !currentMessages.length) return;
    if (saveInFlight) {
      // Another save is already on the wire; mark dirty so the in-flight
      // save's finally-block kicks off a follow-up once it returns.
      saveDirty = true;
      return;
    }
    saveInFlight = true;
    saveDirty = false;
    try {
      const payload = {
        id: currentChatId || undefined,
        messages: currentMessages,
      };
      const result = await chatsApi.save(payload);
      if (result && result.ok && result.chat && result.chat.id) {
        currentChatId = result.chat.id;
        await refreshChatList();
      }
    } catch (_) {
      // Persistence failures are non-fatal for the chat UX; the next call
      // will retry. We deliberately don't surface a toast - chat history
      // is a convenience feature, not a security gate.
    } finally {
      saveInFlight = false;
      if (saveDirty) {
        saveDirty = false;
        // Re-arm the debounced save so the latest message state lands.
        scheduleSave();
      }
    }
  }

  function relativeTime(iso) {
    const then = new Date(iso);
    if (Number.isNaN(then.getTime())) return "";
    const diff = Math.max(0, Date.now() - then.getTime());
    const sec = Math.floor(diff / 1000);
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h`;
    const day = Math.floor(hr / 24);
    if (day < 7) return `${day}d`;
    const wk = Math.floor(day / 7);
    if (wk < 5) return `${wk}w`;
    const mo = Math.floor(day / 30);
    if (mo < 12) return `${mo}mo`;
    const yr = Math.floor(day / 365);
    return `${yr}y`;
  }

  function renderChatList() {
    if (!chatList) return;
    chatList.textContent = "";
    if (chatListEmpty) {
      chatListEmpty.style.display = cachedSummaries.length ? "none" : "";
    }
    for (const summary of cachedSummaries) {
      const row = document.createElement("div");
      row.className = "chat-list-item";
      row.dataset.chatId = summary.id;
      if (summary.id === currentChatId) {
        row.classList.add("is-active");
      }

      const main = document.createElement("button");
      main.type = "button";
      main.className = "chat-list-item-main";
      const title = document.createElement("span");
      title.className = "chat-list-item-title";
      title.textContent = summary.title || "New chat";
      const time = document.createElement("span");
      time.className = "chat-list-item-time";
      time.textContent = relativeTime(summary.updated_at);
      main.appendChild(title);
      main.appendChild(time);
      main.addEventListener("click", () => {
        loadChat(summary.id).catch(() => {});
      });

      const renameBtn = document.createElement("button");
      renameBtn.type = "button";
      renameBtn.className = "chat-list-action chat-list-rename";
      renameBtn.setAttribute("aria-label", "Rename chat");
      renameBtn.title = "Rename";
      renameBtn.textContent = "✎"; // pencil glyph
      renameBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        renameChat(summary.id, summary.title).catch(() => {});
      });

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "chat-list-action chat-list-delete";
      deleteBtn.setAttribute("aria-label", "Delete chat");
      deleteBtn.title = "Delete";
      deleteBtn.textContent = "×"; // × glyph
      deleteBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        deleteChat(summary.id).catch(() => {});
      });

      row.appendChild(main);
      row.appendChild(renameBtn);
      row.appendChild(deleteBtn);
      chatList.appendChild(row);
    }
  }

  async function refreshChatList() {
    if (!chatsApi) return;
    try {
      const result = await chatsApi.list();
      cachedSummaries = Array.isArray(result && result.chats) ? result.chats : [];
    } catch {
      cachedSummaries = [];
    }
    renderChatList();
  }

  function renderRestoredMessage(role, text) {
    // Mirrors addMessage's DOM output but does NOT push into currentMessages
    // - used when restoring a saved chat where the state array is already set.
    const article = document.createElement("article");
    article.className = `message ${role === "user" ? "user-message" : "assistant-message"}`;
    const avatar = document.createElement("div");
    avatar.className = role === "user" ? "avatar user-avatar" : "avatar assistant-avatar";
    avatar.textContent = role === "user" ? "You" : "";
    if (role !== "user") {
      avatar.setAttribute("aria-hidden", "true");
    }
    const card = document.createElement("div");
    card.className = "message-card";
    String(text || "")
      .split("\n")
      .filter((line) => line.trim().length)
      .forEach((line) => {
        const p = document.createElement("p");
        p.textContent = line;
        card.appendChild(p);
      });
    article.appendChild(avatar);
    article.appendChild(card);
    chatMessages.appendChild(article);
  }

  async function loadChat(id) {
    if (!chatsApi || !id || id === currentChatId) return;
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = null;
      await persistNow();
    }
    try {
      const result = await chatsApi.get(id);
      if (!result || !result.ok || !result.chat) return;
      currentChatId = result.chat.id;
      currentMessages = Array.isArray(result.chat.messages) ? result.chat.messages.slice() : [];
      clearMessageDom();
      showWelcome(currentMessages.length === 0);
      for (const message of currentMessages) {
        renderRestoredMessage(message.role, message.content);
      }
      scrollChat();
      chatsApi.setActive(id).catch(() => {});
      renderChatList();
    } catch {
      // ignore - the previous chat stays loaded on failure
    }
  }

  async function startNewChat() {
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = null;
      await persistNow();
    }
    currentChatId = "";
    currentMessages = [];
    clearMessageDom();
    showWelcome(true);
    chatInput.value = "";
    setChatInputHeight();
    chatInput.focus();
    if (chatsApi) {
      chatsApi.setActive("").catch(() => {});
    }
    renderChatList();
  }

  async function deleteChat(id) {
    if (!chatsApi || !id) return;
    const target = cachedSummaries.find((s) => s.id === id);
    const label = (target && target.title) || "this chat";
    if (!window.confirm(`Delete "${label}"? This cannot be undone.`)) return;
    try {
      const result = await chatsApi.delete(id);
      if (!result || !result.ok) return;
      cachedSummaries = Array.isArray(result.chats)
        ? result.chats
        : cachedSummaries.filter((s) => s.id !== id);
      if (currentChatId === id) {
        currentChatId = "";
        currentMessages = [];
        if (result.active_chat_id) {
          await loadChat(result.active_chat_id);
        } else {
          await startNewChat();
        }
      } else {
        renderChatList();
      }
    } catch {
      // ignore
    }
  }

  async function renameChat(id, currentTitle) {
    if (!chatsApi || !id) return;
    const next = window.prompt("Rename chat:", currentTitle || "");
    if (next === null) return;
    const title = next.trim();
    if (!title) return;
    try {
      const result = await chatsApi.rename(id, title);
      if (!result || !result.ok) return;
      await refreshChatList();
    } catch {
      // ignore
    }
  }

  async function bootChatHistory() {
    if (!chatsApi) {
      // Older build without the chats IPC: leave the welcome visible and
      // skip persistence. The chat surface still works in-memory.
      return;
    }
    try {
      const result = await chatsApi.list();
      cachedSummaries = Array.isArray(result && result.chats) ? result.chats : [];
      renderChatList();
      const active = result && result.active_chat_id;
      if (active && cachedSummaries.some((s) => s.id === active)) {
        await loadChat(active);
      }
    } catch {
      // Boot-time persistence failures are non-fatal - the user can still
      // chat; the next save attempt will recreate the file.
    }
  }

  const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  function scrollChat() {
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function addMessage(role, text) {
    const article = document.createElement("article");
    article.className = `message ${role === "user" ? "user-message" : "assistant-message"}`;

    const avatar = document.createElement("div");
    avatar.className = role === "user" ? "avatar user-avatar" : "avatar assistant-avatar";
    avatar.textContent = role === "user" ? "You" : "";
    if (role !== "user") {
      avatar.setAttribute("aria-hidden", "true");
    }

    const card = document.createElement("div");
    card.className = "message-card";
    String(text || "")
      .split("\n")
      .filter((line) => line.trim().length)
      .forEach((line) => {
        const paragraph = document.createElement("p");
        paragraph.textContent = line;
        card.appendChild(paragraph);
      });

    article.appendChild(avatar);
    article.appendChild(card);
    chatMessages.appendChild(article);
    scrollChat();
    // Record into the persistence state. scan-progress-chat.js creates
    // its own message articles via direct DOM manipulation and does NOT
    // call addMessage, so live scan progress noise never lands in saved
    // chat history.
    recordMessage(role, text);
    return article;
  }

  function replaceMessage(article, text) {
    const card = article?.querySelector(".message-card");
    if (!card) {
      return addMessage("assistant", text);
    }
    card.textContent = "";
    String(text || "")
      .split("\n")
      .filter((line) => line.trim().length)
      .forEach((line) => {
        const paragraph = document.createElement("p");
        paragraph.textContent = line;
        card.appendChild(paragraph);
      });
    scrollChat();
    updateLastMessage(text);
    return article;
  }

  function clickAction(id) {
    const button = document.getElementById(id);
    if (button && !button.disabled) {
      button.click();
      return true;
    }
    return false;
  }

  function setChatInputHeight() {
    chatInput.style.height = "auto";
    chatInput.style.height = `${Math.min(chatInput.scrollHeight, 150)}px`;
  }

  function normalizedText(value) {
    return String(value || "").toLowerCase();
  }

  const RESISTANCE_GROUPS = [
    {
      key: "credential theft",
      terms: ["credential", "mimikatz", "gpp", "vault", "autologon", "lsass", "password", "minidump", "process_dumping"],
    },
    {
      key: "privilege escalation",
      terms: ["privesc", "alwaysinstallelevated", "elevat", "system", "sensitive_privilege", "windows_privesc"],
    },
    {
      key: "persistence",
      terms: ["persistence", "startup", "security support provider", "ssp", "autostart"],
    },
    {
      key: "PowerShell abuse",
      terms: ["powershell", "encodedcommand", "script_obfuscation", "invoke-expression", "downloadstring"],
    },
    {
      key: "surveillance",
      terms: ["surveillance", "keystroke", "screenshot", "microphone", "screen capture", "audio capture"],
    },
    {
      key: "shadow copy / raw disk",
      terms: ["shadow", "raw_ntfs", "ninjacopy", "volume", "direct volume"],
    },
    {
      key: "recon",
      terms: ["recon", "discovery", "securitypackages", "privescaudit"],
    },
    {
      key: "service/DLL hijack risk",
      terms: ["service", "dll", "hijack", "unquoted", "scheduled_task", "path_hardening"],
    },
  ];

  function resistanceFindingText(finding) {
    return [
      finding.rule_id,
      finding.title,
      finding.category,
      finding.plain_english,
      finding.evidence?.matched_artifact,
      finding.evidence?.matched_behavior,
      finding.evidence?.signature_category,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  }

  function isResistanceFinding(finding) {
    const text = resistanceFindingText(finding);
    return /powersploit|mimikatz|privesc|alwaysinstallelevated|autologon|gpp|lsass|powershell|dll|service|shadow|ninjacopy|credential|surveillance|scheduled_task|path_hardening|defender|credential_guard|script_block/.test(text);
  }

  function highestSeverity(findings) {
    return findings
      .map((finding) => String(finding.severity || "info").toLowerCase())
      .sort((a, b) => (SEVERITY_RANK[b] || 0) - (SEVERITY_RANK[a] || 0))[0] || "info";
  }

  function topFinding(findings) {
    return findings
      .slice()
      .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))[0];
  }

  function summarizeResistanceReport(report, prompt) {
    const findings = Array.isArray(report.findings) ? report.findings.filter(isResistanceFinding) : [];
    const normalized = prompt.toLowerCase();
    let narrowed = findings;
    if (/alwaysinstallelevated|installer/.test(normalized)) {
      narrowed = findings.filter((finding) => resistanceFindingText(finding).includes("alwaysinstallelevated") || resistanceFindingText(finding).includes("installer"));
    } else if (/mimikatz|credential|password|lsass/.test(normalized)) {
      narrowed = findings.filter((finding) => RESISTANCE_GROUPS[0].terms.some((term) => resistanceFindingText(finding).includes(term)));
    } else if (/system|privilege|elevation|harden first/.test(normalized)) {
      narrowed = findings.filter((finding) => resistanceFindingText(finding).match(/privesc|elevat|system|service|dll|scheduled_task|path_hardening|sensitive_privilege/));
    }

    const source = narrowed.length ? narrowed : findings;
    if (!source.length) {
      return [
        "I checked the latest report and did not find PowerSploit resistance or Windows privilege-escalation findings.",
        "If this report was created without the endpoint scan, run a scan first so GreyNOC can review local Windows hardening signals.",
      ].join("\n");
    }

    const lines = [
      `I found ${source.length} relevant PowerSploit resistance finding(s). Highest severity: ${highestSeverity(source)}.`,
    ];
    for (const group of RESISTANCE_GROUPS) {
      const grouped = source.filter((finding) => group.terms.some((term) => resistanceFindingText(finding).includes(term)));
      if (!grouped.length) {
        continue;
      }
      const top = topFinding(grouped);
      const fix = Array.isArray(top.recommended_actions) && top.recommended_actions.length ? top.recommended_actions[0] : "Review and harden this finding first.";
      lines.push(`${group.key}: ${grouped.length}; highest ${highestSeverity(grouped)}; top finding: ${top.title}; recommended fix: ${fix}`);
    }
    return lines.join("\n");
  }

  function isResistancePrompt(normalized) {
    return /powersploit|mimikatz|privilege escalation|privesc|alwaysinstallelevated|system|harden first|resistance check|protect against/.test(normalized);
  }

  async function answerResistanceReport(prompt) {
    const payload = await loadLatestReport();
    if (!payload?.ok) {
      return noReportMessage(payload?.message);
    }
    return summarizeResistanceReport(payload.report || {}, prompt);
  }

  function findingRank(finding) {
    const severity = SEVERITY_RANK[normalizedText(finding.severity)] || 0;
    const score = Number(finding.risk_score || 0);
    const confidence = Number(finding.confidence || 0);
    return severity * 1000 + score * 10 + confidence;
  }

  function sortedFindings(report) {
    return [...(Array.isArray(report?.findings) ? report.findings : [])].sort((a, b) => findingRank(b) - findingRank(a));
  }

  function formatFinding(finding, index = 1) {
    const title = finding.title || finding.rule_id || "Security finding";
    const severity = String(finding.severity || "info").toUpperCase();
    const device = finding.device_name || finding.device_ip || "unknown device";
    const score = Number(finding.risk_score || 0).toFixed(1);
    return `${index}. ${title} - ${severity}, score ${score}, device: ${device}.`;
  }

  function findingActions(finding) {
    const actions = Array.isArray(finding.recommended_actions) ? finding.recommended_actions : [];
    return actions.slice(0, 3).map((action, index) => `   Fix ${index + 1}: ${action}`).join("\n");
  }

  function loadLatestReport() {
    if (!window.homeguard?.latestReport) {
      return Promise.resolve({ ok: false, message: "This build does not expose latest report access yet." });
    }
    return window.homeguard.latestReport();
  }

  function noReportMessage(message) {
    return `${message || "No GreyNOC report is available yet."}\n\nRun a scan first, then ask me what to fix first, explain my latest report, or show risky devices.`;
  }

  async function answerLatestReport() {
    const payload = await loadLatestReport();
    if (!payload?.ok) {
      return noReportMessage(payload?.message);
    }
    const report = payload.report || {};
    const findings = sortedFindings(report);
    const top = findings.slice(0, 3).map(formatFinding).join("\n");
    const nextSteps = Array.isArray(report.next_steps) ? report.next_steps.slice(0, 3) : [];
    return [
      `Latest GreyNOC report: ${report.overall_risk || "unknown"} risk, score ${Number(report.overall_score || 0).toFixed(1)}.`,
      `Devices seen: ${report.device_count || 0}. Findings: ${report.finding_count || findings.length}.`,
      report.summary ? `Summary: ${report.summary}` : "",
      findings.length ? `Top findings:\n${top}` : "No findings were reported in the latest scan.",
      nextSteps.length ? `Recommended next steps:\n${nextSteps.map((step, index) => `${index + 1}. ${step}`).join("\n")}` : "",
    ].filter(Boolean).join("\n\n");
  }

  async function answerFixFirst() {
    const payload = await loadLatestReport();
    if (!payload?.ok) {
      return noReportMessage(payload?.message);
    }
    const report = payload.report || {};
    const findings = sortedFindings(report);
    if (!findings.length) {
      return `The latest report shows no active findings. Overall risk is ${report.overall_risk || "unknown"}. Keep definitions updated and scan again after adding new devices.`;
    }
    const top = findings[0];
    const actions = findingActions(top);
    return [
      "Fix this first:",
      formatFinding(top, 1),
      top.plain_english ? `Why it matters: ${top.plain_english}` : "",
      actions || "Recommended action: Review this finding in the report and remediate the exposed service or device configuration.",
      findings.length > 1 ? `After that, handle these next:\n${findings.slice(1, 4).map(formatFinding).join("\n")}` : "",
    ].filter(Boolean).join("\n\n");
  }

  async function answerRiskyDevices() {
    const payload = await loadLatestReport();
    if (!payload?.ok) {
      return noReportMessage(payload?.message);
    }
    const findings = sortedFindings(payload.report || {});
    if (!findings.length) {
      return "I do not see risky devices in the latest report. Run an active scan if you want GreyNOC to check bounded private-network services more deeply.";
    }
    const byDevice = new Map();
    for (const finding of findings) {
      const key = finding.device_ip || finding.device_name || "unknown device";
      if (!byDevice.has(key)) {
        byDevice.set(key, []);
      }
      byDevice.get(key).push(finding);
    }
    const rows = [...byDevice.entries()].slice(0, 6).map(([device, deviceFindings], index) => {
      const top = deviceFindings[0];
      return `${index + 1}. ${device}: ${deviceFindings.length} finding(s). Highest: ${top.title || top.rule_id || "finding"} (${String(top.severity || "info").toUpperCase()}).`;
    });
    return `Risky devices from the latest report:\n${rows.join("\n")}\n\nAsk me about one of those devices or say "what should I fix first" for the top priority.`;
  }

  async function answerPortOrDevice(prompt) {
    const payload = await loadLatestReport();
    if (!payload?.ok) {
      return noReportMessage(payload?.message);
    }
    const report = payload.report || {};
    const findings = sortedFindings(report);
    const needle = normalizedText(prompt);
    const tokens = needle.match(/[a-z0-9._:-]+/g) || [];
    const matched = findings.filter((finding) => {
      const haystack = normalizedText([
        finding.title,
        finding.rule_id,
        finding.category,
        finding.device_ip,
        finding.device_name,
        finding.plain_english,
        JSON.stringify(finding.evidence || {}),
      ].join(" "));
      return tokens.some((token) => token.length >= 2 && haystack.includes(token));
    });
    const targetFindings = matched.length ? matched : findings.slice(0, 3);
    if (!targetFindings.length) {
      return "I do not see matching findings in the latest report. Try running a scan first, or ask about devices, risky services, or what to fix first.";
    }
    const lines = targetFindings.slice(0, 3).map((finding, index) => [
      formatFinding(finding, index + 1),
      finding.plain_english ? `   Why: ${finding.plain_english}` : "",
      findingActions(finding),
    ].filter(Boolean).join("\n"));
    return `Here is what I found in the latest report:\n${lines.join("\n\n")}`;
  }

  function isScanCommand(normalized) {
    return /\b(run|start|begin)\b.*\b(scan|network check)\b/.test(normalized)
      || /\bscan\b.*\b(network|home|devices|lan)\b/.test(normalized)
      || normalized === "scan";
  }

  // Local fallback used when AI is sterile or the bridge is unavailable.
  // Keeps the chat useful out-of-the-box without requiring a configured key.
  async function localFallbackAnswer(prompt) {
    const normalized = normalizedText(prompt);
    if (isResistancePrompt(normalized)) return answerResistanceReport(prompt);
    if (/fix first|priority|what should i fix|recommend|next step|next steps/.test(normalized)) return answerFixFirst();
    if (/risky devices|suspicious devices|unknown devices|dangerous devices/.test(normalized)) return answerRiskyDevices();
    if (/report|summary|summarize|explain latest|latest scan|risk/.test(normalized)) return answerLatestReport();
    if (/rdp|3389|ssh|22|smb|445|telnet|23|ftp|21|vnc|5900|camera|router|printer|iot|port|open port|device/.test(normalized)) {
      return answerPortOrDevice(prompt);
    }
    return answerLatestReport();
  }

  function aiHistoryFromState() {
    // Send the recent in-memory turns to the AI as conversation context.
    // We exclude the very last user message because respondToPrompt appends
    // it just before calling here, and the LLM expects it as the prompt.
    const recent = currentMessages.slice(-20, -1);
    return recent
      .filter((entry) => entry && (entry.role === "user" || entry.role === "assistant"))
      .map((entry) => ({ role: entry.role, content: String(entry.content || "") }))
      .filter((entry) => entry.content.trim());
  }

  async function respondToPrompt(prompt) {
    const normalized = normalizedText(prompt);

    if (isScanCommand(normalized)) {
      const activeScan = document.getElementById("activeScan");
      addMessage("assistant", `Starting a GreyNOC scan now. ${activeScan?.checked ? "Active checks are enabled, so GreyNOC will use bounded private-network probing." : "Active checks are off, so this will use the gentler scan mode."}`);
      clickAction("scanButton");
      return;
    }

    if (/\b(update|refresh)\b.*\b(definitions|cve|kev|security data)\b/.test(normalized) || normalized === "update definitions") {
      addMessage("assistant", "Updating local CVE and KEV definitions now. I will show the status in the protection panel when it finishes.");
      clickAction("updateButton");
      return;
    }

    if (/\b(history|previous scans|past scans|old scans)\b/.test(normalized)) {
      addMessage("assistant", "Opening scan history. Select a row to open the saved HTML, PDF, or report folder.");
      clickAction("historyButton");
      return;
    }

    if (/\b(show|open|list)\b.*\b(device|devices)\b/.test(normalized)) {
      addMessage("assistant", "Opening the device view. This shows known devices, trust status, labels, and open ports from local scans.");
      clickAction("devicesTab");
      return;
    }

    const thinking = addMessage("assistant", "Thinking...");
    try {
      const aiApi = window.homeguard && window.homeguard.ai;
      if (aiApi && typeof aiApi.chat === "function") {
        const history = aiHistoryFromState();
        const result = await aiApi.chat({ message: prompt, history });
        if (result && result.ok && result.response) {
          if (result.response.sterile) {
            // Sterile mode: keep the chat useful via the local fallback so
            // users without an API key still get answers grounded in the
            // latest report.
            replaceMessage(thinking, await localFallbackAnswer(prompt));
            return;
          }
          replaceMessage(thinking, result.response.text || result.response.error || "(empty response)");
          return;
        }
        const errorText = (result && (result.message || (result.response && result.response.error))) || "";
        if (errorText) {
          replaceMessage(thinking, `AI provider error: ${errorText}\n\nFalling back to the local report summary.`);
        }
      }
      replaceMessage(thinking, await localFallbackAnswer(prompt));
    } catch (error) {
      replaceMessage(thinking, `I could not complete this request. ${error.message || String(error)}`);
    }
  }

  chatForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const prompt = chatInput.value.trim();
    if (!prompt) {
      return;
    }
    addMessage("user", prompt);
    chatInput.value = "";
    setChatInputHeight();
    respondToPrompt(prompt).catch((error) => {
      addMessage("assistant", error?.message || "I could not read the latest report. Run a scan first, then ask again.");
    });
  });

  chatInput.addEventListener("input", setChatInputHeight);
  chatInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      chatForm.requestSubmit();
    }
  });

  document.querySelectorAll(".prompt-chip").forEach((button) => {
    button.addEventListener("click", () => {
      const prompt = button.dataset.prompt || button.textContent || "";
      chatInput.value = prompt;
      chatForm.requestSubmit();
    });
  });

  if (newChatButton) {
    newChatButton.addEventListener("click", () => {
      startNewChat().catch(() => {});
    });
  }

  // Restore the active chat from disk (or start fresh if there isn't one)
  // once the renderer has wired everything else up.
  bootChatHistory().catch(() => {});
})();
