(() => {
  const chatMessages = document.getElementById("chatMessages");
  const chatForm = document.getElementById("chatForm");
  const chatInput = document.getElementById("chatInput");
  const newChatButton = document.getElementById("newChatButton");

  if (!chatMessages || !chatForm || !chatInput) {
    return;
  }

  const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  function scrollChat() {
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function addMessage(role, text) {
    const article = document.createElement("article");
    article.className = `message ${role === "user" ? "user-message" : "assistant-message"}`;

    const avatar = document.createElement("div");
    avatar.className = "avatar";
    avatar.textContent = role === "user" ? "You" : "HG";

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
    return `${index}. ${title} — ${severity}, score ${score}, device: ${device}.`;
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
    return `${message || "No HomeGuard report is available yet."}\n\nRun a scan first, then ask me what to fix first, explain my latest report, or show risky devices.`;
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
      `Latest HomeGuard report: ${report.overall_risk || "unknown"} risk, score ${Number(report.overall_score || 0).toFixed(1)}.`,
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
      return "I do not see risky devices in the latest report. Run an active scan if you want HomeGuard to check bounded private-network services more deeply.";
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

  async function respondToPrompt(prompt) {
    const normalized = normalizedText(prompt);

    if (isScanCommand(normalized)) {
      const activeScan = document.getElementById("activeScan");
      addMessage("assistant", `Starting a HomeGuard scan now. ${activeScan?.checked ? "Active checks are enabled, so HomeGuard will use bounded private-network probing." : "Active checks are off, so this will use the gentler scan mode."}`);
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

    const thinking = addMessage("assistant", "Checking the latest HomeGuard report...");
    try {
      let answer;
      if (/fix first|priority|what should i fix|recommend|next step|next steps/.test(normalized)) {
        answer = await answerFixFirst();
      } else if (/risky devices|suspicious devices|unknown devices|dangerous devices/.test(normalized)) {
        answer = await answerRiskyDevices();
      } else if (/report|summary|summarize|explain latest|latest scan|risk/.test(normalized)) {
        answer = await answerLatestReport();
      } else if (/rdp|3389|ssh|22|smb|445|telnet|23|ftp|21|vnc|5900|camera|router|printer|iot|port|open port|device/.test(normalized)) {
        answer = await answerPortOrDevice(prompt);
      } else {
        answer = await answerLatestReport();
      }
      replaceMessage(thinking, answer);
    } catch (error) {
      replaceMessage(thinking, `I could not read the latest report safely. ${error.message || String(error)}`);
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
    respondToPrompt(prompt);
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
      chatMessages.querySelectorAll(".message:not(:first-child)").forEach((message) => message.remove());
      chatInput.value = "";
      setChatInputHeight();
      chatInput.focus();
    });
  }
})();
