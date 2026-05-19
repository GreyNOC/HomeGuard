(() => {
  const chatMessages = document.getElementById("chatMessages");
  const chatForm = document.getElementById("chatForm");
  const chatInput = document.getElementById("chatInput");
  const newChatButton = document.getElementById("newChatButton");

  if (!chatMessages || !chatForm || !chatInput) {
    return;
  }

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

  const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  const resistanceGroups = [
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

  function findingText(finding) {
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
    const text = findingText(finding);
    return /powersploit|mimikatz|privesc|alwaysinstallelevated|autologon|gpp|lsass|powershell|dll|service|shadow|ninjacopy|credential|surveillance|scheduled_task|path_hardening|defender|credential_guard|script_block/.test(text);
  }

  function highestSeverity(findings) {
    return findings
      .map((finding) => String(finding.severity || "info").toLowerCase())
      .sort((a, b) => (severityRank[b] || 0) - (severityRank[a] || 0))[0] || "info";
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
      narrowed = findings.filter((finding) => findingText(finding).includes("alwaysinstallelevated") || findingText(finding).includes("installer"));
    } else if (/mimikatz|credential|password|lsass/.test(normalized)) {
      narrowed = findings.filter((finding) => resistanceGroups[0].terms.some((term) => findingText(finding).includes(term)));
    } else if (/system|privilege|elevation|harden first/.test(normalized)) {
      narrowed = findings.filter((finding) => findingText(finding).match(/privesc|elevat|system|service|dll|scheduled_task|path_hardening|sensitive_privilege/));
    }

    const source = narrowed.length ? narrowed : findings;
    if (!source.length) {
      return [
        "I checked the latest report and did not find PowerSploit resistance or Windows privilege-escalation findings.",
        "If this report was created without the endpoint scan, run a scan first so HomeGuard can review local Windows hardening signals.",
      ].join("\n");
    }

    const lines = [
      `I found ${source.length} relevant PowerSploit resistance finding(s). Highest severity: ${highestSeverity(source)}.`,
    ];
    for (const group of resistanceGroups) {
      const grouped = source.filter((finding) => group.terms.some((term) => findingText(finding).includes(term)));
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

  function summarizeGeneralReport(report) {
    const findings = Array.isArray(report.findings) ? report.findings.slice() : [];
    if (!findings.length) {
      return `The latest report is ${report.overall_risk || "clean"} with no findings. Run another scan after changes or if something on the network changes.`;
    }
    const sorted = findings.sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
    const lines = [
      `Latest report: ${findings.length} finding(s), overall risk ${report.overall_risk || "unknown"}, score ${report.overall_score ?? 0}.`,
    ];
    sorted.slice(0, 3).forEach((finding, index) => {
      const fix = Array.isArray(finding.recommended_actions) && finding.recommended_actions.length ? finding.recommended_actions[0] : "Review this finding first.";
      lines.push(`${index + 1}. ${finding.title} (${finding.severity || "info"}): ${fix}`);
    });
    return lines.join("\n");
  }

  async function answerFromLatestReport(prompt) {
    if (!window.homeguard?.latestReport) {
      addMessage("assistant", "Run a scan first so I can answer from the latest HomeGuard report.");
      return;
    }
    const result = await window.homeguard.latestReport();
    if (!result?.ok || !result.report) {
      addMessage("assistant", result?.message || "Run a scan first so I can answer from the latest HomeGuard report.");
      return;
    }
    const normalized = prompt.toLowerCase();
    addMessage("assistant", isResistancePrompt(normalized) ? summarizeResistanceReport(result.report, prompt) : summarizeGeneralReport(result.report));
  }

  async function respondToPrompt(prompt) {
    const normalized = prompt.toLowerCase();

    if (isResistancePrompt(normalized)) {
      await answerFromLatestReport(prompt);
      return;
    }

    if (/run|start|scan|check my network|local network/.test(normalized)) {
      const activeScan = document.getElementById("activeScan");
      addMessage("assistant", `Starting a HomeGuard scan now. ${activeScan?.checked ? "Active checks are enabled, so HomeGuard will use bounded private-network probing." : "Active checks are off, so this will use the gentler scan mode."}`);
      clickAction("scanButton");
      return;
    }

    if (/update|definitions|cve|kev/.test(normalized)) {
      addMessage("assistant", "Updating local CVE and KEV definitions now. I will show the status in the protection panel when it finishes.");
      clickAction("updateButton");
      return;
    }

    if (/history|previous|past scan|old scan/.test(normalized)) {
      addMessage("assistant", "Opening scan history. Select a row to open the saved HTML, PDF, or report folder.");
      clickAction("historyButton");
      return;
    }

    if (/device|devices|risky devices|unknown|trusted|quarantine/.test(normalized)) {
      addMessage("assistant", "Opening the device view. This shows known devices, trust status, labels, and open ports from local scans.");
      clickAction("devicesTab");
      return;
    }

    if (/report|explain|fix first|priority|recommend|what should i fix/.test(normalized)) {
      await answerFromLatestReport(prompt);
      return;
    }

    if (/rdp|3389|ssh|22|camera|router|printer|iot|port|open port/.test(normalized)) {
      addMessage("assistant", "Run a scan first, then open the latest report or ask what to fix first. I can summarize report findings by device, risk, and recommended action.");
      return;
    }

    addMessage("assistant", "I can help with local HomeGuard actions: run a scan, update definitions, open devices, open history, or explain the latest report.");
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
      chatMessages.querySelectorAll(".message:not(:first-child)").forEach((message) => message.remove());
      chatInput.value = "";
      setChatInputHeight();
      chatInput.focus();
    });
  }
})();
