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

  function respondToPrompt(prompt) {
    const normalized = prompt.toLowerCase();

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
      addMessage("assistant", "I can help explain the latest HomeGuard report once a scan has produced one. Use Run Scan first if there is no report yet, then ask me what to fix first. The next phase will connect this chat directly to report JSON so answers can reference exact findings.");
      return;
    }

    if (/rdp|3389|ssh|22|camera|router|printer|iot|port|open port/.test(normalized)) {
      addMessage("assistant", "Good security question. HomeGuard should answer this from scan evidence: device, open port, trust state, severity, and suggested fix. For now, run a scan and review Devices or Latest Report. The upcoming command router will turn questions like this into finding-specific explanations.");
      return;
    }

    addMessage("assistant", "I can help with local HomeGuard actions right now: run a scan, update definitions, open devices, open history, or explain what the next assistant router should do. Try asking: Run a local network scan, Show risky devices, or Explain my latest report.");
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
