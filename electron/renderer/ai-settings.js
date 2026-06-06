(() => {
  const ai = window.homeguard && window.homeguard.ai;
  if (!ai) return;

  const providerSelect = document.getElementById("aiProvider");
  const modelInput = document.getElementById("aiModel");
  const apiKeyEnvInput = document.getElementById("aiApiKeyEnv");
  const apiKeyStatus = document.getElementById("aiApiKeyStatus");
  const endpointInput = document.getElementById("aiEndpoint");
  const shareLevelSelect = document.getElementById("aiShareLevel");
  const useToolsCheckbox = document.getElementById("aiUseEngineTools");
  const useMemoryCheckbox = document.getElementById("aiUseMemoryContext");
  const useTrafficCheckbox = document.getElementById("aiUseTrafficContext");
  const form = document.getElementById("aiSettingsForm");
  const sterileButton = document.getElementById("aiSterileButton");
  const testButton = document.getElementById("aiTestButton");
  const formStatus = document.getElementById("aiFormStatus");

  const memorySummary = document.getElementById("aiMemorySummary");
  const memoryForm = document.getElementById("aiMemoryAddForm");
  const memoryNote = document.getElementById("aiMemoryNote");
  const memoryRefresh = document.getElementById("aiMemoryRefresh");
  const memoryClear = document.getElementById("aiMemoryClear");
  const memoryStatus = document.getElementById("aiMemoryStatus");

  const trafficRefresh = document.getElementById("aiTrafficRefresh");
  const trafficOutput = document.getElementById("aiTrafficOutput");

  if (!form || !providerSelect) return;

  function setStatus(target, text, tone = "") {
    if (!target) return;
    target.textContent = text || "";
    target.dataset.tone = tone || "";
  }

  function applySettings(settings) {
    if (!settings) return;
    providerSelect.value = String(settings.provider || "sterile");
    modelInput.value = String(settings.model || "");
    apiKeyEnvInput.value = String(settings.api_key_env || "");
    endpointInput.value = String(settings.endpoint || "");
    shareLevelSelect.value = String(settings.share_level || "minimal");
    useToolsCheckbox.checked = settings.use_engine_tools !== false;
    useMemoryCheckbox.checked = settings.use_memory_context !== false;
    useTrafficCheckbox.checked = settings.use_traffic_context === true;
    const sterile = settings.sterile === true || providerSelect.value === "sterile";
    if (sterile) {
      setStatus(apiKeyStatus, "Sterile mode is active — no AI provider calls are made.");
    } else if (!apiKeyEnvInput.value) {
      setStatus(apiKeyStatus, "Set an environment variable name and load the key in your shell.", "warn");
    } else if (settings.api_key_present) {
      setStatus(
        apiKeyStatus,
        `Environment variable ${apiKeyEnvInput.value} is set in this HomeGuard process.`,
        "ok",
      );
    } else {
      setStatus(
        apiKeyStatus,
        `Environment variable ${apiKeyEnvInput.value} is NOT set in this HomeGuard process. Set it and restart HomeGuard.`,
        "warn",
      );
    }
  }

  async function loadStatus() {
    setStatus(formStatus, "Loading current AI settings...");
    const result = await ai.status();
    if (result && result.ok) {
      applySettings(result.settings || {});
      setStatus(formStatus, "");
    } else {
      setStatus(formStatus, (result && result.message) || "Could not load AI settings.", "warn");
    }
  }

  function readForm() {
    return {
      provider: providerSelect.value,
      model: modelInput.value.trim(),
      api_key_env: apiKeyEnvInput.value.trim(),
      endpoint: endpointInput.value.trim(),
      share_level: shareLevelSelect.value,
      use_engine_tools: useToolsCheckbox.checked,
      use_memory_context: useMemoryCheckbox.checked,
      use_traffic_context: useTrafficCheckbox.checked,
    };
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setStatus(formStatus, "Saving...");
    const payload = readForm();
    if (payload.provider === "sterile") {
      const result = await ai.sterile();
      if (result && result.ok) {
        applySettings(result.settings || { provider: "sterile", sterile: true });
        setStatus(formStatus, "HomeGuard is back in sterile mode.", "ok");
      } else {
        setStatus(formStatus, (result && result.message) || "Could not switch to sterile.", "warn");
      }
      return;
    }
    if (!payload.api_key_env) {
      setStatus(formStatus, "Set the environment variable that holds your API key.", "warn");
      return;
    }
    const result = await ai.configure(payload);
    if (result && result.ok) {
      applySettings(result.settings || payload);
      setStatus(formStatus, "Saved. Remember to set the env var in your shell before AI chat.", "ok");
    } else {
      setStatus(formStatus, (result && result.message) || "Save failed.", "warn");
    }
  });

  sterileButton.addEventListener("click", async () => {
    setStatus(formStatus, "Switching to sterile mode...");
    const result = await ai.sterile();
    if (result && result.ok) {
      applySettings(result.settings || { provider: "sterile", sterile: true });
      setStatus(formStatus, "Sterile mode active.", "ok");
    } else {
      setStatus(formStatus, (result && result.message) || "Could not switch to sterile.", "warn");
    }
  });

  testButton.addEventListener("click", async () => {
    setStatus(formStatus, "Sending a one-shot ping to the configured provider...");
    const result = await ai.chat({
      message: "Reply with the single word OK so HomeGuard knows the connection works.",
      history: [],
      include_traffic: false,
    });
    if (result && result.ok && result.response) {
      if (result.response.sterile) {
        setStatus(formStatus, "Sterile mode is active — no provider call was made.");
      } else if (result.response.text) {
        setStatus(formStatus, `Provider responded: ${result.response.text.slice(0, 200)}`, "ok");
      } else {
        setStatus(formStatus, "Provider responded but with no text.", "warn");
      }
    } else {
      setStatus(formStatus, (result && (result.message || (result.response && result.response.error))) || "Test failed.", "warn");
    }
  });

  function renderMemory(memory) {
    if (!memorySummary) return;
    memorySummary.textContent = "";
    if (!memory) {
      memorySummary.textContent = "No memory yet.";
      return;
    }
    const notes = Array.isArray(memory.notes) ? memory.notes : [];
    const facts = Array.isArray(memory.device_facts) ? memory.device_facts : [];
    const history = Array.isArray(memory.signal_history) ? memory.signal_history : [];

    function section(title, items, renderItem) {
      const wrapper = document.createElement("div");
      wrapper.className = "ai-memory-section";
      const heading = document.createElement("h4");
      heading.textContent = title;
      wrapper.appendChild(heading);
      if (!items.length) {
        const empty = document.createElement("p");
        empty.className = "meta";
        empty.textContent = "Empty.";
        wrapper.appendChild(empty);
      } else {
        const list = document.createElement("ul");
        for (const item of items) {
          const li = document.createElement("li");
          renderItem(li, item);
          list.appendChild(li);
        }
        wrapper.appendChild(list);
      }
      memorySummary.appendChild(wrapper);
    }

    section("Notes", notes, (li, note) => {
      li.textContent = String((note && note.text) || "");
    });
    section("Device facts", facts, (li, fact) => {
      const parts = [];
      if (fact.label) parts.push(fact.label);
      if (fact.trust) parts.push(`trust=${fact.trust}`);
      if (fact.owner) parts.push(`owner=${fact.owner}`);
      if (fact.notes) parts.push(fact.notes);
      li.textContent = parts.length ? parts.join(" — ") : String(fact.fingerprint || "device");
    });
    section("Recent scan trend", history, (li, snap) => {
      const date = snap.created_at ? new Date(snap.created_at * 1000).toLocaleString() : "";
      li.textContent = `${date}: risk=${snap.overall_risk || "?"} score=${Number(snap.overall_score || 0).toFixed(1)} findings=${snap.finding_count || 0}`;
    });
  }

  async function refreshMemory() {
    setStatus(memoryStatus, "Loading memory...");
    const result = await ai.memoryShow();
    if (result && result.ok) {
      renderMemory(result.memory || {});
      setStatus(memoryStatus, "");
    } else {
      setStatus(memoryStatus, (result && result.message) || "Could not load memory.", "warn");
    }
  }

  if (memoryForm) {
    memoryForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const text = memoryNote.value.trim();
      if (!text) return;
      setStatus(memoryStatus, "Saving...");
      const result = await ai.memoryAdd({ text });
      if (result && result.ok) {
        memoryNote.value = "";
        setStatus(memoryStatus, "Saved.", "ok");
        refreshMemory();
      } else {
        setStatus(memoryStatus, (result && result.message) || "Save failed.", "warn");
      }
    });
  }

  if (memoryRefresh) memoryRefresh.addEventListener("click", refreshMemory);
  if (memoryClear) {
    memoryClear.addEventListener("click", async () => {
      if (!window.confirm("Erase all AI memory? This cannot be undone.")) return;
      setStatus(memoryStatus, "Clearing...");
      const result = await ai.memoryClear();
      if (result && result.ok) {
        setStatus(memoryStatus, "Memory cleared.", "ok");
        refreshMemory();
      } else {
        setStatus(memoryStatus, (result && result.message) || "Clear failed.", "warn");
      }
    });
  }

  async function refreshTraffic() {
    if (!trafficOutput) return;
    trafficOutput.textContent = "Loading...";
    const result = await ai.traffic();
    if (result && result.ok) {
      trafficOutput.textContent = JSON.stringify(result.traffic || {}, null, 2);
    } else {
      trafficOutput.textContent = (result && result.message) || "Could not collect traffic.";
    }
  }

  if (trafficRefresh) trafficRefresh.addEventListener("click", refreshTraffic);

  // Refresh data when the AI tab becomes active. The renderer's tab handler
  // toggles a class on the page element, so we observe that to know when to
  // reload — keeps the dashboard idle when the user isn't on this page.
  const aiPage = document.getElementById("aiPage");
  if (aiPage) {
    const observer = new MutationObserver(() => {
      if (aiPage.classList.contains("active-page")) {
        loadStatus();
        refreshMemory();
      }
    });
    observer.observe(aiPage, { attributes: true, attributeFilter: ["class"] });
  }

  loadStatus();
})();
