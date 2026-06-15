"use strict";

// Privacy/path scrubbing helpers for the HomeGuard Electron main process.
//
// These were extracted verbatim from electron/main.js to keep the main process
// from doing everything in one file. They are pure functions with no dependency
// on Electron or app state, so moving them here is a behavior-preserving change.
// They mirror the Python redaction in src/greynoc_homeguard/privacy.py: strip
// local user paths, environment assignments, private keys, secret assignments,
// and mask MAC addresses before any value reaches the UI, logs, or the AI bridge.

function maskIdentifier(value) {
  const text = String(value ?? "");
  const match = text.match(/\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/i);
  if (!match) {
    return text;
  }
  const parts = match[0].toLowerCase().split(":");
  return `device id ending ${parts.at(-2)}:${parts.at(-1)}`;
}

function scrubText(value) {
  return String(value ?? "")
    .replace(/[A-Za-z]:\\Users\\[^\\\r\n\t"'<>]+(?:\\[^\\\r\n\t"'<>]*)*/gi, "local app data")
    .replace(/[^ \r\n\t"'<>]*AppData[^ \r\n\t"'<>]*/gi, "local app data")
    .replace(/\/Users\/[^/\s"'<>]+(?:\/[^/\s"'<>]+)*/gi, "local app data")
    .replace(/\b(HOME|USERNAME|USERPROFILE|LOCALAPPDATA|APPDATA)=\S+/gi, "redacted")
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gi, "redacted")
    .replace(/\b(token|api[_-]?key|password|secret|credential)s?\b\s*[:=]\s*[^\s,;]+/gi, "redacted")
    .replace(/\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi, (value) => maskIdentifier(value));
}

function scrubObject(value) {
  if (Array.isArray(value)) {
    return value.map((item) => scrubObject(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, scrubObject(item)]));
  }
  return typeof value === "string" ? scrubText(value) : value;
}

module.exports = { scrubText, maskIdentifier, scrubObject };
