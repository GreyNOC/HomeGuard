# Security and responsible use

HomeGuard is intended for local networks that you own or are authorized to assess.

Allowed use examples:

- Check your home WiFi for unknown devices.
- Identify risky services exposed inside your LAN.
- Export a report before calling your ISP or an IT professional.
- Teach basic home cybersecurity concepts.

Not supported:

- Scanning networks you do not own or administer.
- Exploitation, password guessing, credential harvesting, stealth, persistence, or evasion.
- Internet-wide scanning.

Default safety choices:

- Passive discovery is the default.
- Active probing requires `--active` or explicit port options.
- Active targets are limited to private, loopback, link-local, or directly configured local CIDRs.
- Timeouts, host counts, and worker counts are bounded.
- Reports use careful wording: "may indicate" and "recommended next steps" instead of overclaiming compromise.

Report suspected vulnerabilities privately before public disclosure.
