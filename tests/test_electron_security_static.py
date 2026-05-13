from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "electron" / "main.js"
PRELOAD = ROOT / "electron" / "preload.js"
SECURE_MAIN = ROOT / "electron" / "main.secure.js"
PACKAGE = ROOT / "package.json"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_packaged_electron_uses_secure_entrypoint():
    package = _text(PACKAGE)
    secure_main = _text(SECURE_MAIN)
    assert '"main": "electron/main.secure.js"' in package
    assert "delete process.env[key]" in secure_main
    assert "HOMEGUARD_CORE_EXE" in secure_main
    assert "HOMEGUARD_PYTHON" in secure_main
    assert '"PYTHON"' in secure_main
    assert "HOMEGUARD_DEV_MODE" in secure_main
    assert 'require("./main.js")' in secure_main


def test_preload_exposes_expected_ipc_surface_only_through_context_bridge():
    preload = _text(PRELOAD)
    assert "contextBridge.exposeInMainWorld" in preload
    assert "require(\"electron\")" in preload
    assert "ipcRenderer.invoke" in preload
    assert "homeguard" in preload


def test_open_path_and_show_item_are_allowlisted():
    main = _text(MAIN)
    assert "OPENABLE_REPORT_EXTENSIONS" in main
    assert "isAllowedOpenPath" in main
    assert "isAllowedReportOrLogPath" in main
    assert "homeguard:open-path" in main
    assert "homeguard:show-item" in main
    assert "shell.openPath" in main
    assert "shell.showItemInFolder" in main


def test_save_html_as_requires_report_or_log_source():
    main = _text(MAIN)
    assert "homeguard:save-html-as" in main
    assert "isAllowedReportOrLogPath" in main
    assert "showSaveDialog" in main
    assert ".html" in main


def test_device_trust_and_label_ipc_validate_values():
    main = _text(MAIN)
    assert "homeguard:device-trust" in main
    assert "trusted" in main
    assert "unknown" in main
    assert "quarantined" in main
    assert "Invalid trust value" in main
    assert "homeguard:device-label" in main
    assert "owners = new Set" in main
    assert "types = new Set" in main
    assert "cleanString" in main


def test_malformed_payloads_are_normalized_before_use():
    main = _text(MAIN)
    assert "isPlainObject" in main
    assert "options = isPlainObject(options) ? options : {}" in main
    assert "label = isPlainObject(label) ? label : {}" in main
    assert "schedule = isPlainObject(schedule) ? schedule : {}" in main
    assert "clampInteger" in main
