"""Vendored multi-vector discovery engine.

Source: GreyNOC/saturn (packages/noc-core/src/noc_core/) at the time of
HomeGuard 1.1.0. Kept as a private subpackage so HomeGuard does not need
a release dependency on the saturn repo and so the upstream module's own
__init__.py — which imports shared.contracts — is not loaded.

Imports inside these files were rewritten from `noc_core.X` to relative
`.X` so the modules resolve against this package. No other source edits.
"""
