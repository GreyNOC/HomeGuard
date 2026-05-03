[app]
title = GreyNOC HomeGuard
package.name = greynochomeguard
package.domain = com.greynoc.homeguard
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json
version = 0.5.0
requirements = python3,kivy
orientation = portrait
fullscreen = 0

# Android permissions appropriate for a network awareness app on a mobile
# device. Note: ARP table access is restricted on modern Android; the mobile
# build relies on socket fallbacks.
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_MULTICAST_STATE
android.api = 34
android.minapi = 24
android.archs = arm64-v8a, armeabi-v7a

# (Optional) icon and presplash. Drop assets into this folder if available.
# icon.filename = icon.png
# presplash.filename = presplash.png

# Signing placeholders. Real release builds require keystore configuration.
# android.release_artifact = aab
# p4a.bootstrap = sdl2

[buildozer]
log_level = 2
warn_on_root = 1
