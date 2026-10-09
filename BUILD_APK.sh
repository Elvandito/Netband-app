#!/usr/bin/env bash
set -euo pipefail
command -v flutter >/dev/null || { echo 'ERROR: Flutter SDK not found in PATH.' >&2; exit 127; }
flutter doctor
flutter pub get
flutter analyze
flutter build apk --release
printf '\nAPK: %s\n' "$PWD/build/app/outputs/flutter-apk/app-release.apk"
