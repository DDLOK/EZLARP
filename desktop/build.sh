#!/bin/sh
# Builds the Windows app into public/download/ (served by the site) with its sha256.
# Needs Go 1.22+; python3 + Pillow only if you change the icon or version (winres.py).
set -e
cd "$(dirname "$0")"
VERSION=$(sed -n 's/^\tVersion = "\(.*\)"/\1/p' main.go)
[ -f rsrc_windows_amd64.syso ] || python3 winres.py ../public/icons/icon-512.png "$VERSION"
mkdir -p ../public/download
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-H windowsgui -s -w -buildid=" -o ../public/download/EZLARP-Setup.exe .
SUM=$(sha256sum ../public/download/EZLARP-Setup.exe | cut -d' ' -f1)
SIZE=$(stat -c%s ../public/download/EZLARP-Setup.exe)
printf '{"version":"%s","sha256":"%s","size":%s}\n' "$VERSION" "$SUM" "$SIZE" > ../public/download/version.json
cat ../public/download/version.json
