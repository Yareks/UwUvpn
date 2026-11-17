#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# UwUvpn / VeloxVPN — one-command GitHub release publisher.
#
#   GITHUB_TOKEN=<pat> scripts/publish-release.sh 1.7.1 /path/to/VeloxVPN.apk "Заголовок релиза" [/path/notes.md]
#
# What it does (all steps are idempotent-ish and verified):
#   1. Sanitizes + syncs the working tree into a throw-away clone (never commits
#      keystores, *.so, build outputs, local.properties or any secret).
#   2. Refuses to continue if a token / keystore password shows up in the staged tree.
#   3. Commits & pushes `main`.
#   4. Creates the GitHub release for tag `v<version>` (or reuses it) and uploads
#      the APK + SHA256SUMS.txt.
#   5. Downloads the published APK again and byte-compares it with the local file.
#
# The token is only ever passed through an HTTP header for the duration of this
# process; it is never written to disk, never staged and never embedded in the APK.
# ---------------------------------------------------------------------------
set -euo pipefail

VERSION="${1:?usage: publish-release.sh <version> <apk> [title] [notes.md]}"
APK="${2:?missing apk path}"
TITLE="${3:-VeloxVPN ${VERSION}}"
NOTES_FILE="${4:-}"

REPO_OWNER="Yareks"
REPO_NAME="UwUvpn"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${GITHUB_TOKEN:?Set GITHUB_TOKEN (temporary PAT with repo scope)}"
[ -f "$APK" ] || { echo "APK not found: $APK" >&2; exit 1; }

API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

say "1/6 Syncing sanitized tree"
git clone --quiet "https://github.com/${REPO_OWNER}/${REPO_NAME}" "$WORK/repo"
(
  cd "$ROOT_DIR"
  tar -cf - \
    --exclude='./.git' --exclude='./android/keystore' --exclude='*.jks' --exclude='*.keystore' \
    --exclude='./target' --exclude='./rust-engine/target' --exclude='./build' \
    --exclude='./android/build' --exclude='./android/app/build' --exclude='./android/.gradle' \
    --exclude='./third_party' --exclude='./android/local.properties' --exclude='*.so' \
    --exclude='./.secrets' . | (cd "$WORK/repo" && tar -xf -)
)
chmod +x "$WORK/repo"/scripts/*.sh
cd "$WORK/repo"

say "2/6 Secret scan"
SCAN_RE='ghp_[A-Za-z0-9]{30,}|github_pat_|VeloxVpn2026|BEGIN [A-Z ]*PRIVATE KEY'
if grep -rInE "$SCAN_RE" . --exclude-dir=.git --exclude='publish-release.sh' >/dev/null 2>&1; then
  echo "!! secret-looking string found in staged tree — aborting" >&2
  grep -rInE "$SCAN_RE" . --exclude-dir=.git --exclude='publish-release.sh' | head -5 >&2
  exit 1
fi
echo "clean"

say "3/6 Commit & push main"
git add -A
if git diff --cached --quiet; then
  echo "no source changes to commit"
else
  git -c user.name="$REPO_OWNER" \
      -c user.email="${REPO_OWNER}@users.noreply.github.com" \
      commit -q -m "Release v${VERSION}: ${TITLE}"
fi
HEADER="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 -w0)"
git -c http.https://github.com/.extraheader="$HEADER" push -q origin main
echo "pushed $(git log --oneline -1)"

say "4/6 Release v${VERSION}"
NOTES_JSON="[]"
if [ -n "$NOTES_FILE" ] && [ -f "$NOTES_FILE" ]; then
  NOTES_JSON="$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1],encoding="utf-8").read()))' "$NOTES_FILE")"
fi
BODY="$(python3 - "$VERSION" "$TITLE" "$NOTES_JSON" <<'PY'
import json, sys
version, title, notes = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
print(json.dumps({
    "tag_name": f"v{version}",
    "target_commitish": "main",
    "name": title,
    "body": notes or f"VeloxVPN {version}",
    "draft": False,
    "prerelease": False,
}, ensure_ascii=False))
PY
)"
RELEASE_ID="$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" -H 'Accept: application/vnd.github+json' \
  "${API}/releases/tags/v${VERSION}" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)"
if [ -n "$RELEASE_ID" ]; then
  echo "release already exists (id $RELEASE_ID) — updating notes"
  curl -s -X PATCH -H "Authorization: Bearer $GITHUB_TOKEN" -H 'Accept: application/vnd.github+json' \
    -H 'Content-Type: application/json' --data-binary "$BODY" "${API}/releases/${RELEASE_ID}" >/dev/null
else
  RELEASE_ID="$(printf '%s' "$BODY" | curl -s -X POST \
    -H "Authorization: Bearer $GITHUB_TOKEN" -H 'Accept: application/vnd.github+json' \
    -H 'Content-Type: application/json' --data-binary @- "${API}/releases" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("id") or "")')"
fi
[ -n "$RELEASE_ID" ] || { echo "failed to create release" >&2; exit 1; }
echo "release id: $RELEASE_ID"

say "5/6 Upload assets"
ASSET="VeloxVPN-v${VERSION}.apk"
cp "$APK" "$WORK/$ASSET"
( cd "$WORK" && sha256sum "$ASSET" > SHA256SUMS.txt )
for f in "$ASSET" SHA256SUMS.txt; do
  EXISTING="$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "${API}/releases/${RELEASE_ID}/assets" \
    | python3 -c 'import json,sys,urllib.parse;name=sys.argv[1];print(next((a["id"] for a in json.load(sys.stdin) if a["name"]==name),""))' "$f")"
  [ -n "$EXISTING" ] && curl -s -X DELETE -H "Authorization: Bearer $GITHUB_TOKEN" "${API}/releases/assets/${EXISTING}" >/dev/null
  CT="application/octet-stream"; case "$f" in *.txt) CT="text/plain";; esac
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $GITHUB_TOKEN" -H "Content-Type: ${CT}" \
    --data-binary "@$WORK/$f" \
    "https://uploads.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/${RELEASE_ID}/assets?name=$f")"
  echo "  $f -> HTTP $CODE"
  [ "$CODE" = "201" ] || { echo "upload failed for $f" >&2; exit 1; }
done

say "6/6 Verify public download"
URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/v${VERSION}/${ASSET}"
curl -sL --retry 3 -o "$WORK/download.apk" "$URL"
LOCAL_SUM="$(sha256sum "$APK" | cut -d' ' -f1)"
REMOTE_SUM="$(sha256sum "$WORK/download.apk" | cut -d' ' -f1)"
echo "local : $LOCAL_SUM"
echo "remote: $REMOTE_SUM"
[ "$LOCAL_SUM" = "$REMOTE_SUM" ] || { echo "!! published APK differs from local build" >&2; exit 1; }
echo "byte-identical: OK"

echo
echo "Release published: https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/tag/v${VERSION}"
