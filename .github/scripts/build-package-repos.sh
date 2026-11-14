#!/usr/bin/env bash
# Build the signed apt and rpm repositories served at https://pkg.klaay.com.
#
# Usage: build-package-repos.sh <out-dir> <package-dir>
#
#   <package-dir> holds the production .deb and .rpm files to publish. The
#   release workflow fills it with the newest few published releases; a local
#   test fills it with whatever it built.
#   <out-dir> receives the site: klaay.asc, klaay.gpg, apt/ and rpm/.
#
# The signing key must already be in the default GnuPG home ($GNUPGHOME), and
# PACKAGE_SIGNING_KEY_ID must name it. The script never sees a passphrase: the
# key has none, and the only place it lives besides 1Password is the protected
# `release` environment.
#
# Why each repository is shaped the way it is:
#
# * apt: one suite, `stable`, one component, `main`, amd64 only. The packages sit
#   under pool/ and the index lists them by that relative path, so the site can
#   move hosts without rebuilding. Release carries no Valid-Until: a repository
#   that goes a few weeks without a release must not start failing `apt update`
#   on customer machines.
# * rpm: every package is signed (`rpm --addsign`) and so is repomd.xml, which
#   is what `gpgcheck=1` and `repo_gpgcheck=1` check. The .rpm in the GitHub
#   release stays unsigned; the repository serves the signed copy.
#
# The script checks its own output before returning: apt's signatures verify,
# the rpm signatures verify, and every package it was given is listed. A
# repository that fails any of those must not be deployed.
set -euo pipefail

OUT="${1:?usage: build-package-repos.sh <out-dir> <package-dir>}"
PKGS="${2:?usage: build-package-repos.sh <out-dir> <package-dir>}"
KEY_ID="${PACKAGE_SIGNING_KEY_ID:?PACKAGE_SIGNING_KEY_ID must name the signing key}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# The public key the packages ship. A test points this at its throwaway key.
PUBLIC_KEY="${PACKAGE_REPO_PUBLIC_KEY:-$HERE/../../src-tauri/linux/package-repo/klaay.asc}"

for tool in apt-ftparchive createrepo_c rpmsign rpm gpg dpkg-deb; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

# The key that signs must be the key the packages ship. A mismatch would build a
# repository every customer machine rejects.
signing_fpr=$(gpg --batch --with-colons --fingerprint "$KEY_ID" | awk -F: '/^fpr:/ {print $10; exit}')
shipped_fpr=$(gpg --batch --with-colons --show-keys "$PUBLIC_KEY" | awk -F: '/^fpr:/ {print $10; exit}')
if [ -z "$signing_fpr" ] || [ "$signing_fpr" != "$shipped_fpr" ]; then
  echo "signing key ${signing_fpr:-<none>} is not the key in $PUBLIC_KEY (${shipped_fpr:-<none>})" >&2
  exit 1
fi

shopt -s nullglob
debs=("$PKGS"/*.deb)
rpms=("$PKGS"/*.rpm)
shopt -u nullglob
[ "${#debs[@]}" -gt 0 ] || { echo "no .deb in $PKGS" >&2; exit 1; }
[ "${#rpms[@]}" -gt 0 ] || { echo "no .rpm in $PKGS" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT"

# Public key, in both forms: armoured for people and for rpm, binary for apt's
# signed-by. The packages ship their own copy; these are for anyone setting the
# repository up by hand.
cp "$PUBLIC_KEY" "$OUT/klaay.asc"
gpg --batch --yes --dearmor -o "$OUT/klaay.gpg" "$PUBLIC_KEY"

# --- apt ---------------------------------------------------------------------
APT="$OUT/apt"
POOL="pool/main/k/klaay-guard"
mkdir -p "$APT/$POOL" "$APT/dists/stable/main/binary-amd64"
for deb in "${debs[@]}"; do
  name=$(dpkg-deb -f "$deb" Package)
  [ "$name" = "klaay-guard" ] || { echo "$deb is package '$name', not klaay-guard" >&2; exit 1; }
  version=$(dpkg-deb -f "$deb" Version)
  arch=$(dpkg-deb -f "$deb" Architecture)
  cp "$deb" "$APT/$POOL/${name}_${version}_${arch}.deb"
done

(
  cd "$APT"
  apt-ftparchive packages "$POOL" > dists/stable/main/binary-amd64/Packages
  gzip -9nk dists/stable/main/binary-amd64/Packages
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin="Klaay" \
    -o APT::FTPArchive::Release::Label="KlaayGuard" \
    -o APT::FTPArchive::Release::Suite="stable" \
    -o APT::FTPArchive::Release::Codename="stable" \
    -o APT::FTPArchive::Release::Architectures="amd64" \
    -o APT::FTPArchive::Release::Components="main" \
    -o APT::FTPArchive::Release::Description="KlaayGuard security agent" \
    release dists/stable > dists/stable/Release
  gpg --batch --yes --local-user "$KEY_ID" --digest-algo SHA512 \
    --clearsign -o dists/stable/InRelease dists/stable/Release
  gpg --batch --yes --local-user "$KEY_ID" --digest-algo SHA512 \
    --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
)

# --- rpm ---------------------------------------------------------------------
RPMDIR="$OUT/rpm"
mkdir -p "$RPMDIR"
for rpmfile in "${rpms[@]}"; do
  name=$(rpm -qp --qf '%{NAME}' "$rpmfile" 2>/dev/null)
  [ "$name" = "klaay-guard" ] || { echo "$rpmfile is package '$name', not klaay-guard" >&2; exit 1; }
  cp "$rpmfile" "$RPMDIR/$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' "$rpmfile" 2>/dev/null)"
done
# Name gpg explicitly: Ubuntu's rpm looks for gpg2, which Ubuntu does not ship.
rpmsign --define "__gpg $(command -v gpg)" --define "_gpg_name $KEY_ID" \
  --define "_gpg_digest_algo sha512" --addsign "$RPMDIR"/*.rpm >/dev/null
createrepo_c --quiet "$RPMDIR"
gpg --batch --yes --local-user "$KEY_ID" --armor --detach-sign \
  -o "$RPMDIR/repodata/repomd.xml.asc" "$RPMDIR/repodata/repomd.xml"

# --- landing page --------------------------------------------------------------
cat > "$OUT/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Klaay packages</title>
<p>Package repositories for the KlaayGuard agent. The .deb and .rpm from
<a href="https://app.klaay.com/employee-hub">app.klaay.com</a> set these up on install.</p>
<ul>
<li><a href="klaay.asc">Signing key</a></li>
<li>apt: <code>deb [arch=amd64 signed-by=/usr/share/keyrings/klaay.gpg] https://pkg.klaay.com/apt stable main</code></li>
<li>rpm: <code>https://pkg.klaay.com/rpm/</code></li>
</ul>
HTML

# --- self-check ----------------------------------------------------------------
verify_home=$(mktemp -d)
trap 'rm -rf "$verify_home"' EXIT
gpg --batch --quiet --homedir "$verify_home" --import "$PUBLIC_KEY" 2>/dev/null
gpg --batch --quiet --homedir "$verify_home" --verify "$APT/dists/stable/InRelease" 2>/dev/null \
  || { echo "InRelease does not verify against the shipped key" >&2; exit 1; }
gpg --batch --quiet --homedir "$verify_home" --verify "$APT/dists/stable/Release.gpg" "$APT/dists/stable/Release" 2>/dev/null \
  || { echo "Release.gpg does not verify against the shipped key" >&2; exit 1; }
gpg --batch --quiet --homedir "$verify_home" --verify "$RPMDIR/repodata/repomd.xml.asc" "$RPMDIR/repodata/repomd.xml" 2>/dev/null \
  || { echo "repomd.xml.asc does not verify against the shipped key" >&2; exit 1; }

listed=$(grep -c '^Package: klaay-guard$' "$APT/dists/stable/main/binary-amd64/Packages")
[ "$listed" -eq "${#debs[@]}" ] || { echo "apt index lists $listed packages, expected ${#debs[@]}" >&2; exit 1; }

rpmdb=$(mktemp -d)
rpm --dbpath "$rpmdb" --initdb
rpm --dbpath "$rpmdb" --import "$PUBLIC_KEY"
for rpmfile in "$RPMDIR"/*.rpm; do
  rpm --dbpath "$rpmdb" -K "$rpmfile" | grep -qiE 'signatures? ok|pgp.*ok|digests signatures OK' \
    || { echo "$rpmfile: rpm signature does not verify" >&2; rpm --dbpath "$rpmdb" -Kv "$rpmfile" >&2; rm -rf "$rpmdb"; exit 1; }
done
rm -rf "$rpmdb"

echo "built $OUT: ${#debs[@]} deb, ${#rpms[@]} rpm, signed by $signing_fpr"
