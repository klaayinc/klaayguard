#!/usr/bin/env bash
# End-to-end test of the package repositories (PROD-7007), in containers.
#
# It proves, on real package managers, what a customer machine goes through:
#
#   1. Installing the .deb or .rpm by hand adds Klaay's repository.
#   2. The package manager trusts the repository's signature, and only that.
#   3. Publishing a newer version makes `apt upgrade` / `dnf upgrade` take it.
#   4. A repository index changed after signing is refused.
#   5. Uninstalling removes the repository and its key.
#   6. /etc/klaay/no-repo keeps the machine off the repository.
#   7. A build without the repository files (development, staging) adds nothing.
#
# The packages are stand-ins: a shell script at /usr/bin/KlaayGuard, the
# repository files, and the real linux/postinst.sh and linux/postrm.sh. The real
# app needs a desktop session and a webkit stack the containers lack, and the
# maintainer scripts and the repository are what this test is about. The repo
# files point at a plain-HTTP server inside the test network instead of
# https://pkg.klaay.com; validate-linux-deb.sh checks the shipped ones.
#
# The signing key is a throwaway made for this run. The real key never leaves
# the protected `release` environment.
#
# Needs: docker. Runs as an ordinary user (rootless docker works).
# Usage: test-package-repo.sh [client-image ...]
set -euo pipefail

cd "$(dirname "$0")/.."
SRC_TAURI="$(pwd)"
REPO_ROOT="$(cd .. && pwd)"

CLIENTS=("$@")
if [ "${#CLIENTS[@]}" -eq 0 ]; then
  CLIENTS=(ubuntu:22.04 ubuntu:24.04 debian:12 fedora:42 rockylinux:9)
fi
BUILDER=ubuntu:22.04
RUN_ID="klaay-repo-test-$$"
WORK="$(mktemp -d)"
NET="$RUN_ID-net"
SERVER="$RUN_ID-pkgrepo"

cleanup() {
  if [ -n "${KEEP_WORK:-}" ]; then
    echo "KEEP_WORK set: left $WORK, network $NET and server $SERVER running" >&2
    return
  fi
  docker rm -f "$SERVER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  # Files written by root in a container belong to a subuid under rootless
  # docker; let a container delete them.
  docker run --rm -v "$WORK:/w" "$BUILDER" sh -c 'rm -rf /w/* /w/.[!.]*' >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

failures=0
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }
pass() { echo "  ok: $1"; }

mkdir -p "$WORK/src"
cp -r "$REPO_ROOT/.github/scripts/build-package-repos.sh" "$SRC_TAURI/linux/postinst.sh" \
  "$SRC_TAURI/linux/postrm.sh" "$WORK/src/"

echo "==> build the stand-in packages and two repository snapshots"
docker run --rm -v "$WORK:/w" "$BUILDER" bash -euo pipefail -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq apt-utils createrepo-c rpm gnupg dpkg-dev >/dev/null

  export GNUPGHOME=/w/gnupg
  mkdir -p -m 700 "$GNUPGHOME"
  gpg --batch --quiet --passphrase "" --quick-gen-key "Klaay Packages TEST <test@example.invalid>" rsa4096 sign never
  KEY_ID=$(gpg --batch --with-colons --list-keys | awk -F: "/^fpr:/ {print \$10; exit}")
  gpg --batch --armor --export "$KEY_ID" > /w/klaay.asc
  gpg --batch --export "$KEY_ID" > /w/klaay.gpg
  echo "$KEY_ID" > /w/key-id

  # The repo files the stand-in ships. Same shape as the real ones; only the
  # URL differs.
  mkdir -p /w/repo-files
  cp /w/klaay.asc /w/klaay.gpg /w/repo-files/
  printf "deb [arch=amd64 signed-by=/usr/share/keyrings/klaay.gpg] http://pkgrepo:8080/apt stable main\n" > /w/repo-files/klaay.list
  printf "[klaay]\nname=Klaay TEST\nbaseurl=http://pkgrepo:8080/rpm/\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-klaay\n" > /w/repo-files/klaay.repo

  # with_repo=1 ships the repo files (the production build); 0 does not.
  build_deb() {
    version=$1; with_repo=$2; out=$3
    root=$(mktemp -d)
    mkdir -p "$root/DEBIAN" "$root/usr/bin"
    printf "#!/bin/sh\necho KlaayGuard stand-in %s\n" "$version" > "$root/usr/bin/KlaayGuard"
    chmod 755 "$root/usr/bin/KlaayGuard"
    if [ "$with_repo" = 1 ]; then
      mkdir -p "$root/usr/share/klaay-guard/package-repo"
      cp /w/repo-files/* "$root/usr/share/klaay-guard/package-repo/"
    fi
    printf "Package: klaay-guard\nVersion: %s\nArchitecture: amd64\nMaintainer: Klaay <support@klaay.com>\nDescription: KlaayGuard test stand-in\n" "$version" > "$root/DEBIAN/control"
    install -m 755 /w/src/postinst.sh "$root/DEBIAN/postinst"
    install -m 755 /w/src/postrm.sh "$root/DEBIAN/postrm"
    dpkg-deb --root-owner-group --build "$root" "$out" >/dev/null
  }
  build_rpm() {
    version=$1; with_repo=$2; outdir=$3
    top=$(mktemp -d)
    mkdir -p "$top"/{SPECS,BUILD,RPMS,SOURCES,BUILDROOT}
    {
      echo "Name: klaay-guard"
      echo "Version: $version"
      echo "Release: 1"
      echo "Summary: KlaayGuard test stand-in"
      echo "License: GPL-3.0"
      echo "BuildArch: x86_64"
      echo "%description"
      echo "stand-in"
      echo "%install"
      echo "mkdir -p %{buildroot}/usr/bin"
      echo "printf \"#!/bin/sh\\necho KlaayGuard stand-in $version\\n\" > %{buildroot}/usr/bin/KlaayGuard"
      echo "chmod 755 %{buildroot}/usr/bin/KlaayGuard"
      if [ "$with_repo" = 1 ]; then
        echo "mkdir -p %{buildroot}/usr/share/klaay-guard/package-repo"
        echo "cp /w/repo-files/* %{buildroot}/usr/share/klaay-guard/package-repo/"
      fi
      echo "%files"
      echo "/usr/bin/KlaayGuard"
      [ "$with_repo" = 1 ] && echo "/usr/share/klaay-guard"
      echo "%post"
      cat /w/src/postinst.sh
      echo "%postun"
      cat /w/src/postrm.sh
    } > "$top/SPECS/k.spec"
    rpmbuild --quiet --define "_topdir $top" --define "debug_package %{nil}" -bb "$top/SPECS/k.spec" >/dev/null 2>&1 \
      || rpmbuild --define "_topdir $top" --define "debug_package %{nil}" -bb "$top/SPECS/k.spec"
    cp "$top"/RPMS/x86_64/*.rpm "$outdir/"
  }

  mkdir -p /w/v1 /w/v2 /w/norepo /w/local
  build_deb 0.0.1 1 /w/v1/klaay-guard_0.0.1_amd64.deb
  build_rpm 0.0.1 1 /w/v1
  cp /w/v1/* /w/v2/
  build_deb 0.0.2 1 /w/v2/klaay-guard_0.0.2_amd64.deb
  build_rpm 0.0.2 1 /w/v2
  build_deb 0.0.3 0 /w/norepo/klaay-guard_0.0.3_amd64.deb
  build_rpm 0.0.3 0 /w/norepo
  cp /w/v1/* /w/local/

  export PACKAGE_SIGNING_KEY_ID=$KEY_ID PACKAGE_REPO_PUBLIC_KEY=/w/klaay.asc
  bash /w/src/build-package-repos.sh /w/site-v1 /w/v1
  bash /w/src/build-package-repos.sh /w/site-v2 /w/v2

  # A copy of v2 whose apt index changed after signing, and one whose rpm
  # metadata did. Both must be refused.
  cp -a /w/site-v2 /w/site-tampered
  printf "Package: klaay-guard\nVersion: 9.9.9\nArchitecture: amd64\nFilename: pool/evil.deb\nSize: 1\nSHA256: 00\n\n" >> /w/site-tampered/apt/dists/stable/main/binary-amd64/Packages
  gzip -9nf -k /w/site-tampered/apt/dists/stable/main/binary-amd64/Packages
  echo "<!-- tampered -->" >> /w/site-tampered/rpm/repodata/repomd.xml

  # A copy of v2 whose indexes are re-signed by a different key: what someone
  # who can write to the host, but does not hold Klaay'"'"'s key, could serve.
  gpg --batch --quiet --passphrase "" --quick-gen-key "Not Klaay <other@example.invalid>" rsa3072 sign never
  OTHER=$(gpg --batch --with-colons --list-keys "other@example.invalid" | awk -F: "/^fpr:/ {print \$10; exit}")
  cp -a /w/site-v2 /w/site-otherkey
  d=/w/site-otherkey/apt/dists/stable
  gpg --batch --yes --local-user "$OTHER" --clearsign -o "$d/InRelease" "$d/Release"
  gpg --batch --yes --local-user "$OTHER" --armor --detach-sign -o "$d/Release.gpg" "$d/Release"
  r=/w/site-otherkey/rpm/repodata
  gpg --batch --yes --local-user "$OTHER" --armor --detach-sign -o "$r/repomd.xml.asc" "$r/repomd.xml"

  # The snapshots are built within a second of each other, and apt asks the
  # server "modified since?" by timestamp. Give each its own time, in the order
  # the clients see them (v1, tampered, other key, v2), so every switch reads
  # as new content. (GitHub Pages changes the file on every deploy, so
  # production never hits this.)
  find /w/site-v1 -exec touch -d "4 hours ago" {} +
  find /w/site-tampered -exec touch -d "3 hours ago" {} +
  find /w/site-otherkey -exec touch -d "2 hours ago" {} +
  find /w/site-v2 -exec touch -d "1 hour ago" {} +

  mkdir -p /w/serve
  ln -sfn /w/site-v1 /w/serve/current
  chmod -R a+rX /w
'

publish() { # point the server at a snapshot and wait until it serves it
  docker run --rm -v "$WORK:/w" "$BUILDER" ln -sfn "/w/$1" /w/serve/current
  docker restart "$SERVER" >/dev/null
  for _ in $(seq 1 50); do
    docker exec "$SERVER" wget -q -O /dev/null http://127.0.0.1:8080/klaay.asc 2>/dev/null && return 0
    sleep 0.2
  done
  echo "repository server did not come back" >&2
  exit 1
}

echo "==> start the repository server"
docker network create "$NET" >/dev/null
docker run -d --name "$SERVER" --network "$NET" --network-alias pkgrepo -v "$WORK:/w:ro" \
  python:3.12-alpine python -m http.server 8080 --directory /w/serve/current >/dev/null
sleep 2

# Each client runs one script; it prints "ok: …" / "FAIL: …" lines. The server
# snapshot changes between steps, so each step is its own container run against
# a container that persists for the whole client.
for image in "${CLIENTS[@]}"; do
  echo "==> client $image"
  publish site-v1
  name="$RUN_ID-client"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "$NET" -v "$WORK:/w:ro" "$image" sleep infinity >/dev/null

  case "$image" in
    ubuntu* | debian*) family=apt ;;
    *) family=rpm ;;
  esac

  ex() { docker exec "$name" sh -c "$1"; }
  check() { # description, command
    if ex "$2" >/tmp/"$RUN_ID".out 2>&1; then pass "$image: $1"; else fail "$image: $1"; sed 's/^/      /' /tmp/"$RUN_ID".out >&2; fi
  }

  if [ "$family" = apt ]; then
    ex 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && apt-get install -y -qq ca-certificates >/dev/null'
    check "manual install of 0.0.1 adds the repository" \
      'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /w/local/klaay-guard_0.0.1_amd64.deb >/dev/null && test -f /etc/apt/sources.list.d/klaay.list && test -f /usr/share/keyrings/klaay.gpg'
    check "key is scoped with signed-by, not in a global keyring" \
      'grep -q "signed-by=/usr/share/keyrings/klaay.gpg" /etc/apt/sources.list.d/klaay.list && ! ls /etc/apt/trusted.gpg.d/ 2>/dev/null | grep -qi klaay'
    check "apt update trusts the repository" \
      'apt-get update -o APT::Update::Error-Mode=any >/tmp/u 2>&1; rc=$?; cat /tmp/u; [ $rc -eq 0 ] && ! grep -qE "^(W|E):" /tmp/u && apt-cache policy klaay-guard | grep -q pkgrepo'
    # The tampered snapshot is v2 with an extra entry appended to the index
    # after signing. apt must refuse the whole index and keep 0.0.1, even
    # though the snapshot also offers a genuine 0.0.2.
    publish site-tampered
    check "a changed index is refused and nothing upgrades" \
      '! apt-get update -o APT::Update::Error-Mode=any >/tmp/u 2>&1; cat /tmp/u; grep -qiE "hash sum mismatch|unexpected size|mirror sync" /tmp/u && apt-cache policy klaay-guard | grep -q "Candidate: 0.0.1"'
    publish site-otherkey
    check "an index signed by another key is refused and nothing upgrades" \
      '! apt-get update -o APT::Update::Error-Mode=any >/tmp/u 2>&1; cat /tmp/u; grep -qiE "NO_PUBKEY|not signed|signatures (couldn.t be verified|were invalid)" /tmp/u && apt-cache policy klaay-guard | grep -q "Candidate: 0.0.1"'
    publish site-v2
    check "apt upgrade takes 0.0.2 from the repository" \
      'apt-get update -qq -o APT::Update::Error-Mode=any && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade klaay-guard >/dev/null && [ "$(dpkg-query -W -f="\${Version}" klaay-guard)" = 0.0.2 ]'
    check "uninstall removes the repository and key" \
      'DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq klaay-guard >/dev/null && ! test -e /etc/apt/sources.list.d/klaay.list && ! test -e /usr/share/keyrings/klaay.gpg'
    check "/etc/klaay/no-repo keeps the machine off the repository" \
      'mkdir -p /etc/klaay && touch /etc/klaay/no-repo && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /w/local/klaay-guard_0.0.1_amd64.deb >/dev/null && ! test -e /etc/apt/sources.list.d/klaay.list && rm /etc/klaay/no-repo && DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq klaay-guard >/dev/null'
    check "a build without repository files removes an earlier registration" \
      'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /w/local/klaay-guard_0.0.1_amd64.deb >/dev/null && test -e /etc/apt/sources.list.d/klaay.list && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /w/norepo/klaay-guard_0.0.3_amd64.deb >/dev/null && ! test -e /etc/apt/sources.list.d/klaay.list && ! test -e /usr/share/keyrings/klaay.gpg'
  else
    pm=dnf
    check "manual install of 0.0.1 adds the repository" \
      "$pm install -y -q /w/local/klaay-guard-0.0.1-1.x86_64.rpm >/dev/null && test -f /etc/yum.repos.d/klaay.repo && test -f /etc/pki/rpm-gpg/RPM-GPG-KEY-klaay"
    check "dnf trusts the repository (gpgcheck + repo_gpgcheck)" \
      "$pm -y -q --disablerepo='*' --enablerepo=klaay makecache"
    # dnf skips a repository whose repomd.xml signature fails (Fedora and RHEL
    # default skip_if_unavailable=1) instead of failing every dnf command on the
    # machine. What matters is that it installs nothing from it.
    publish site-tampered
    check "changed repository metadata is refused and nothing upgrades" \
      "$pm -y --refresh upgrade klaay-guard >/tmp/u 2>&1; cat /tmp/u; grep -qiE 'signature' /tmp/u && [ \"\$(rpm -q --qf %{VERSION} klaay-guard)\" = 0.0.1 ]"
    publish site-otherkey
    check "metadata signed by another key is refused and nothing upgrades" \
      "$pm -y --refresh upgrade klaay-guard >/tmp/u 2>&1; cat /tmp/u; grep -qiE 'signature|key' /tmp/u && [ \"\$(rpm -q --qf %{VERSION} klaay-guard)\" = 0.0.1 ]"
    publish site-v2
    check "dnf upgrade takes 0.0.2 from the repository" \
      "$pm -y -q --disablerepo='*' --enablerepo=klaay --refresh upgrade klaay-guard >/dev/null && [ \"\$(rpm -q --qf %{VERSION} klaay-guard)\" = 0.0.2 ]"
    check "uninstall removes the repository and key" \
      "$pm remove -y -q klaay-guard >/dev/null && ! test -e /etc/yum.repos.d/klaay.repo && ! test -e /etc/pki/rpm-gpg/RPM-GPG-KEY-klaay"
    check "/etc/klaay/no-repo keeps the machine off the repository" \
      "mkdir -p /etc/klaay && touch /etc/klaay/no-repo && $pm install -y -q /w/local/klaay-guard-0.0.1-1.x86_64.rpm >/dev/null && ! test -e /etc/yum.repos.d/klaay.repo && rm /etc/klaay/no-repo && $pm remove -y -q klaay-guard >/dev/null"
    check "a build without repository files removes an earlier registration" \
      "$pm install -y -q /w/local/klaay-guard-0.0.1-1.x86_64.rpm >/dev/null && test -e /etc/yum.repos.d/klaay.repo && $pm install -y -q /w/norepo/klaay-guard-0.0.3-1.x86_64.rpm >/dev/null && ! test -e /etc/yum.repos.d/klaay.repo && ! test -e /etc/pki/rpm-gpg/RPM-GPG-KEY-klaay"
  fi
  docker rm -f "$name" >/dev/null
done
rm -f /tmp/"$RUN_ID".out

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
