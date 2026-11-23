# Package signing key

The key that signs Klaay's apt and rpm repositories at `https://pkg.klaay.com`
(PROD-7007). Every Linux machine with KlaayGuard installed from a `.deb` or
`.rpm` trusts it to deliver code that runs as root, so treat it like the Apple
and Azure code-signing credentials.

| | |
|---|---|
| Fingerprint | `13D8 0297 A1F6 85A7 F895  2CF6 5FD4 764C DBDF 659E` |
| Created / expires | 2026-11-14 / never |
| User ID | `Klaay Packages <support@klaay.com>` |
| Algorithm | RSA 4096. Ed25519 would be smaller, but RHEL 8's rpm cannot verify it. |
| Expiry | None, on purpose. dnf and rpm import the key once and never re-import a key ID they already hold, so a later package shipping an extended key would not reach them: at the original expiry every rpm machine would silently stop updating. Revocation, not expiry, is how this key ends (below). |
| Passphrase | None. CI signs unattended. The protection is where the key lives. |
| Private key | One 1Password item, "KlaayGuard package signing key" in the Klaay account's Development vault, and the `PACKAGE_SIGNING_KEY` secret of the `release` environment in `klaayinc/klaayguard`. Nowhere else. |
| Revocation certificate | Same 1Password item. |
| Public key in the repo | `src-tauri/linux/package-repo/klaay.asc` (armoured) and `klaay.gpg` (binary, for apt's `signed-by`). |

## Create it (once)

On a trusted machine, in a throwaway GnuPG home that is deleted afterwards:

```sh
export GNUPGHOME="$(mktemp -d)"
gpg --batch --passphrase '' --quick-gen-key 'Klaay Packages <support@klaay.com>' rsa4096 sign never
FPR=$(gpg --batch --with-colons --list-keys | awk -F: '/^fpr:/ {print $10; exit}')

gpg --armor --export "$FPR"             > src-tauri/linux/package-repo/klaay.asc
gpg --export "$FPR"                     > src-tauri/linux/package-repo/klaay.gpg
gpg --armor --export-secret-keys "$FPR" > klaay-packages-private.asc   # → 1Password, then delete
cp "$GNUPGHOME/openpgp-revocs.d/$FPR.rev" klaay-packages-revoke.asc    # → 1Password, then delete
echo "$FPR"                                                            # → 1Password item + PR description

rm -rf "$GNUPGHOME"
```

Then:

1. Put `klaay-packages-private.asc`, `klaay-packages-revoke.asc` and the
   fingerprint in the 1Password item, and delete both files.
2. Create the GitHub environment `release` in `klaayinc/klaayguard`
   (Settings → Environments): required reviewer, deployment branches limited
   to `main`, and the secret `PACKAGE_SIGNING_KEY` holding the armoured private
   key.
3. Commit `klaay.asc` and `klaay.gpg`.

## If the key leaks

Machines trust only the key their installed package shipped, so the move to a
new key has to arrive signed by the old one. That leaves one release in which
both Klaay and whoever holds the leaked key can sign; keep it short.

1. Create a new key as above. Commit its public files and release. Publish that
   release once with the **old** key in `PACKAGE_SIGNING_KEY`, so machines
   accept it and install the package that carries the new key.
2. Put the new private key in `PACKAGE_SIGNING_KEY` and run
   `publish-package-repos` again, so the site is now signed by the new key.
3. Publish the revocation certificate for the old key and delete it from
   1Password.

Machines that were off during step 1 can no longer read the repository after
step 2. They need the current package installed once by hand, like any install
from before the repository existed.
