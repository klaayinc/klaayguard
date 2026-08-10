# Contributing to KlaayGuard

Thank you for your interest in KlaayGuard. This guide explains how to build the
agent, how to send a change, and the standards a change must meet.

## License and the CLA

KlaayGuard is licensed under GPL-3.0-or-later. When you open your first pull
request, the CLA Assistant bot asks you to sign the
[Contributor License Agreement](CLA.md). Sign it once. The bot records your
agreement against your GitHub account and marks later pull requests as covered.

The CLA lets Klaay distribute your change under the project license and keep the
option of a commercial license of the combined work. You keep the copyright to
your contribution.

## Ways to contribute

- Report a bug. Open an issue with the bug report template.
- Request a feature. Open an issue with the feature request template.
- Send a fix or a feature. Open a pull request.
- Improve the documentation. The same pull request flow applies.

For a large change, open an issue first and agree on the approach. This saves
you from a rewrite after review.

## Build from source

You need Rust, the Tauri CLI, and Ruby with rake. The README lists the full
prerequisites and build commands. In short:

```bash
# Install Rust, then the Tauri CLI
cargo install tauri-cli --version "^2"

# Fetch and checksum-verify the osquery sidecars
rake

# Build the agent
cargo tauri build
```

`rake` downloads the osquery binary for your platform and checks its SHA-256
before the build uses it. The build fails if the checksum does not match.

To point the agent at your own server, set the environment variables the README
documents (`VITE_API_BASE_URL`, `VITE_EARTHENWARE_URL`, `KLAAY_ENV`). You do not
need Klaay credentials to build or run the agent against your own backend.

## Before you open a pull request

Run the same checks that CI runs. All must pass:

```bash
cd src-tauri
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

CI also runs `cargo audit` and `cargo deny check licenses`. The license gate
fails if a new dependency uses a license that is not compatible with
GPL-3.0-or-later. If your change adds a dependency, confirm its license is on the
allow-list in `src-tauri/deny.toml`.

Add a `// SPDX-License-Identifier: GPL-3.0-or-later` header to every new
first-party Rust source file.

## Pull request standards

- Keep each commit small, logical, and able to be reverted on its own.
- Write a clear commit message. State what the commit does and why.
- Add tests for a fix or a feature. A bug fix needs a test that fails before the
  fix and passes after it.
- Keep the pull request focused. Do not mix unrelated changes.

## Writing standard for prose

All prose in this repository — documentation, code comments, commit messages,
and pull request text — follows ASD-STE100 (Simplified Technical English) and
George Orwell's six rules of writing.

ASD-STE100:

- Use only approved words. One word, one meaning. Technical names and technical
  verbs of this domain are permitted.
- Write in the active voice. Use the present tense where possible.
- Keep sentences short. Use a maximum of 20 words in an instruction and 25 words
  in descriptive text.
- Give one instruction per sentence. Start an instruction with the command form
  of the verb.
- Do not make noun clusters of more than three nouns.
- Do not use slang, idioms, or Latin abbreviations.
- Use a vertical list when you give more than three facts or steps in sequence.
- Start a warning or a caution with the command, not the explanation.

Orwell's six rules:

1. Never use a metaphor, simile, or other figure of speech which you are used to
   seeing in print.
2. Never use a long word where a short one will do.
3. If it is possible to cut a word out, always cut it out.
4. Never use the passive where you can use the active.
5. Never use a foreign phrase, a scientific word, or a jargon word if you can
   think of an everyday English equivalent.
6. Break any of these rules sooner than say anything outright barbarous.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By taking
part, you agree to uphold it. Report unacceptable behavior to security@klaay.com.

## Security

Do not report a security problem in a public issue. Follow the private process in
[SECURITY.md](SECURITY.md).
