---
paths:
  - 'src-tauri/macos/scripts/**'
  - 'src-tauri/scripts/**'
---

# Installer scripts

Read this before you source or run `postinstall` or `preinstall`.

`src-tauri/macos/scripts/postinstall` and `preinstall` run their `main` only when `$0` has the
script's own name. The last lines are `case "${0##*/}" in postinstall) main ;; esac`. A test
sources the file to call one function, and `$0` then names the test.

- In bash, `$0` stays `bash` when you source a file. The guard holds, and `main` does not run.
- In zsh, `$0` becomes the name of the sourced file. The guard fires, and `main` runs against the
  real machine. For `postinstall` this stops the installed agent and starts the install.
- Both scripts start with `#!/bin/bash`. The `src-tauri/scripts/test-*.sh` files run under bash and are safe.

To call one function of an installer script, use a bash subshell:

```bash
bash -c '. src-tauri/macos/scripts/postinstall; stop_running_agent'
```

Never write `. script` in an interactive or tool shell that may be zsh.

## Review rules

- Flag a test or a doc that sources `postinstall` or `preinstall` outside a `bash` invocation.
- Flag a change that removes or weakens the `case "${0##*/}"` guard at the end of either script.
