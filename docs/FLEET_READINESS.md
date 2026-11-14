# Fleet readiness: can the release drop the macOS .dmg?

The `.dmg` can leave the release only when every active macOS agent runs the
updater that installs from the `.pkg`. Old updaters read only a `.dmg`. This
page says how to check.

Let `V` be the first release that holds the `.pkg` updater. It is the version
the release workflow publishes after the updater PR merges. The first such
release is v0.1.70.

## Where to look

Open the kiln back office page `/admin/fleet_readiness`. The menu name is
"KlaayGuard Fleet". Enter `V` in the target version field and press Check.
The page reads the `devices` table live. It needs no database restore.

The page shows:

- A verdict. "Ready" or "Not ready: N agents need a manual .pkg install".
- A count per platform (Mac, Windows, Linux, Unknown): active agents, agents at
  or above `V`, agents below `V`, and agents with no version.
- A list of every active agent below `V` or with no version, with its account,
  operating system, agent version and last seen time.

An agent is active when `source` is `klaayguard` and `agent_last_seen_at` is
within the last 7 days. This matches the `has_klaayguard` rule in kiln. The page
compares versions with `Gem::Version`, never as strings.

An agent that has not reported its operating system shows in the Unknown row.
It could be a Mac, so it counts against readiness until it reports.

## Rules

- Use the page. Never run a command on a production dyno.
- Write down counts only. Never copy a row, a serial number, a device name or an
  account into a message, a PR or a commit.

## The two groups that need a manual .pkg install

- **No version (older than v0.1.26).** These agents do not report a version, so
  kiln cannot tell their updater from a broken one. The page shows them in the
  "No version" column. Install the `.pkg` by hand.
- **Broken self-update.** An agent can report a version below `V` for weeks
  while its updater fails. The page shows only the state now, so it cannot show
  this alone. Open the page on two dates a week apart. An agent that stays below
  `V` while its last seen time stays fresh has a broken updater. Install the
  `.pkg` by hand.

## Ready rule

The `.dmg` can leave the release when both hold:

- The Mac and Unknown rows show zero agents below `V` with a version, or each
  remaining agent has a named owner and a manual `.pkg` install date.
- The Mac and Unknown rows show zero agents with no version, or each remaining
  agent has the same.

Windows and Linux agents do not block the `.dmg`. Their counts show for
information.

Record the counts and the date you checked in the step-5 PR (the PR that removes
the `.dmg`).

## Limit

The `devices` table holds no installer type. The page cannot tell a `.dmg`
install from a `.pkg` install. The agent version is the only proxy.
