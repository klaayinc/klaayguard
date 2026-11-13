# Fleet readiness: can the release drop the macOS .dmg?

The `.dmg` can leave the release only when every active macOS agent runs the
updater that installs from the `.pkg`. Old updaters read only a `.dmg`. This
page says how to count them.

Let `V` be the first release that holds the `.pkg` updater. It is the version
the release workflow publishes after the updater PR merges.

## Data source

Kiln stores the agent version on the `devices` table:

- `agent_version` (string). The agent sends `app_version` in each report, and
  `Klaayguard::CollectDeviceDataJob#record_agent_report` writes it.
- `agent_last_seen_at` (datetime). The same job sets it on each report.
- `source` is `klaayguard` for a device that an agent reports.

Agents older than v0.1.26 send no version. Their `agent_version` is `NULL`.

## Rules

- Run the query on a local restore only: `composefork exec web bin/rails db:restore_production`.
  Never run a command on a production dyno.
- Write down counts only. Never copy a row, a serial number, a name or an
  account into a message, a PR or a commit.

## Active macOS agent

A device is an active macOS agent when all of these hold:

- `source = 'klaayguard'`
- `agent_last_seen_at` is within the last 7 days. This matches the `has_klaayguard` rule in kiln.
- The device is a Mac. Use the device type or operating system field that the
  report fills. If no such field is set, count by the report items.

## Counts to take

Run each count in `bin/rails runner` in the local stack.

1. **Active agents.** Count the active devices above. This is the total `N`.
2. **At or above V.** Count active devices with `agent_version` at or above `V`.
   Compare with `Gem::Version`, never as strings, because `0.1.9` sorts after `0.1.71` as text.
3. **Below V with a version.** `N` minus group 2 minus group 4. These agents
   self-update through the `.dmg`. They need the `.dmg` until they update.
4. **No version.** Count active devices with `agent_version IS NULL`. These run
   v0.1.25 or older.

```ruby
active = Device.where(source: :klaayguard).where(agent_last_seen_at: 7.days.ago..)
v = Gem::Version.new("V")
versions = active.where.not(agent_version: nil).pluck(:agent_version).map { Gem::Version.new(it) }
puts({ active: active.count,
       at_or_above_v: versions.count { it >= v },
       below_v: versions.count { it < v },
       no_version: active.where(agent_version: nil).count })
```

Skip the Mac filter in this snippet only if the table holds no Windows or Linux
agents. Otherwise add the filter first, or the counts mix platforms.

## The two groups that need a manual .pkg install

- **No version (older than v0.1.26).** These agents do not report a version, so
  kiln cannot tell their updater from a broken one. Install the `.pkg` by hand.
- **Broken self-update.** An agent can report a version below `V` for weeks
  while its updater fails. Find them: the version has not moved across two
  releases while `agent_last_seen_at` stays fresh. Compare two restores a week
  apart, or compare the version with the latest release date. Install the
  `.pkg` by hand.

## Ready rule

The `.dmg` can leave the release when both hold:

- Group 3 (below `V`, with a version) is zero, or each remaining agent has a named owner and a manual `.pkg` install date.
- Group 4 (no version) is zero, or each remaining agent has the same.

Record the counts and the restore date in the step-5 PR (the PR that removes the `.dmg`).
