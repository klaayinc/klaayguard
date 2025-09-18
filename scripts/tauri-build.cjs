#!/usr/bin/env node
const { spawnSync } = require('node:child_process')

const hasKey = !!process.env.TAURI_SIGNING_PRIVATE_KEY
const args = ['build']

if (!hasKey) {
  // Merge override to disable updater artifacts locally
  args.push('--config', 'src-tauri/tauri.no-updater.json')
}

const result = spawnSync('tauri', args, { stdio: 'inherit' })
process.exit(result.status || 0)
