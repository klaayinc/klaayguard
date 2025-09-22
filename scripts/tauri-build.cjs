#!/usr/bin/env node
const { spawnSync } = require('node:child_process')
const path = require('node:path')
const fs = require('node:fs')

// KLAAY_ENV determines which environment to build for. Defaults to production.
// Allowed values: production | staging | development
const KLAAY_ENV = (process.env.KLAAY_ENV || process.env.NODE_ENV || 'production').toLowerCase()

// Provide sensible defaults for required Vite vars if not already set
if (!process.env.VITE_API_BASE_URL || !process.env.VITE_EARTHENWARE_URL) {
  if (KLAAY_ENV === 'staging') {
    process.env.VITE_API_BASE_URL ||= 'https://api.klaay.dev'
    process.env.VITE_EARTHENWARE_URL ||= 'https://app.klaay.dev'
  } else if (KLAAY_ENV === 'development') {
    process.env.VITE_API_BASE_URL ||= 'http://localhost:3000'
    process.env.VITE_EARTHENWARE_URL ||= 'http://localhost:5173'
  } else {
    process.env.VITE_API_BASE_URL ||= 'https://api.klaay.com'
    process.env.VITE_EARTHENWARE_URL ||= 'https://app.klaay.com'
  }
}

const hasKey = !!process.env.TAURI_SIGNING_PRIVATE_KEY
const args = ['build']
const passThrough = process.argv.slice(2)

// Select a per-env tauri config to ensure Vite runs with the correct mode
if (KLAAY_ENV === 'staging') {
  args.push('--config', 'src-tauri/tauri.staging.json')
} else if (KLAAY_ENV === 'development') {
  args.push('--config', 'src-tauri/tauri.development.json')
}

if (!hasKey) {
  // Merge override to disable updater artifacts locally
  args.push('--config', 'src-tauri/tauri.no-updater.json')
}

// Pass through any additional CLI flags (e.g., --target)
args.push(...passThrough)

function resolveTauriCommand() {
  const binDir = path.resolve(__dirname, '../node_modules/.bin')
  const win = process.platform === 'win32'
  
  if (win) {
    // On Windows, try multiple candidates
    const candidates = [
      path.join(binDir, 'tauri.cmd'),
      path.join(binDir, 'tauri'),
      path.resolve(__dirname, '../node_modules/@tauri-apps/cli-win32-x64-msvc/tauri.exe'),
      path.resolve(__dirname, '../node_modules/@tauri-apps/cli/tauri.js')
    ]
    
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        console.log(`[tauri-build] Using Tauri CLI: ${candidate}`)
        return candidate
      }
    }
  } else {
    const candidate = path.join(binDir, 'tauri')
    if (fs.existsSync(candidate)) return candidate
  }
  
  // Fallback to PATH (works when invoked via yarn where .bin is injected)
  return 'tauri'
}

const tauriCmd = resolveTauriCommand()
console.log(`[tauri-build] Resolved Tauri command: ${tauriCmd}`)
console.log(`[tauri-build] Command exists: ${fs.existsSync(tauriCmd)}`)
console.log(`[tauri-build] Platform: ${process.platform}`)
console.log(`[tauri-build] Args: ${args.join(' ')}`)

const result = spawnSync(tauriCmd, args, { 
  stdio: 'inherit', 
  env: process.env, 
  shell: process.platform === 'win32' // Use shell on Windows
})

if (result.error) {
  console.error(`[tauri-build] Failed to spawn Tauri CLI: ${result.error.message}`)
  process.exit(1)
}

if (typeof result.status !== 'number' || result.status !== 0) {
  console.error(`[tauri-build] Tauri exited with code ${result.status ?? 'unknown'}`)
  process.exit(result.status ?? 1)
}

process.exit(0)
