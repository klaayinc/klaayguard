#!/usr/bin/env node

import fs from 'fs';
import path from 'path';

// Read version from VERSION file
const version = fs.readFileSync('VERSION', 'utf8').trim();

console.log(`Syncing version ${version} across all files...`);

// Update tauri.conf.json
const tauriConfigPath = 'src-tauri/tauri.conf.json';
const tauriConfig = JSON.parse(fs.readFileSync(tauriConfigPath, 'utf8'));
tauriConfig.version = version;
fs.writeFileSync(tauriConfigPath, JSON.stringify(tauriConfig, null, 2) + '\n');
console.log(`✓ Updated ${tauriConfigPath}`);

// Update Cargo.toml
const cargoTomlPath = 'src-tauri/Cargo.toml';
let cargoToml = fs.readFileSync(cargoTomlPath, 'utf8');
cargoToml = cargoToml.replace(/^version = ".*"$/m, `version = "${version}"`);
fs.writeFileSync(cargoTomlPath, cargoToml);
console.log(`✓ Updated ${cargoTomlPath}`);

console.log('Version sync complete!');
