# KlaayGuard

[![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri-FFC131.svg?logo=tauri)](https://tauri.app)

A lightweight desktop application built with Tauri and [your tech stack, e.g., React/Svelte/Vue].

![App Screenshot](./screenshot.png) *(Optional screenshot)*

## Features
- Feature 1 (e.g., Cross-platform support)
- Feature 2 (e.g., Offline capability)
- Feature 3 (e.g., Native system integrations)

## Prerequisites
- [Node.js](https://nodejs.org/) (v22 recommended)
- [Rust](https://www.rust-lang.org/) (latest stable)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites)
- [Tauri Prerequisites](https://v1.tauri.app/v1/guides/getting-started/prerequisites/)

## Downloading a precompiled dev build (Mac)

1. navigate to https://github.com/klaayinc/klaayguard/releases

2. look for the most recent "dev" release

3. download the appropriate package, this will probably be klaay_XXX_aarch64.dmg for apple silicon macs

4. install the package

## Compile dev build (Linux)
1. clone the repo:
   ```bash
   git clone https://github.com/klaayinc/klaayguard.git
   cd klaayguard
   ```

2. create a `.env` with the same content as `.env.example`

3. in the project root, run `docker compose run --rm klaayguard -- yarn run tauri build`

4. you will now have a binary `src-tauri/target/release/klaay`

## Quick Start
1. clone the repo:
   ```bash
   git clone https://github.com/klaayinc/klaayguard.git
   cd klaayguard

2. Install Dependencies:
    ```bash 
    npm install  # or pnpm/yarn

3. Run in development
    ```bash
    npm run tauri dev # or yarn tauri dev

4. Build the production:
    ```bash
    npm run tauri build # or yarn tauri dev

Project Structure

    /
    ├── src-tauri/      # Tauri backend (Rust)
    ├── src/            # Frontend (e.g., React/Vue files)
    ├── public/         # Static assets
    └── ...             # Other config files

Build for different platforms

    Platform	Command
    ```bash
    Windows	    npm run tauri build -- --target x86_64-pc-windows-msvc
    macOS	    npm run tauri build -- --target aarch64-apple-darwin
    Linux	    npm run tauri build -- --target x86_64-unknown-linux-gnu
