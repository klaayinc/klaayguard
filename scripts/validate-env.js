#!/usr/bin/env node
/**
 * Validate environment files for KlaayGuard
 * Ensures all required variables are defined and consistent
 */

const fs = require('fs')
const path = require('path')

const PROJECT_ROOT = path.join(__dirname, '..')
const ENVIRONMENTS = ['development', 'staging', 'production']
const REQUIRED_VARS = ['KLAAY_ENV', 'VITE_API_BASE_URL', 'VITE_EARTHENWARE_URL']
const OPTIONAL_VARS = ['KLAAYGUARD_COLLECTION_INTERVAL_SECONDS', 'VITE_SENTRY_DSN']

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m'
}

function parseEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return null
  }

  const content = fs.readFileSync(filePath, 'utf8')
  const vars = {}

  content.split('\n').forEach(line => {
    // Skip comments and empty lines
    if (line.trim().startsWith('#') || !line.trim()) {
      return
    }

    // Parse key=value
    const match = line.match(/^([^=]+)=(.*)$/)
    if (match) {
      const key = match[1].trim()
      const value = match[2].trim()
      vars[key] = value
    }
  })

  return vars
}

function validateEnvironment(envName) {
  const envFile = path.join(PROJECT_ROOT, `.env.${envName}`)
  const errors = []
  const warnings = []

  console.log(`\n${colors.blue}Validating ${envName} environment...${colors.reset}`)

  // Check if file exists
  if (!fs.existsSync(envFile)) {
    errors.push(`Environment file not found: .env.${envName}`)
    console.log(`  ${colors.red}✗${colors.reset} File missing`)
    return { errors, warnings, vars: {} }
  }

  const vars = parseEnvFile(envFile)

  // Check required variables
  REQUIRED_VARS.forEach(varName => {
    if (!vars[varName] || vars[varName] === '') {
      errors.push(`${varName} is not defined in .env.${envName}`)
      console.log(`  ${colors.red}✗${colors.reset} ${varName} is missing`)
    } else {
      console.log(`  ${colors.green}✓${colors.reset} ${varName} = ${vars[varName]}`)
    }
  })

  // Check KLAAY_ENV matches
  if (vars.KLAAY_ENV && vars.KLAAY_ENV !== envName) {
    errors.push(`KLAAY_ENV="${vars.KLAAY_ENV}" does not match environment "${envName}"`)
    console.log(`  ${colors.red}✗${colors.reset} KLAAY_ENV mismatch`)
  }

  // Validate URL formats
  if (vars.VITE_API_BASE_URL) {
    try {
      new URL(vars.VITE_API_BASE_URL)
    } catch (e) {
      errors.push(`VITE_API_BASE_URL is not a valid URL: ${vars.VITE_API_BASE_URL}`)
      console.log(`  ${colors.red}✗${colors.reset} Invalid API URL format`)
    }
  }

  if (vars.VITE_EARTHENWARE_URL) {
    try {
      new URL(vars.VITE_EARTHENWARE_URL)
    } catch (e) {
      errors.push(`VITE_EARTHENWARE_URL is not a valid URL: ${vars.VITE_EARTHENWARE_URL}`)
      console.log(`  ${colors.red}✗${colors.reset} Invalid Earthenware URL format`)
    }
  }

  // Validate collection interval if present
  if (vars.KLAAYGUARD_COLLECTION_INTERVAL_SECONDS) {
    const interval = parseInt(vars.KLAAYGUARD_COLLECTION_INTERVAL_SECONDS, 10)
    if (isNaN(interval) || interval < 60) {
      warnings.push(`KLAAYGUARD_COLLECTION_INTERVAL_SECONDS should be >= 60 seconds`)
      console.log(`  ${colors.yellow}⚠${colors.reset} Collection interval may be too short`)
    }
  }

  return { errors, warnings, vars }
}

function checkDefaults() {
  const defaultsFile = path.join(PROJECT_ROOT, '.env.defaults')
  console.log(`\n${colors.blue}Checking defaults file...${colors.reset}`)

  if (!fs.existsSync(defaultsFile)) {
    console.log(`  ${colors.yellow}⚠${colors.reset} .env.defaults not found (optional)`)
    return { errors: [], warnings: ['No .env.defaults file found'], vars: {} }
  }

  const vars = parseEnvFile(defaultsFile)
  console.log(`  ${colors.green}✓${colors.reset} Found .env.defaults`)

  return { errors: [], warnings: [], vars }
}

function checkTemplates() {
  const configDir = path.join(PROJECT_ROOT, 'config')
  console.log(`\n${colors.blue}Checking template files...${colors.reset}`)

  if (!fs.existsSync(configDir)) {
    return { errors: ['config/ directory not found'], warnings: [] }
  }

  const templates = ['env.defaults', 'env.development', 'env.staging', 'env.production']
  const errors = []

  templates.forEach(template => {
    const templatePath = path.join(configDir, template)
    if (!fs.existsSync(templatePath)) {
      errors.push(`Template file missing: config/${template}`)
      console.log(`  ${colors.red}✗${colors.reset} ${template} missing`)
    } else {
      console.log(`  ${colors.green}✓${colors.reset} ${template}`)
    }
  })

  return { errors, warnings: [] }
}

function main() {
  console.log(`${colors.blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`)
  console.log(`${colors.blue}  KlaayGuard Environment Validation${colors.reset}`)
  console.log(`${colors.blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`)

  let allErrors = []
  let allWarnings = []

  // Check templates
  const templatesResult = checkTemplates()
  allErrors.push(...templatesResult.errors)
  allWarnings.push(...templatesResult.warnings)

  // Check defaults
  const defaultsResult = checkDefaults()
  allErrors.push(...defaultsResult.errors)
  allWarnings.push(...defaultsResult.warnings)

  // Validate each environment
  ENVIRONMENTS.forEach(env => {
    const result = validateEnvironment(env)
    allErrors.push(...result.errors)
    allWarnings.push(...result.warnings)
  })

  // Print summary
  console.log(`\n${colors.blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`)
  console.log(`${colors.blue}  Summary${colors.reset}`)
  console.log(`${colors.blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}\n`)

  if (allErrors.length === 0 && allWarnings.length === 0) {
    console.log(`${colors.green}✓ All environment files are valid!${colors.reset}\n`)
    process.exit(0)
  }

  if (allWarnings.length > 0) {
    console.log(`${colors.yellow}Warnings (${allWarnings.length}):${colors.reset}`)
    allWarnings.forEach(warning => {
      console.log(`  ${colors.yellow}⚠${colors.reset} ${warning}`)
    })
    console.log('')
  }

  if (allErrors.length > 0) {
    console.log(`${colors.red}Errors (${allErrors.length}):${colors.reset}`)
    allErrors.forEach(error => {
      console.log(`  ${colors.red}✗${colors.reset} ${error}`)
    })
    console.log('')
    console.log(`${colors.yellow}Run: scripts/setup-env.sh to create missing files${colors.reset}\n`)
    process.exit(1)
  }

  process.exit(0)
}

if (require.main === module) {
  main().catch((error) => {
    console.error('Unhandled error:', error)
    process.exit(1)
  })
}

module.exports = { parseEnvFile, validateEnvironment }
