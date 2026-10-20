#!/usr/bin/env node

/**
 * scripts/stamp-license-date.js
 * 
 * Automates setting the BSL 1.1 "Change Date" (+4 years from current date)
 * across all LICENSE files in the Seatling monorepo.
 * 
 * Usage:
 *   node scripts/stamp-license-date.js               # Sets date to today + 4 years
 *   node scripts/stamp-license-date.js 2030-10-20     # Sets date to explicit YYYY-MM-DD
 *   node scripts/stamp-license-date.js --check        # Validates dates in CI
 */

const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const licenseFiles = [
  path.join(rootDir, 'LICENSE'),
  path.join(rootDir, 'crates', 'seatling-node', 'LICENSE'),
];

function calculateDefaultChangeDate() {
  const now = new Date();
  const year = now.getUTCFullYear() + 4;
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const day = String(now.getUTCDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

const args = process.argv.slice(2);
const isCheckMode = args.includes('--check');

if (isCheckMode) {
  let hasErrors = false;
  const todayStr = new Date().toISOString().split('T')[0];

  for (const filePath of licenseFiles) {
    if (!fs.existsSync(filePath)) {
      console.error(`[ERROR] License file missing: ${filePath}`);
      hasErrors = true;
      continue;
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const match = content.match(/^Change Date:\s+(\d{4}-\d{2}-\d{2})/m);

    if (!match) {
      console.error(`[ERROR] Could not find valid Change Date in: ${filePath}`);
      hasErrors = true;
      continue;
    }

    const dateStr = match[1];
    if (dateStr < todayStr) {
      console.error(`[ERROR] Change Date ${dateStr} in ${filePath} is expired (earlier than today: ${todayStr})`);
      hasErrors = true;
    } else {
      console.log(`[OK] ${path.relative(rootDir, filePath)}: Change Date is valid (${dateStr})`);
    }
  }

  if (hasErrors) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

// Stamping mode
let targetDate = calculateDefaultChangeDate();
const dateArg = args.find(arg => /^\d{4}-\d{2}-\d{2}$/.test(arg));
if (dateArg) {
  targetDate = dateArg;
}

let modifiedCount = 0;
for (const filePath of licenseFiles) {
  if (!fs.existsSync(filePath)) {
    console.warn(`[WARN] License file missing, skipping: ${filePath}`);
    continue;
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const regex = /^(Change Date:\s+)(.*)$/m;

  if (!regex.test(content)) {
    console.warn(`[WARN] No Change Date line found in: ${filePath}`);
    continue;
  }

  const updatedContent = content.replace(regex, `$1${targetDate}`);
  if (updatedContent !== content) {
    fs.writeFileSync(filePath, updatedContent, 'utf8');
    console.log(`[STAMPED] ${path.relative(rootDir, filePath)} -> Change Date: ${targetDate}`);
    modifiedCount++;
  } else {
    console.log(`[UNCHANGED] ${path.relative(rootDir, filePath)} already set to ${targetDate}`);
  }
}

console.log(`Successfully checked ${licenseFiles.length} license files (${modifiedCount} updated).`);
