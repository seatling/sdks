const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..', '..', '..');
const targetDir = path.resolve(__dirname, '..');

if (!fs.existsSync(targetDir)) {
  fs.mkdirSync(targetDir, { recursive: true });
}

const possibleSources = [
  path.join(rootDir, 'target', 'release', 'seatling_node.dll'),
  path.join(rootDir, 'target', 'release', 'libseatling_node.so'),
  path.join(rootDir, 'target', 'release', 'libseatling_node.dylib'),
  path.join(rootDir, 'target', 'debug', 'seatling_node.dll'),
  path.join(rootDir, 'target', 'debug', 'libseatling_node.so'),
  path.join(rootDir, 'target', 'debug', 'libseatling_node.dylib'),
];

let copied = false;
for (const src of possibleSources) {
  if (fs.existsSync(src)) {
    const dest = path.join(targetDir, 'seatling.node');
    fs.copyFileSync(src, dest);
    console.log(`Copied ${src} -> ${dest}`);
    copied = true;
    break;
  }
}

if (!copied) {
  console.warn('Warning: Could not find compiled seatling-node binary to copy. Run cargo build -p seatling-node first.');
}
