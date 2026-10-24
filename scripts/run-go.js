#!/usr/bin/env node

/**
 * scripts/run-go.js
 * 
 * Cross-platform runner for Go SDK commands with CGO_ENABLED=1.
 * Automatically injects Zig CC on Windows if needed.
 */

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const args = process.argv.slice(2);
const env = { ...process.env, CGO_ENABLED: '1' };

const rootDir = path.resolve(__dirname, '..');
const goCwd = path.join(rootDir, 'crates', 'seatling-go');

// Keep C header synchronized with authoritative Rust core C header
const srcHeader = path.join(rootDir, 'crates', 'seatling', 'include', 'seatling', 'seatling.h');
const dstHeader = path.join(goCwd, 'include', 'seatling.h');
if (fs.existsSync(srcHeader)) {
  fs.mkdirSync(path.dirname(dstHeader), { recursive: true });
  fs.copyFileSync(srcHeader, dstHeader);
}

// Sync freshly built Rust staticlib into crates/seatling-go/lib/<os>_<arch>/libseatling.a if present
const platformMap = { win32: 'windows', darwin: 'darwin', linux: 'linux' };
const archMap = { x64: 'amd64', arm64: 'arm64' };
const goOS = platformMap[os.platform()];
const goArch = archMap[os.arch()];

if (goOS && goArch) {
  let builtRustLib = null;
  if (os.platform() === 'win32') {
    const gnuLib = path.join(rootDir, 'target', 'x86_64-pc-windows-gnu', 'release', 'libseatling.a');
    if (fs.existsSync(gnuLib)) {
      builtRustLib = gnuLib;
    }
  } else {
    const unixLib = path.join(rootDir, 'target', 'release', 'libseatling.a');
    if (fs.existsSync(unixLib)) {
      builtRustLib = unixLib;
    }
  }

  const dstLibDir = path.join(goCwd, 'lib', `${goOS}_${goArch}`);
  const dstLibPath = path.join(dstLibDir, 'libseatling.a');
  if (builtRustLib && fs.existsSync(builtRustLib)) {
    fs.mkdirSync(dstLibDir, { recursive: true });
    fs.copyFileSync(builtRustLib, dstLibPath);
  }
}

if (os.platform() === 'win32') {
  // First check if a MinGW GCC installation is available
  const possibleGccDirs = [];
  const localAppData = process.env.LOCALAPPDATA || '';
  if (localAppData) {
    const wingetPkgs = path.join(localAppData, 'Microsoft', 'WinGet', 'Packages');
    if (fs.existsSync(wingetPkgs)) {
      for (const entry of fs.readdirSync(wingetPkgs)) {
        if (entry.toLowerCase().includes('winlibs')) {
          const bin = path.join(wingetPkgs, entry, 'mingw64', 'bin');
          if (fs.existsSync(path.join(bin, 'gcc.exe'))) {
            possibleGccDirs.push(bin);
          }
        }
      }
    }
  }

  if (possibleGccDirs.length > 0) {
    const gccDir = possibleGccDirs[0];
    if (!env.CC) {
      env.CC = 'gcc';
    }
    if (!(env.PATH || '').toLowerCase().includes(gccDir.toLowerCase())) {
      env.PATH = `${gccDir};${env.PATH || ''}`;
    }
  } else {
    const possibleZigDirs = [];
    if (fs.existsSync('C:\\tools')) {
      for (const entry of fs.readdirSync('C:\\tools')) {
        if (entry.toLowerCase().startsWith('zig')) {
          possibleZigDirs.push(path.join('C:\\tools', entry));
        }
      }
    }
    possibleZigDirs.push(
      path.join(
        process.env.LOCALAPPDATA || '',
        'Microsoft',
        'WinGet',
        'Packages',
        'zig.zig_Microsoft.Winget.Source_8wekyb3d8bbwe'
      )
    );

    for (const dir of possibleZigDirs) {
      if (fs.existsSync(dir) && fs.existsSync(path.join(dir, 'zig.exe'))) {
        if (!env.CC) {
          env.CC = 'zig cc';
        }
        if (!(env.PATH || '').toLowerCase().includes(dir.toLowerCase())) {
          env.PATH = `${dir};${env.PATH || ''}`;
        }
        break;
      }
    }
  }

  // If using Zig CC on Windows, link -lunwind for LLVM-based GNU unwinding
  if (env.CC && env.CC.toLowerCase().includes('zig')) {
    if (!env.CGO_LDFLAGS || !env.CGO_LDFLAGS.includes('-lunwind')) {
      env.CGO_LDFLAGS = (env.CGO_LDFLAGS ? env.CGO_LDFLAGS + ' ' : '') + '-lunwind';
    }
  }
}

const result = spawnSync('go', ['-C', goCwd, ...args], {
  stdio: 'inherit',
  env,
});

if (result.error) {
  console.error(`Failed to execute go: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
