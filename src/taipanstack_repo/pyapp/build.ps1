# Build standalone executable using PyApp (Windows)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

# Configuration
$env:PYAPP_PROJECT_NAME = "stack-bootstrapper"
$env:PYAPP_PROJECT_VERSION = "2.0.0"
$env:PYAPP_PROJECT_PATH = $ProjectRoot
$env:PYAPP_PYTHON_VERSION = "3.11"
$env:PYAPP_EXEC_SCRIPT = "stack_bootstrapper.py"
$env:PYAPP_DISTRIBUTION_EMBED = "true"
$env:PYAPP_FULL_ISOLATION = "true"

# Check for Rust
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "Error: Rust/Cargo is required. Install from https://rustup.rs/"
    exit 1
}

# Clone or update PyApp
$PyAppDir = Join-Path $ScriptDir ".pyapp-src"
if (Test-Path $PyAppDir) {
    Write-Host "Updating PyApp source..."
    git -C $PyAppDir pull --quiet
} else {
    Write-Host "Cloning PyApp source..."
    git clone --depth 1 https://github.com/ofek/pyapp.git $PyAppDir
}

# Build
Write-Host "Building standalone executable..."
Set-Location $PyAppDir
cargo build --release

# Copy output
$DistDir = Join-Path $ScriptDir "dist"
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
Copy-Item (Join-Path $PyAppDir "target\release\pyapp.exe") (Join-Path $DistDir "stack-bootstrapper.exe")

Write-Host ""
Write-Host "Build complete! Executable: $DistDir\stack-bootstrapper.exe"
Write-Host ""
Write-Host "Usage:"
Write-Host "  .\dist\stack-bootstrapper.exe --help"
Write-Host "  .\dist\stack-bootstrapper.exe --dry-run"
