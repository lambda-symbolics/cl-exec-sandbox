# Run from a Visual Studio developer shell (Windows SDK headers and libraries).
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build'
New-Item -ItemType Directory -Force -Path $build | Out-Null
$source = Join-Path $root 'helper\cl-exec-sandbox-windows.c'
$output = Join-Path $build 'cl-exec-sandbox-windows.exe'
$compiler = if ($env:CC) { $env:CC } else { 'clang' }
& $compiler -std=c11 -O2 -Wall -Wextra -Werror $source -o $output -ladvapi32 -luserenv -lole32
if ($LASTEXITCODE -ne 0) { throw "Windows helper compilation failed: $LASTEXITCODE" }
$output
