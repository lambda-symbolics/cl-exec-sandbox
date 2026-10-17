# Build the Windows sandbox helper and native compatibility DLLs.
[CmdletBinding()]
param(
  [switch]$InternalBuild,
  [string]$Stage,
  [string]$DetoursSource,
  [string]$Architecture
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$lock = Join-Path $PSScriptRoot 'windows-dependency.lock'
$build = Join-Path $root 'build'
$lockData = ConvertFrom-StringData (Get-Content $lock -Raw)
$commit = $lockData.commit
$url = $lockData.archive
$hash = $lockData.sha256

function Invoke-Native([string]$Program, [string[]]$Arguments) {
  & $Program @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
function Find-Vcvarsall {
  $where = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
  if (Test-Path $where) {
    $install = & $where -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($install) {
      $candidate = Join-Path $install.Trim() 'VC/Auxiliary/Build/vcvarsall.bat'
      if (Test-Path $candidate) { return $candidate }
    }
  }
  $candidate = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio') -Filter vcvarsall.bat -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like '*VC*Auxiliary*Build*' } | Select-Object -First 1
  if ($candidate) { return $candidate.FullName }
  throw 'Visual Studio vcvarsall.bat was not found'
}
function Read-DetoursSource([string]$Override) {
  if ($Override) {
    if (-not (Test-Path (Join-Path $Override 'src/Makefile'))) { throw "Incomplete Detours source override: $Override" }
    $actual = (& git -C $Override rev-parse HEAD).Trim()
    if ($actual -ne $commit) { throw "Detours override revision mismatch: $actual" }
    return (Resolve-Path $Override).Path
  }
  $archive = Join-Path $env:TEMP "detours-$commit.tar.gz"
  if (-not (Test-Path $archive)) { Invoke-WebRequest $url -OutFile $archive -UseBasicParsing }
  if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) { throw 'Detours archive SHA256 mismatch' }
  $extract = Join-Path $env:TEMP "detours-$commit"
  if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
  New-Item -ItemType Directory $extract | Out-Null
  Invoke-Native tar @('-xzf', $archive, '-C', $extract)
  $source = Get-ChildItem $extract -Directory | Select-Object -First 1
  if (-not $source) { throw 'Detours archive contained no source directory' }
  return $source.FullName
}
function Invoke-ArchBuild([string]$Arch, [string]$OutputStage, [string]$Source) {
  $script = $PSCommandPath
  $args = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -InternalBuild -Stage `"$OutputStage`" -DetoursSource `"$Source`" -Architecture $Arch"
  $command = "call `"$(Find-Vcvarsall)`" $Arch && powershell.exe $args"
  Invoke-Native cmd.exe @('/d', '/s', '/c', $command)
}
function Assert-Pe([string]$Path, [int]$Machine) {
  $bytes = [IO.File]::ReadAllBytes($Path)
  $offset = [BitConverter]::ToInt32($bytes, 0x3c)
  if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a -or $offset -lt 0 -or $offset + 6 -gt $bytes.Length -or [BitConverter]::ToUInt16($bytes, $offset + 4) -ne $Machine) { throw "Invalid PE output: $Path" }
}

if (-not $InternalBuild) {
  if ((Get-Content $lock -Raw) -notmatch $hash) { throw 'Detours lock file is inconsistent' }
  $stageRoot = Join-Path $root ('.windows-build-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory $stageRoot | Out-Null
  try {
    $source = Read-DetoursSource $env:CL_EXEC_SANDBOX_DETOURS_SOURCE
    Invoke-ArchBuild 'x64' $stageRoot $source
    Invoke-ArchBuild 'x86' $stageRoot $source
    $outputs = @('cl-exec-sandbox-windows.exe', 'cl-exec-sandbox-compat64.dll', 'cl-exec-sandbox-compat32.dll', 'LICENSE-Detours.txt')
    foreach ($name in $outputs) {
      $path = Join-Path $stageRoot $name
      if (-not (Test-Path $path) -or (Get-Item $path).Length -eq 0) { throw "Missing build output: $name" }
    }
    Assert-Pe (Join-Path $stageRoot $outputs[0]) 0x8664
    Assert-Pe (Join-Path $stageRoot $outputs[1]) 0x8664
    Assert-Pe (Join-Path $stageRoot $outputs[2]) 0x14c
    if (Test-Path $build) { Move-Item $build ($build + '.old-' + [Guid]::NewGuid().ToString('N')) }
    Move-Item $stageRoot $build
  } catch {
    if (Test-Path $stageRoot) { Remove-Item $stageRoot -Recurse -Force }
    throw
  }
  exit 0
}

New-Item -ItemType Directory -Force $Stage | Out-Null
$detoursBuild = Join-Path $env:TEMP ('detours-build-' + [Guid]::NewGuid().ToString('N'))
try {
  Copy-Item $DetoursSource $detoursBuild -Recurse
  Push-Location (Join-Path $detoursBuild 'src')
  $processor = if ($Architecture -eq 'x86') { 'X86' } else { 'X64' }
  Invoke-Native nmake.exe @('/nologo', '/f', 'Makefile', "DETOURS_TARGET_PROCESSOR=$processor")
  $lib = Join-Path $detoursBuild "lib.$processor/detours.lib"
  if (-not (Test-Path $lib)) { throw "Detours library was not built: $lib" }
  Pop-Location
  $cobj = Join-Path $Stage 'cl-exec-sandbox-windows.obj'
  Invoke-Native clang.exe @('-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-c', (Join-Path $root 'helper/cl-exec-sandbox-windows.c'), '-o', $cobj)
  $sources = @((Join-Path $root 'helper/windows-inject.cpp'), (Join-Path $root 'helper/nul-broker.cpp'))
  $objects = foreach ($source in $sources) {
    $object = Join-Path $Stage ((Split-Path $source -Leaf) -replace '.cpp$', '.obj')
    Invoke-Native cl.exe @('/nologo', '/c', '/O2', '/MT', '/W4', '/WX', '/EHsc', $source, "/Fo$object")
    $object
  }
  if ($Architecture -eq 'x64') {
    Invoke-Native cl.exe (@('/nologo', '/O2', '/MT', '/W4', '/WX', $cobj) + $objects + @($lib, 'advapi32.lib', 'userenv.lib', 'ole32.lib', "/Fe:$(Join-Path $Stage 'cl-exec-sandbox-windows.exe')"))
  }
  $dll = if ($Architecture -eq 'x64') { 'cl-exec-sandbox-compat64.dll' } else { 'cl-exec-sandbox-compat32.dll' }
  Invoke-Native cl.exe @('/nologo', '/LD', '/O2', '/MT', '/W4', '/WX', '/DCL_EXEC_SANDBOX_NULL_DLL', "/Fe:$(Join-Path $Stage $dll)", (Join-Path $root 'helper/windows-compat.cpp'), (Join-Path $root 'helper/windows-inject.cpp'), $lib, 'advapi32.lib', 'userenv.lib', 'ole32.lib', '/link', '/EXPORT:DetourFinishHelperProcess,@1,NONAME')
  if ($Architecture -eq 'x86') { Copy-Item (Join-Path $DetoursSource 'LICENSE.md') (Join-Path $Stage 'LICENSE-Detours.txt') }
} finally {
  Pop-Location -ErrorAction SilentlyContinue
  if (Test-Path $detoursBuild) { Remove-Item $detoursBuild -Recurse -Force }
}
