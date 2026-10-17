# Build the Windows sandbox helper and native compatibility DLLs.
[CmdletBinding()]
param(
  [switch]$InternalBuild,
  [string]$Stage,
  [string]$DetoursSource,
  [string]$Architecture,
  [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $PSScriptRoot 'windows-dependency.lock'
$defaultOutput = Join-Path $root 'build'

function Invoke-Native([string]$Program, [string[]]$Arguments) {
  & $Program @Arguments | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
function Invoke-Captured([string]$Program, [string[]]$Arguments) {
  $result = & $Program @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
  return ($result -join "`n").Trim()
}
function Read-Lock {
  $data = ConvertFrom-StringData (Get-Content $lockPath -Raw)
  foreach ($field in @('name', 'version', 'commit', 'archive', 'sha256')) {
    if (-not $data.ContainsKey($field) -or [string]::IsNullOrWhiteSpace($data[$field])) {
      throw "Dependency lock lacks $field"
    }
  }
  if ($data.commit -notmatch '^[0-9a-f]{40}$') { throw 'Invalid Detours commit in lock' }
  if ($data.archive -notmatch '^https://github\.com/microsoft/Detours/archive/[0-9a-f]{40}\.tar\.gz$') { throw 'Invalid Detours archive in lock' }
  if ($data.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Invalid Detours SHA256 in lock' }
  if (($data.archive -split '/')[-1] -ne ($data.commit + '.tar.gz')) { throw 'Detours archive does not match commit' }
  [pscustomobject]$data
}
function Find-Vcvarsall {
  $where = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
  if (Test-Path $where) {
    $install = & $where -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -eq 0 -and $install) {
      $candidate = Join-Path $install.Trim() 'VC/Auxiliary/Build/vcvarsall.bat'
      if (Test-Path $candidate) { return $candidate }
    }
  }
  $candidate = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio') -Filter vcvarsall.bat -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like '*VC*Auxiliary*Build*' } | Select-Object -First 1
  if ($candidate) { return $candidate.FullName }
  throw 'Visual Studio vcvarsall.bat was not found'
}
function Read-DetoursSource($lockData, [string]$Override, [string]$TempRoot) {
  $archive = Join-Path $TempRoot 'detours.tar.gz'
  $extract = Join-Path $TempRoot 'detours-source'
  New-Item -ItemType Directory -Path $TempRoot | Out-Null
  if ($Override) {
    $actual = Invoke-Captured git @('-C', $Override, 'rev-parse', '--verify', "$($lockData.commit)^{commit}")
    if ($actual -ne $lockData.commit) { throw 'Detours source override is not at the locked commit' }
    $tar = Join-Path $TempRoot 'detours-source.tar'
    Invoke-Native git @('-C', $Override, 'archive', '--format=tar', $lockData.commit, '-o', $tar)
    New-Item -ItemType Directory -Path $extract | Out-Null
    Invoke-Native tar @('-xf', $tar, '-C', $extract)
    return $extract
  } else {
    Invoke-WebRequest -Uri $lockData.archive -OutFile $archive -UseBasicParsing
    if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $lockData.sha256) { throw 'Detours archive SHA256 mismatch' }
    New-Item -ItemType Directory -Path $extract | Out-Null
    Invoke-Native tar @('-xzf', $archive, '-C', $extract)
  }
  $source = Get-ChildItem $extract -Directory | Select-Object -First 1
  if (-not $source) { throw 'Detours source archive contained no directory' }
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
  if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) { throw "Invalid PE output: $Path" }
  $offset = [BitConverter]::ToInt32($bytes, 0x3c)
  if ($offset -lt 0 -or $offset -gt ($bytes.Length - 24) -or $bytes[$offset] -ne 0x50 -or $bytes[$offset + 1] -ne 0x45 -or $bytes[$offset + 2] -ne 0 -or $bytes[$offset + 3] -ne 0 -or [BitConverter]::ToUInt16($bytes, $offset + 4) -ne $Machine) { throw "Invalid PE output: $Path" }
}

if (-not $InternalBuild) {
  $lockData = Read-Lock
  $destination = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory) } else { $defaultOutput }
  if ($OutputDirectory -and (Test-Path $destination)) { throw "Output directory already exists: $destination" }
  $stageRoot = Join-Path $root ('.windows-build-' + [Guid]::NewGuid().ToString('N'))
  $sourceTemp = Join-Path $stageRoot 'dependency'
  New-Item -ItemType Directory -Path $stageRoot | Out-Null
  try {
    $source = Read-DetoursSource $lockData $env:CL_EXEC_SANDBOX_DETOURS_SOURCE $sourceTemp
    Invoke-ArchBuild 'x64' $stageRoot $source
    Invoke-ArchBuild 'x86' $stageRoot $source
    foreach ($buildOnly in @('dependency', 'x64', 'x86')) {
      $path = Join-Path $stageRoot $buildOnly
      if (Test-Path $path) { Remove-Item $path -Recurse -Force }
    }
    $outputs = @('cl-exec-sandbox-windows.exe', 'cl-exec-sandbox-compat64.dll', 'cl-exec-sandbox-compat32.dll', 'LICENSE-Detours.txt')
    foreach ($name in $outputs) {
      $path = Join-Path $stageRoot $name
      if (-not (Test-Path $path) -or (Get-Item $path).Length -eq 0) { throw "Missing build output: $name" }
    }
    Assert-Pe (Join-Path $stageRoot $outputs[0]) 0x8664
    Assert-Pe (Join-Path $stageRoot $outputs[1]) 0x8664
    Assert-Pe (Join-Path $stageRoot $outputs[2]) 0x14c
    if ($OutputDirectory) {
      New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
      Move-Item $stageRoot $destination
    } else {
      $backup = $null
      if (Test-Path $destination) {
        $backup = $destination + '.old-' + [Guid]::NewGuid().ToString('N')
        Move-Item $destination $backup
      }
      try { Move-Item $stageRoot $destination }
      catch {
        if ($backup -and (Test-Path $backup) -and -not (Test-Path $destination)) { Move-Item $backup $destination }
        throw
      }
    }
  } catch {
    if (Test-Path $stageRoot) { Remove-Item $stageRoot -Recurse -Force }
    throw
  }
  exit 0
}

if ($Architecture -notin @('x64', 'x86')) { throw "Unsupported architecture: $Architecture" }
New-Item -ItemType Directory -Path $Stage -Force | Out-Null
$archStage = Join-Path $Stage $Architecture
New-Item -ItemType Directory -Path $archStage -Force | Out-Null
$detoursBuild = Join-Path $Stage ('detours-build-' + [Guid]::NewGuid().ToString('N'))
$target = if ($Architecture -eq 'x64') { 'x86_64-pc-windows-msvc' } else { 'i686-pc-windows-msvc' }
$include = Join-Path $detoursBuild 'include'
try {
  Copy-Item $DetoursSource $detoursBuild -Recurse
  Push-Location (Join-Path $detoursBuild 'src')
  $processor = if ($Architecture -eq 'x86') { 'X86' } else { 'X64' }
  Invoke-Native nmake.exe @('/nologo', '/f', 'Makefile', "DETOURS_TARGET_PROCESSOR=$processor")
  $lib = Join-Path $detoursBuild "lib.$processor/detours.lib"
  if (-not (Test-Path $lib)) { throw "Detours library was not built: $lib" }
  Pop-Location
  $cobj = Join-Path $archStage 'cl-exec-sandbox-windows.obj'
  Invoke-Native clang-cl.exe @("--target=$target", '/TC', '/std:c11', '/O2', '/MT', '/clang:-Wall', '/clang:-Wextra', '/clang:-Werror', '/c', (Join-Path $root 'helper/cl-exec-sandbox-windows.c'), "/Fo$cobj")
  $sources = @((Join-Path $root 'helper/windows-inject.cpp'), (Join-Path $root 'helper/nul-broker.cpp'))
  $objects = foreach ($source in $sources) {
    $object = Join-Path $archStage ((Split-Path $source -Leaf) -replace '\.cpp$', '.obj')
    Invoke-Native cl.exe @('/nologo', "/I$include", '/c', '/O2', '/MT', '/W4', '/WX', '/EHsc', $source, "/Fo$object")
    $object
  }
  if ($Architecture -eq 'x64') {
    Invoke-Native cl.exe (@('/nologo', "/I$include", '/O2', '/MT', '/W4', '/WX', $cobj) + $objects + @($lib, 'advapi32.lib', 'userenv.lib', 'ole32.lib', 'ntdll.lib', "/Fe:$(Join-Path $archStage 'cl-exec-sandbox-windows.exe')"))
  }
  $dll = if ($Architecture -eq 'x64') { 'cl-exec-sandbox-compat64.dll' } else { 'cl-exec-sandbox-compat32.dll' }
  $dllObjectDirectory = Join-Path $archStage 'dll-objects'
  New-Item -ItemType Directory -Path $dllObjectDirectory -Force | Out-Null
  $dllObjectOutput = $dllObjectDirectory + '\'
  Invoke-Native cl.exe @('/nologo', "/I$include", '/LD', '/O2', '/MT', '/W4', '/WX', '/EHsc', '/DCL_EXEC_SANDBOX_NULL_DLL', "/Fo$dllObjectOutput", "/Fe:$(Join-Path $archStage $dll)", (Join-Path $root 'helper/windows-compat.cpp'), (Join-Path $root 'helper/windows-inject.cpp'), $lib, 'advapi32.lib', 'userenv.lib', 'ole32.lib', 'ntdll.lib', '/link', '/EXPORT:DetourFinishHelperProcess,@1,NONAME')
  if ($Architecture -eq 'x86') { Copy-Item (Join-Path $DetoursSource 'LICENSE.md') (Join-Path $archStage 'LICENSE-Detours.txt') }
  Copy-Item (Join-Path $archStage $dll) (Join-Path $Stage $dll)
  if ($Architecture -eq 'x64') { Copy-Item (Join-Path $archStage 'cl-exec-sandbox-windows.exe') (Join-Path $Stage 'cl-exec-sandbox-windows.exe') }
  if ($Architecture -eq 'x86') { Copy-Item (Join-Path $archStage 'LICENSE-Detours.txt') (Join-Path $Stage 'LICENSE-Detours.txt') }
} finally {
  Pop-Location -ErrorAction SilentlyContinue
  if (Test-Path $detoursBuild) { Remove-Item $detoursBuild -Recurse -Force }
}
