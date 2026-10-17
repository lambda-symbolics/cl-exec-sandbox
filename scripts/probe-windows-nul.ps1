$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The diagnostic account must not be elevated.'
}
$root = $PSScriptRoot
$workspace = Join-Path $root 'workspace'
$programs = Join-Path $root 'programs'
$gitRoot = Join-Path $root 'git'
$helper = Join-Path $programs 'cl-exec-sandbox-windows.exe'
$child = Join-Path $programs 'windows-child-x64.exe'
$processProbe = Join-Path $programs 'windows-process-x64.exe'
$childX86 = Join-Path $programs 'windows-child-x86.exe'
$processProbeX86 = Join-Path $programs 'windows-process-x86.exe'
$git = Join-Path $gitRoot 'cmd/git.exe'
$env:TEMP = Join-Path $root 'temp'
$env:TMP = $env:TEMP
$env:HOME = $root
$env:USERPROFILE = $root
$env:LOCALAPPDATA = Join-Path $root 'AppData/Local'
$env:APPDATA = Join-Path $root 'AppData/Roaming'
New-Item -ItemType Directory -Force -Path $workspace, $env:TEMP, $env:LOCALAPPDATA, $env:APPDATA | Out-Null

$unexpected = [Collections.Generic.List[string]]::new()

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program exited $LASTEXITCODE" }
}

function Invoke-Probe {
    param([string]$Mode, [string]$Name, [string]$Program, [string[]]$Arguments,
          [int]$Expected = -1, [switch]$Capture)
    Write-Host "PROBE mode=$Mode name=$Name"
    if ($Mode -eq 'ordinary-user') {
        if ($Capture) { $captured = @(& $Program @Arguments) }
        else { & $Program @Arguments }
        $status = $LASTEXITCODE
    } else {
        $profile = (& $helper --new-profile).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Could not allocate the sandbox profile.' }
        $rules = @('read', $programs, 'write', $workspace,
                   'read', (Join-Path $workspace '.git'))
        if ($Program -eq $git) { $rules += @('read', $gitRoot) }
        $actualArguments = @($Arguments | ForEach-Object {
            $_ -replace '@PROFILE@', $profile
        })
        try {
            if ($Capture) { $captured = @(& $helper --run $profile isolated $workspace @rules -- $Program @actualArguments) }
            else { & $helper --run $profile isolated $workspace @rules -- $Program @actualArguments }
            $status = $LASTEXITCODE
        } finally {
            & $helper --cleanup $profile @rules
            if ($LASTEXITCODE -ne 0) { throw "Profile cleanup failed: $profile" }
        }
    }
    Write-Host "RESULT mode=$Mode name=$Name exit=$status"
    if ($Expected -ge 0 -and $status -ne $Expected) {
        $script:unexpected.Add("Unexpected result for $Mode/${Name}: got $status, expected $Expected.")
    }
    if ($Capture) { return $captured }
}

Invoke-Checked $git @('-C', $workspace, 'init', '--quiet')
Invoke-Checked $git @('-C', $workspace, 'config', 'user.email', 'diagnostic@example.invalid')
Invoke-Checked $git @('-C', $workspace, 'config', 'user.name', 'diagnostic')
[IO.File]::WriteAllText((Join-Path $workspace 'tracked.txt'), 'fixture')
Invoke-Checked $git @('-C', $workspace, 'add', 'tracked.txt')
Invoke-Checked $git @('-C', $workspace, 'commit', '--quiet', '-m', 'fixture')
foreach ($mode in @('ordinary-user', 'production-sandbox')) {
    Invoke-Probe $mode 'nul-security' $child @('nul-security')
    Invoke-Probe $mode 'nul' $child @('nul') -Expected 0
    Invoke-Probe $mode 'nul-descendant' $child @('nul-descendant') -Expected 0
    Invoke-Probe $mode 'cwd' $child @('cwd') -Expected 0
    Invoke-Probe $mode 'git-status' $git @('-C', $workspace, 'status', '--porcelain') -Expected 0
    Invoke-Probe $mode 'git-rev-parse' $git @('-C', $workspace, 'rev-parse', '--show-toplevel') -Expected 0
    Invoke-Probe $mode 'nul-semantics' $child @('nul-semantics') -Expected 0
    Invoke-Probe $mode 'final-path-semantics' $child @('final-path-semantics') -Expected 0
    Invoke-Probe $mode 'nul-x86' $childX86 @('nul') -Expected 0
    Invoke-Probe $mode 'nul-semantics-x86' $childX86 @('nul-semantics') -Expected 0
    Invoke-Probe $mode 'final-path-semantics-x86' $childX86 @('final-path-semantics') -Expected 0
    $processOptions = @()
    if ($mode -eq 'production-sandbox') { $processOptions += '--sandbox' }
    Invoke-Probe $mode 'process-x64-to-x86' $processProbe ($processOptions + @('--peer', $processProbeX86)) -Expected 0
    Invoke-Probe $mode 'process-x86-to-x64' $processProbeX86 ($processOptions + @('--peer', $processProbe)) -Expected 0
}
Invoke-Probe 'production-sandbox' 'appcontainer-identity-x86' $childX86 @('identity') -Expected 0
foreach ($arch in @('x64', 'x86')) {
    $native = Join-Path $programs "windows-native-$arch.exe"
    $baseline = @(Invoke-Probe 'ordinary-user' "native-outputs-$arch" $native @() -Expected 0 -Capture)
    $contained = @(Invoke-Probe 'production-sandbox' "native-outputs-$arch" $native @() -Expected 0 -Capture)
    $baseline | ForEach-Object { Write-Host "NATIVE $arch $_" }
    foreach ($api in @('NtCreateFile', 'NtOpenFile')) {
        if (-not ($baseline -match "^api=$api case=control status=0x00000000 file=valid ")) {
            throw "The ordinary $arch $api control did not open Null."
        }
    }
    if ([string]::Join("`n", [string[]]$baseline) -cne [string]::Join("`n", [string[]]$contained)) {
        $contained | ForEach-Object { Write-Host "CONTAINED $arch $_" }
        throw "Native output semantics differ inside the $arch sandbox."
    }
}
Invoke-Probe 'production-sandbox' 'alias-tamper' $processProbe @('alias-tamper', '@PROFILE@') -Expected 0
$outside = Join-Path $root 'outside'
New-Item -ItemType Directory -Path $outside | Out-Null
$secret = Join-Path $outside 'secret.txt'
[IO.File]::WriteAllText($secret, 'outside fixture')
Invoke-Probe 'production-sandbox' 'appcontainer-identity' $child @('identity') -Expected 0
Invoke-Probe 'production-sandbox' 'workspace-read' $child @('read', (Join-Path $workspace 'tracked.txt')) -Expected 0
Invoke-Probe 'production-sandbox' 'workspace-write' $child @('write', (Join-Path $workspace 'allowed.txt')) -Expected 0
Invoke-Probe 'production-sandbox' 'outside-read' $child @('read', $secret) -Expected 5
Invoke-Probe 'production-sandbox' 'outside-write' $child @('write', (Join-Path $outside 'denied.txt')) -Expected 5
Invoke-Probe 'production-sandbox' 'metadata-acl' $child @('change-acl', (Join-Path $workspace '.git/config')) -Expected 5
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
try {
    $port = $listener.LocalEndpoint.Port.ToString()
    Invoke-Probe 'ordinary-user' 'network-control' $child @('connect', $port) -Expected 0
    Invoke-Probe 'production-sandbox' 'network-denial' $child @('connect', $port) -Expected 5
} finally { $listener.Stop() }
$delayed = Join-Path $workspace 'descendant-survived.txt'
Invoke-Probe 'production-sandbox' 'descendant-cleanup' $child @('spawn-exit', $delayed) -Expected 0
Start-Sleep -Seconds 2
if (Test-Path -LiteralPath $delayed) { throw 'A sandbox descendant survived the main process.' }
$originalPrograms = $programs
$programs = Join-Path $root 'programs žluťoučký 日本'
New-Item -ItemType Directory -Path $programs | Out-Null
foreach ($name in @('cl-exec-sandbox-windows.exe', 'windows-child-x64.exe', 'windows-child-x86.exe',
                   'windows-process-x64.exe', 'windows-process-x86.exe', 'LICENSE-Detours.txt',
                   'cl-exec-sandbox-compat64.dll', 'cl-exec-sandbox-compat32.dll')) {
    Copy-Item -LiteralPath (Join-Path $originalPrograms $name) -Destination $programs
}
$helper = Join-Path $programs 'cl-exec-sandbox-windows.exe'
$child = Join-Path $programs 'windows-child-x64.exe'
$processProbe = Join-Path $programs 'windows-process-x64.exe'
$processProbeX86 = Join-Path $programs 'windows-process-x86.exe'
$env:PATH = Join-Path $env:SystemRoot 'System32'
Invoke-Probe 'production-sandbox' 'unicode-nul' $child @('nul') -Expected 0
Invoke-Probe 'production-sandbox' 'unicode-descendant' $child @('nul-descendant') -Expected 0
Invoke-Probe 'production-sandbox' 'unicode-alias-clean-environment' $child @('nul-descendant-clean-environment') -Expected 0
if ($unexpected.Count) { throw ($unexpected -join [Environment]::NewLine) }
exit 0
