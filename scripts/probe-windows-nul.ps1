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
$helper = Join-Path $programs 'cl-exec-sandbox-windows-diagnostic.exe'
$child = Join-Path $programs 'windows-child.exe'
$git = Join-Path $gitRoot 'cmd/git.exe'
$env:TEMP = Join-Path $root 'temp'
$env:TMP = $env:TEMP
$env:HOME = $root
$env:USERPROFILE = $root
$env:LOCALAPPDATA = Join-Path $root 'AppData/Local'
$env:APPDATA = Join-Path $root 'AppData/Roaming'
New-Item -ItemType Directory -Force -Path $workspace, $env:TEMP, $env:LOCALAPPDATA, $env:APPDATA | Out-Null

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program exited $LASTEXITCODE" }
}

function Invoke-Probe {
    param([string]$Mode, [string]$Name, [string]$Program, [string[]]$Arguments,
          [int]$Expected = -1)
    Write-Host "PROBE mode=$Mode name=$Name"
    if ($Mode -eq 'ordinary-user') {
        & $Program @Arguments
        $status = $LASTEXITCODE
    } else {
        $env:CL_EXEC_SANDBOX_DIAGNOSTIC_MODE = $Mode
        $profile = (& $helper --new-profile).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Could not allocate the diagnostic profile.' }
        $rules = @('read', $programs, 'write', $workspace,
                   'read', (Join-Path $workspace '.git'))
        if ($Program -eq $git) { $rules += @('read', $gitRoot) }
        try {
            & $helper --run $profile isolated $workspace @rules -- $Program @Arguments
            $status = $LASTEXITCODE
        } finally {
            & $helper --cleanup $profile @rules
            if ($LASTEXITCODE -ne 0) { throw "Profile cleanup failed: $profile" }
        }
        if ($status -eq 125) { throw "Native diagnostic launch failed for $Mode/$Name." }
    }
    Write-Host "RESULT mode=$Mode name=$Name exit=$status"
    if ($Expected -ge 0 -and $status -ne $Expected) {
        throw "Unexpected result for $Mode/${Name}: got $status, expected $Expected."
    }
}

Invoke-Checked $git @('-C', $workspace, 'init', '--quiet')
Invoke-Checked $git @('-C', $workspace, 'config', 'user.email', 'diagnostic@example.invalid')
Invoke-Checked $git @('-C', $workspace, 'config', 'user.name', 'diagnostic')
[IO.File]::WriteAllText((Join-Path $workspace 'tracked.txt'), 'fixture')
Invoke-Checked $git @('-C', $workspace, 'add', 'tracked.txt')
Invoke-Checked $git @('-C', $workspace, 'commit', '--quiet', '-m', 'fixture')
foreach ($mode in @('ordinary-user', 'restricted-only', 'appcontainer-only', 'combined', 'combined-hook')) {
    Invoke-Probe $mode 'nul-security' $child @('nul-security')
    Invoke-Probe $mode 'nul' $child @('nul')
    Invoke-Probe $mode 'nul-descendant' $child @('nul-descendant')
    Invoke-Probe $mode 'cwd' $child @('cwd')
    Invoke-Probe $mode 'git-status' $git @('-C', $workspace, 'status', '--porcelain')
    Invoke-Probe $mode 'git-rev-parse' $git @('-C', $workspace, 'rev-parse', '--show-toplevel')
}
$outside = Join-Path $root 'outside'
New-Item -ItemType Directory -Path $outside | Out-Null
$secret = Join-Path $outside 'secret.txt'
[IO.File]::WriteAllText($secret, 'outside fixture')
Invoke-Probe 'combined-hook' 'appcontainer-identity' $child @('identity') -Expected 0
Invoke-Probe 'combined-hook' 'workspace-read' $child @('read', (Join-Path $workspace 'tracked.txt')) -Expected 0
Invoke-Probe 'combined-hook' 'workspace-write' $child @('write', (Join-Path $workspace 'allowed.txt')) -Expected 0
Invoke-Probe 'combined-hook' 'outside-read' $child @('read', $secret) -Expected 5
Invoke-Probe 'combined-hook' 'outside-write' $child @('write', (Join-Path $outside 'denied.txt')) -Expected 5
Invoke-Probe 'combined-hook' 'metadata-acl' $child @('change-acl', (Join-Path $workspace '.git/config')) -Expected 5
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
try {
    $port = $listener.LocalEndpoint.Port.ToString()
    Invoke-Probe 'ordinary-user' 'network-control' $child @('connect', $port) -Expected 0
    Invoke-Probe 'combined-hook' 'network-denial' $child @('connect', $port) -Expected 5
} finally { $listener.Stop() }
$delayed = Join-Path $workspace 'descendant-survived.txt'
Invoke-Probe 'combined-hook' 'descendant-cleanup' $child @('spawn-exit', $delayed) -Expected 0
Start-Sleep -Seconds 2
if (Test-Path -LiteralPath $delayed) { throw 'A sandbox descendant survived the main process.' }
$originalPrograms = $programs
$programs = Join-Path $root 'programs žluťoučký 日本'
New-Item -ItemType Directory -Path $programs | Out-Null
foreach ($name in @('cl-exec-sandbox-windows-diagnostic.exe', 'windows-child.exe', 'cl-exec-sandbox-null.dll')) {
    Copy-Item -LiteralPath (Join-Path $originalPrograms $name) -Destination $programs
}
$helper = Join-Path $programs 'cl-exec-sandbox-windows-diagnostic.exe'
$child = Join-Path $programs 'windows-child.exe'
$env:PATH = $programs + [IO.Path]::PathSeparator + $env:PATH
$env:CL_EXEC_SANDBOX_NULL_BASENAME = '1'
Invoke-Probe 'combined-hook' 'unicode-nul' $child @('nul') -Expected 0
Invoke-Probe 'combined-hook' 'unicode-descendant' $child @('nul-descendant') -Expected 0
exit 0
