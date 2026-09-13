# CI creates a disposable standard account to test the unprivileged launch path.
param([Parameter(Mandatory = $true)][string]$RuntimeDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Split-Path -Parent $PSScriptRoot
$name = "ClSandbox$PID"
$root = Join-Path $env:PUBLIC $name
$password = ConvertTo-SecureString (([Guid]::NewGuid().ToString('N')) + '!aA1') -AsPlainText -Force
$user = $null
try {
  $user = New-LocalUser -Name $name -Password $password -AccountNeverExpires
  New-Item -ItemType Directory -Path $root | Out-Null
  & icacls.exe $root /inheritance:r /grant:r "*$($user.SID.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
  if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare private test directory.' }
  $repository = Join-Path $root 'source'
  New-Item -ItemType Directory -Path $repository | Out-Null
  foreach ($entry in 'source','tests','build','cl-exec-sandbox.asd') {
    Copy-Item -Recurse -LiteralPath (Join-Path $source $entry) -Destination $repository
  }
  Copy-Item -Recurse -LiteralPath $RuntimeDirectory -Destination (Join-Path $root 'runtime')
  $script = Join-Path $root 'run.ps1'
  @'
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Test account is elevated.' }
$env:TEMP = Join-Path $PSScriptRoot 'temp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
$env:SBCL_HOME = Join-Path $PSScriptRoot 'runtime'
Set-Location (Join-Path $PSScriptRoot 'source')
& (Join-Path $env:SBCL_HOME 'sbcl.exe') --noinform --non-interactive --eval '(require :asdf)' --eval '(asdf:load-asd (truename "cl-exec-sandbox.asd"))' --eval '(asdf:test-system :cl-exec-sandbox/windows-tests)' > (Join-Path $PSScriptRoot 'output.log') 2>&1
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $script -Encoding utf8
  $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
  $process = Start-Process -FilePath (Get-Command pwsh.exe).Source -Credential $credential -LoadUserProfile -PassThru -WorkingDirectory $root -ArgumentList @('-NoProfile','-File',"`"$script`"")
  if (-not $process.WaitForExit(600000)) {
    Stop-Process -Id $process.Id -Force
    throw 'Windows enforcement tests timed out.'
  }
  $process.Refresh()
  $log = Join-Path $root 'output.log'
  if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log }
  if ($process.ExitCode -ne 0) { throw "Standard-user enforcement tests failed: $($process.ExitCode)" }
} finally {
  if ($user) {
    Get-CimInstance Win32_UserProfile | Where-Object SID -eq $user.SID.Value | Remove-CimInstance
    Remove-LocalUser -Name $name
  }
  if (Test-Path -LiteralPath $root) { Remove-Item -Recurse -Force -LiteralPath $root }
}
