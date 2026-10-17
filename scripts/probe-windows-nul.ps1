# Diagnostic-only Windows token/AppContainer/NUL matrix.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Join-Path $env:TEMP ('cl-exec-sandbox-nul-' + [Guid]::NewGuid().ToString('N'))
$workspace = Join-Path $root 'workspace'
$helper = Join-Path $PSScriptRoot '..\build\cl-exec-sandbox-windows-diagnostic.exe'
$child = Join-Path $PSScriptRoot '..\build\windows-child.exe'
$git = (Get-Command git.exe -CommandType Application).Source
New-Item -ItemType Directory -Force -Path $workspace | Out-Null
try {
  & $git -C $workspace init --quiet
  if ($LASTEXITCODE -ne 0) { throw 'Git fixture initialization failed.' }
  & $git -C $workspace config user.email diagnostic@example.invalid
  & $git -C $workspace config user.name diagnostic
  Set-Content -LiteralPath (Join-Path $workspace 'tracked.txt') -Value 'fixture' -Encoding utf8
  & $git -C $workspace add tracked.txt
  & $git -C $workspace commit --quiet -m fixture
  if ($LASTEXITCODE -ne 0) { throw 'Git fixture commit failed.' }
  $gitRoot = Split-Path -Parent $git
  foreach ($mode in @('ordinary-user','restricted-only','appcontainer-only','combined')) {
    Write-Host "=== $mode ==="
    if ($mode -eq 'ordinary-user') {
      Remove-Item Env:CL_EXEC_SANDBOX_DIAGNOSTIC_MODE -ErrorAction SilentlyContinue
      & $child nul-descendant
      Write-Host "descendant-exit=$LASTEXITCODE"
    } else {
      $env:CL_EXEC_SANDBOX_DIAGNOSTIC_MODE = $mode
      $profile = (& $helper --new-profile).Trim()
      & $helper --run $profile isolated $workspace read $gitRoot write $workspace -- $child nul-descendant
      Write-Host "sandbox-exit=$LASTEXITCODE"
    }
    $env:CL_EXEC_SANDBOX_DIAGNOSTIC_MODE = $mode
    if ($mode -ne 'ordinary-user') {
      $profile = (& $helper --new-profile).Trim()
      & $helper --run $profile isolated $workspace read $gitRoot write $workspace -- $child nul
      Write-Host "nul-exit=$LASTEXITCODE"
      $profile = (& $helper --new-profile).Trim()
      & $helper --run $profile isolated $workspace read $gitRoot write $workspace -- $git -C $workspace status --porcelain
      Write-Host "git-status-exit=$LASTEXITCODE"
      $profile = (& $helper --new-profile).Trim()
      & $helper --run $profile isolated $workspace read $gitRoot write $workspace -- $git -C $workspace rev-parse --show-toplevel
      Write-Host "git-rev-parse-exit=$LASTEXITCODE"
    }
  }
} finally {
  Remove-Item -Recurse -Force -LiteralPath $root -ErrorAction SilentlyContinue
}
