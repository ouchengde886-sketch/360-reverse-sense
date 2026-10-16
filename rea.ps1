# REA launcher for this workspace.
#
# Why this wrapper exists:
#   The DSH file sandbox permits the Java child process to write ONLY inside the
#   workspace. REA's Ghidra provider normally builds its runtime root under
#   %TEMP% (and Ghidra's LaunchSupport writes java_home.save under
#   %APPDATA%\ghidra), both of which Java cannot create files in. Ghidra then
#   fails with "JDK 21+ (64-bit) could not be found" and exits before the bridge
#   starts. Redirecting TEMP/TMP/XDG_CONFIG_HOME into the workspace fixes it.
#
# Usage:  .\rea.ps1 inspect <path> --format json
#         .\rea.ps1 function <path> <addr> --format json

$ErrorActionPreference = 'Stop'

$ws = $PSScriptRoot
$env:GHIDRA_INSTALL_DIR = Join-Path $ws 'tools\ghidra_12.1.4_PUBLIC'
$env:JAVA_HOME         = Join-Path $ws 'tools\jdk\jdk-21.0.12.1+1'
$env:PATH              = "$env:JAVA_HOME\bin;$env:PATH"

# Keep every Java-writable path inside the workspace sandbox.
$reaTmp = Join-Path $ws 'tools\rea-tmp'
$ghUser = Join-Path $ws 'tools\ghidra-user'
New-Item -ItemType Directory -Force -Path $reaTmp, "$ghUser\home", "$ghUser\tmp", "$ghUser\config" | Out-Null
$env:TEMP = $reaTmp
$env:TMP  = $reaTmp
$env:XDG_CONFIG_HOME = Join-Path $ghUser 'config'

# Ghidra's LaunchSupport caches the selected JDK under the config root; seed it
# so a headless launch never falls into its interactive JDK prompt.
$save = Join-Path $env:XDG_CONFIG_HOME 'ghidra\ghidra_12.1.4_PUBLIC\java_home.save'
New-Item -ItemType Directory -Force -Path (Split-Path $save) | Out-Null
if (-not (Test-Path $save) -or (Get-Content $save -Raw).Trim() -ne $env:JAVA_HOME) {
    Set-Content -Path $save -Value $env:JAVA_HOME -NoNewline
}

$rea = 'C:\Users\Administrator\Documents\Codex\tools\rea\rea.cmd'
& $rea @args
exit $LASTEXITCODE