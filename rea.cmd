@echo off
REM REA launcher for this workspace (cmd wrapper; avoids PowerShell execution policy).
REM
REM Why this wrapper exists:
REM   The DSH file sandbox permits the Java child process to write ONLY inside the
REM   workspace. REA's Ghidra provider normally builds its runtime root under
REM   %%TEMP%% (and Ghidra's LaunchSupport writes java_home.save under
REM   %%APPDATA%%\ghidra), both of which Java cannot create files in. Ghidra then
REM   fails with "JDK 21+ (64-bit) could not be found" and exits before the bridge
REM   starts. Redirecting TEMP/TMP/XDG_CONFIG_HOME into the workspace fixes it.
setlocal
set "WS=%~dp0"
set "WS=%WS:~0,-1%"
set "GHIDRA_INSTALL_DIR=%WS%\tools\ghidra_12.1.4_PUBLIC"
set "JAVA_HOME=%WS%\tools\jdk\jdk-21.0.12.1+1"
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "TEMP=%WS%\tools\rea-tmp"
set "TMP=%WS%\tools\rea-tmp"
set "XDG_CONFIG_HOME=%WS%\tools\ghidra-user\config"
if not exist "%TEMP%" mkdir "%TEMP%"
if not exist "%XDG_CONFIG_HOME%\ghidra\ghidra_12.1.4_PUBLIC" mkdir "%XDG_CONFIG_HOME%\ghidra\ghidra_12.1.4_PUBLIC"
echo %JAVA_HOME%>"%XDG_CONFIG_HOME%\ghidra\ghidra_12.1.4_PUBLIC\java_home.save"
call "C:\Users\Administrator\Documents\Codex\tools\rea\rea.cmd" %*
exit /b %ERRORLEVEL%