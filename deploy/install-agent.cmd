@echo off
rem Installs the EMS agent without any prompts, for a deployment tool or a
rem start-up script. Must run as administrator. Safe to run again: it
rem upgrades in place.
rem
rem Put this file in a folder together with ONE organisation's installer as
rem downloaded from the console (EMS-Agent-<organisation>.exe), or with
rem ems-agent.exe and that organisation's ems-agent.json.
rem
rem For a single computer there is no need for this file: just double-click
rem the installer.

setlocal
set "AGENT="
set /a FOUND=0
for %%F in ("%~dp0EMS-Agent-*.exe") do (
  set "AGENT=%%~fF"
  set /a FOUND+=1
)
if %FOUND% GTR 1 (
  echo More than one installer was found next to %~nx0. Keep only the one for this organisation.
  exit /b 2
)
if not defined AGENT if exist "%~dp0ems-agent.exe" set "AGENT=%~dp0ems-agent.exe"
if not defined AGENT (
  echo The agent installer was not found next to %~nx0
  exit /b 2
)
rem "start /wait" because the agent is a windowed program and would otherwise return at once.
start "" /wait "%AGENT%" install
exit /b %errorlevel%
