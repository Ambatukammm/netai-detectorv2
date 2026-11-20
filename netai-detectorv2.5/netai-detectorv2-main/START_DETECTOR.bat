@echo off
title NetAI Detector - Made by Ruel
cd /d "%~dp0"
set "PY="
rem Prefer well-supported Python versions; fall back to whatever is newest.
for %%V in (3.13 3.12 3.11 3.14 3.10) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>nul && set "PY=py -%%V"
  )
)
if not defined PY where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python 3.10 or newer is required.
  echo Install Python 3.12 or 3.13 from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
  echo then double-click this file again.
  pause
  exit /b 1
)
%PY% start.py
if errorlevel 1 pause
