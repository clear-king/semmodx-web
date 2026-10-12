@echo off
rem Starts SemModX Web with the interpreter set in settings.ini ([ida] python).
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
set PY=python
for /f "usebackq tokens=1,* delims==" %%A in (`findstr /r /c:"^ *python *=" settings.ini 2^>nul`) do (
    for /f "tokens=*" %%V in ("%%B") do if not "%%V"=="" set PY=%%V
)
"%PY%" serve.py
pause
