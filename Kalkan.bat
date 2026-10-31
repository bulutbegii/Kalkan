@echo off
chcp 65001 >nul
title Kalkan
cd /d "%~dp0"

rem --- Ortami garanti et (stale env'e karsi): arac yollari + API anahtarlari ---
set "PATH=%PATH%;%USERPROFILE%\anaconda3;%USERPROFILE%\anaconda3\Scripts;%USERPROFILE%\tools\bin;C:\Program Files (x86)\Nmap;C:\Program Files\Nmap"
for /f "tokens=2,*" %%A in ('reg query "HKCU\Environment" /v SHODAN_API_KEY 2^>nul ^| findstr /i SHODAN_API_KEY') do set "SHODAN_API_KEY=%%B"
for /f "tokens=2,*" %%A in ('reg query "HKCU\Environment" /v NVD_API_KEY 2^>nul ^| findstr /i NVD_API_KEY') do set "NVD_API_KEY=%%B"

set "KEXE=%USERPROFILE%\anaconda3\Scripts\kalkan.exe"
set "PYEXE=%USERPROFILE%\anaconda3\python.exe"

if exist "%KEXE%" goto runexe
if exist "%PYEXE%" goto runpy
kalkan
goto done

:runexe
"%KEXE%"
goto done

:runpy
"%PYEXE%" -m kalkan.cli
goto done

:done
echo.
echo (pencereyi kapatmak icin bir tusa basin)
pause >nul
