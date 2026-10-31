@echo off
chcp 65001 >nul
title Kalkan
cd /d "%~dp0"

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
