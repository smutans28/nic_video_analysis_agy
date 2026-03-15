@echo off
echo ===================================================
echo COMPILANDO NIC FORENSIC TOOL COM NUITKA
echo ===================================================
echo.
echo Lembre-se de pausar seu Antivirus (Windows Defender) durante a build!
echo.

python -m nuitka ^
  --standalone ^
  --remove-output ^
  --windows-console-mode=disable ^
  --windows-icon-from-ico=assets\icone.ico ^
  --enable-plugin=pyside6 ^
  --enable-plugin=numpy ^
  --include-data-dir=assets=assets ^
  --include-data-dir=bin=bin ^
  --output-dir=build_out ^
  main.py

echo.
echo ===================================================
echo COMPILACAO FINALIZADA!
echo O executavel devera estar em: build_out\main.dist\main.exe
echo ===================================================
pause
