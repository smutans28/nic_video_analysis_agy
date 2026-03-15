@echo off
echo ===================================================
echo COMPILANDO NIC VIDEO FORENSIC TOOL COM NUITKA (ONEFILE)
echo ===================================================
echo.
echo Lembre-se de pausar seu Antivirus (Windows Defender) durante a build!
echo.

python -m nuitka ^
  --onefile ^
  --remove-output ^
  --windows-console-mode=disable ^
  --windows-icon-from-ico=assets\icone.ico ^
  --enable-plugin=pyside6 ^
  --enable-plugin=numpy ^
  --include-data-dir=assets=assets ^
  --include-data-dir=bin=bin ^
  --output-dir=build_out ^
  --output-filename=NIC_Video_Forensic_Tool_v1.0.7.exe ^
  main.py

echo.
echo ===================================================
echo COMPILACAO FINALIZADA!
echo O executavel unico devera estar em: build_out\NIC_Video_Forensic_Tool_v1.0.7.exe
echo ===================================================
pause
