@echo off
echo Installing PyInstaller...
C:\Users\saran\AppData\Local\Programs\Python\Python311\python.exe -m pip install pyinstaller

echo.
echo Building executable...
C:\Users\saran\AppData\Local\Programs\Python\Python311\python.exe -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --name "BruteForceDetector" ^
    --add-data "templates;templates" ^
    --add-data "_keys.py;." ^
    --hidden-import flask ^
    --hidden-import openai ^
    --hidden-import azure.identity ^
    --hidden-import azure.monitor.query ^
    --hidden-import pandas ^
    --hidden-import colorama ^
    --hidden-import tiktoken ^
    --hidden-import tiktoken_ext.openai_public ^
    --hidden-import tiktoken_ext ^
    launcher.py

echo.
echo Done! Your executable is in the dist/ folder.
echo Run: dist\BruteForceDetector.exe
pause
