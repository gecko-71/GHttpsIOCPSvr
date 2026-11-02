@chcp 65001 >nul
@if exist "%~dp0venv\Scripts\python.exe" (
  @"%~dp0venv\Scripts\python.exe" "%~dp0app.py" %*
) else (
  @python.exe "%~dp0app.py" %*
)
