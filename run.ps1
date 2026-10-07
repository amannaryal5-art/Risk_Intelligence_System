# One-command startup for Risk Intelligence System (SafeCheck)
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (Test-Path ".venv\Scripts\python.exe") {
    & ".venv\Scripts\python.exe" start.py
} else {
    python start.py
}
