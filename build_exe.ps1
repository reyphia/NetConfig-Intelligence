$ErrorActionPreference = "Stop"
python -m pip install ".[dev]"
python -m PyInstaller --noconfirm --clean NetConfig-Intelligence.spec
Write-Host "Created dist/NetConfig-Intelligence.exe"
