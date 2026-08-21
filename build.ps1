$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $messageBytes = [Convert]::FromBase64String(
        "5pyq5om+5Yiw6aG555uu6Jma5ouf546v5aKD5Lit55qEIFB5dGhvbuOAguivt+WFiOWIm+W7uiAudmVudiDlubblronoo4XlvIDlj5Hkvp3otZbjgII="
    )
    $message = [Text.Encoding]::UTF8.GetString($messageBytes)
    Write-Error "$message $python"
    exit 1
}

Push-Location $projectRoot
try {
    & $python -m pytest
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed; packaging stopped."
    }

    # network_doctor.app is the application module imported by the launcher.
    & $python -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --windowed `
        --name "NetworkDoctor" `
        --collect-submodules network_doctor `
        network_doctor_main.py
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller packaging failed."
    }

    $executable = Join-Path $projectRoot "dist\NetworkDoctor.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "NetworkDoctor.exe was not found after packaging: $executable"
    }

    $resolvedExecutable = (Resolve-Path -LiteralPath $executable).Path
    Write-Host "Created: $resolvedExecutable"
}
finally {
    Pop-Location
}
