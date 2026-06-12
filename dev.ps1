param(
    [ValidateSet("start", "restart", "stop", "status")]
    [string]$Mode = "start",
    [int]$BackendPort = 8020,
    [int]$FrontendPort = 5173
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $Root "backend"
$FrontendDir = Join-Path $Root "frontend"
$BackendOut = Join-Path $Root "backend-dev.out.log"
$BackendErr = Join-Path $Root "backend-dev.err.log"
$FrontendOut = Join-Path $Root "frontend-dev.out.log"
$FrontendErr = Join-Path $Root "frontend-dev.err.log"

function Get-PortProcessIds {
    param([int]$Port)

    $connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
}

function Stop-Port {
    param(
        [int]$Port,
        [string]$Name
    )

    $processIds = Get-PortProcessIds -Port $Port
    foreach ($processId in $processIds) {
        if (-not $processId) {
            continue
        }

        Write-Host "Stopping $Name on port $Port (PID $processId)..."
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
}

function Test-Http {
    param(
        [string]$Url,
        [int]$TimeoutSec = 2
    )

    try {
        Invoke-WebRequest -UseBasicParsing $Url -TimeoutSec $TimeoutSec | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Wait-Http {
    param(
        [string]$Url,
        [string]$Name,
        [int]$Seconds = 20
    )

    for ($i = 0; $i -lt $Seconds; $i++) {
        if (Test-Http -Url $Url -TimeoutSec 2) {
            Write-Host "$Name is ready: $Url"
            return $true
        }
        Start-Sleep -Seconds 1
    }

    Write-Host "$Name did not respond yet. Check logs if it is still starting."
    return $false
}

function Show-Status {
    $backendIds = Get-PortProcessIds -Port $BackendPort
    $frontendIds = Get-PortProcessIds -Port $FrontendPort

    if ($backendIds.Count -gt 0) {
        Write-Host "Backend: running on $BackendPort (PID $($backendIds -join ', '))"
    } else {
        Write-Host "Backend: stopped"
    }

    if ($frontendIds.Count -gt 0) {
        Write-Host "Frontend: running on $FrontendPort (PID $($frontendIds -join ', '))"
    } else {
        Write-Host "Frontend: stopped"
    }
}

if ($Mode -eq "stop" -or $Mode -eq "restart") {
    Stop-Port -Port $BackendPort -Name "backend"
    Stop-Port -Port $FrontendPort -Name "frontend"
    Start-Sleep -Seconds 1
}

if ($Mode -eq "stop") {
    Show-Status
    exit 0
}

if ($Mode -eq "status") {
    Show-Status
    exit 0
}

$backendHealth = "http://127.0.0.1:$BackendPort/api/v1/health"
$frontendUrl = "http://localhost:$FrontendPort"

if ((Get-PortProcessIds -Port $BackendPort).Count -eq 0) {
    Write-Host "Starting backend on port $BackendPort..."
    Start-Process `
        -FilePath "python" `
        -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$BackendPort", "--reload") `
        -WorkingDirectory $BackendDir `
        -WindowStyle Hidden `
        -RedirectStandardOutput $BackendOut `
        -RedirectStandardError $BackendErr | Out-Null
} else {
    Write-Host "Backend already running on port $BackendPort."
}

if ((Get-PortProcessIds -Port $FrontendPort).Count -eq 0) {
    Write-Host "Starting frontend on port $FrontendPort..."
    Start-Process `
        -FilePath "npm.cmd" `
        -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1", "--port", "$FrontendPort") `
        -WorkingDirectory $FrontendDir `
        -WindowStyle Hidden `
        -RedirectStandardOutput $FrontendOut `
        -RedirectStandardError $FrontendErr | Out-Null
} else {
    Write-Host "Frontend already running on port $FrontendPort."
}

Wait-Http -Url $backendHealth -Name "Backend" | Out-Null
Wait-Http -Url $frontendUrl -Name "Frontend" | Out-Null

Write-Host ""
Write-Host "CloudGuard-AI dev environment"
Write-Host "Frontend: $frontendUrl"
Write-Host "Backend:  http://127.0.0.1:$BackendPort"
Write-Host ""
Write-Host "Useful commands:"
Write-Host "  .\dev.ps1 restart"
Write-Host "  .\dev.ps1 stop"
Write-Host "  .\dev.ps1 status"
Write-Host ""
Write-Host "Logs:"
Write-Host "  $BackendOut"
Write-Host "  $BackendErr"
Write-Host "  $FrontendOut"
Write-Host "  $FrontendErr"
