#!/usr/bin/env pwsh
# BeeBotOS Production Runner (Windows)
# Usage: .\beebotos-run.ps1 [gateway|web|beehub|all]

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Ensure data directories exist
$DataDir = Join-Path $ScriptDir "data"
$RunDir = Join-Path $DataDir "run"
$LogDir = Join-Path $DataDir "logs"
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Start-Gateway {
    Write-Host "Starting Gateway on port 8000..."
    $logFile = Join-Path $LogDir "gateway.log"
    $proc = Start-Process -FilePath (Join-Path $ScriptDir "beebotos-gateway.exe") `
        -RedirectStandardOutput $logFile -RedirectStandardError $logFile `
        -PassThru -WindowStyle Hidden
    $proc.Id | Set-Content (Join-Path $RunDir "gateway.pid") -NoNewline
    Start-Sleep -Seconds 1
    try {
        $check = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        if ($check) {
            Write-Host "Gateway started (PID: $($proc.Id))"
        }
    } catch {
        Write-Host "Gateway failed to start. Check $logFile"
    }
}

function Start-Web {
    Write-Host "Starting Web Server on port 8090..."
    $logFile = Join-Path $LogDir "web.log"
    $proc = Start-Process -FilePath (Join-Path $ScriptDir "web-server.exe") `
        -RedirectStandardOutput $logFile -RedirectStandardError $logFile `
        -PassThru -WindowStyle Hidden
    $proc.Id | Set-Content (Join-Path $RunDir "web.pid") -NoNewline
    Start-Sleep -Seconds 1
    try {
        $check = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        if ($check) {
            Write-Host "Web Server started (PID: $($proc.Id))"
        }
    } catch {
        Write-Host "Web Server failed to start. Check $logFile"
    }
}

function Start-BeeHub {
    $beehubPath = Join-Path $ScriptDir "beehub.exe"
    if (-not (Test-Path $beehubPath)) {
        Write-Host "BeeHub binary not found, skipping."
        return
    }
    Write-Host "Starting BeeHub on port 8080..."
    $logFile = Join-Path $LogDir "beehub.log"
    $proc = Start-Process -FilePath $beehubPath `
        -RedirectStandardOutput $logFile -RedirectStandardError $logFile `
        -PassThru -WindowStyle Hidden
    $proc.Id | Set-Content (Join-Path $RunDir "beehub.pid") -NoNewline
    Start-Sleep -Seconds 1
    try {
        $check = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        if ($check) {
            Write-Host "BeeHub started (PID: $($proc.Id))"
        }
    } catch {
        Write-Host "BeeHub failed to start. Check $logFile"
    }
}

$target = if ($args.Count -gt 0) { $args[0] } else { "all" }

switch ($target) {
    "gateway" { Start-Gateway }
    "web" { Start-Web }
    "beehub" { Start-BeeHub }
    "all" {
        Start-Gateway
        Start-Web
        Start-BeeHub
    }
    default {
        Write-Host "Usage: $($MyInvocation.MyCommand.Name) [gateway|web|beehub|all]"
        exit 1
    }
}
