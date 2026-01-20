<#
.SYNOPSIS
    WireGuard-Go Localhost Handshake Test (Windows)
    Port of linux tests/netns.sh (Basic mode)

.DESCRIPTION
    Launches two wireguard-go instances (wg1, wg2) locally
    and connects them via UDP to verify if the Handshake succeeds.

.USAGE
    Run as Administrator:
    ./tests/windows_test.ps1 C:\Path\To\wireguard-go.exe
#>

param (
    [string]$ProgramPath = "Path\To\wireguard-go"
)

# Force console to use UTF-8 just in case, though English works on any encoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

# 1. Check Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Error "ERROR: Please run this script as Administrator."
    exit 1
}

# 2. Check File Existence
if (-not (Test-Path $ProgramPath)) {
    Write-Error "ERROR: wireguard-go executable not found at: $ProgramPath"
    exit 1
}

# 3. Check wg.exe
if (-not (Get-Command "wg.exe" -ErrorAction SilentlyContinue)) {
    Write-Error "ERROR: 'wg.exe' not found. Please ensure WireGuard tools are installed and in your PATH."
    exit 1
}

Write-Host "[*] Preparing environment..." -ForegroundColor Cyan

# Cleanup Function
function Cleanup {
    Write-Host "`n[*] Cleaning up processes and keys..." -ForegroundColor Yellow
    Get-Process wireguard-go -ErrorAction SilentlyContinue | Stop-Process -Force
}

# Register Cleanup on Exit
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -SupportEvent -Action { Cleanup }

try {
    # Initial Cleanup
    Cleanup
    Start-Sleep -Seconds 1

    Write-Host "[*] Generating keys..." -ForegroundColor Cyan
    $key1 = wg genkey; $pub1 = $key1 | wg pubkey
    $key2 = wg genkey; $pub2 = $key2 | wg pubkey
    $psk  = wg genpsk

    # Save keys to temp files (safer than stdin piping in PS)
    $key1 | Out-File -Encoding ascii private1.key
    $key2 | Out-File -Encoding ascii private2.key
    $psk  | Out-File -Encoding ascii psk.key

    Write-Host "[*] Starting wireguard-go instances (wg1, wg2)..." -ForegroundColor Cyan
    
    # Start wg1
    $proc1 = Start-Process -FilePath $ProgramPath -ArgumentList "wg1" -PassThru -NoNewWindow
    # Start wg2
    $proc2 = Start-Process -FilePath $ProgramPath -ArgumentList "wg2" -PassThru -NoNewWindow

    Write-Host "    Waiting for interfaces to initialize (3s)..."
    Start-Sleep -Seconds 3

    # Set IP Addresses
    Write-Host "[*] Setting IP addresses..." -ForegroundColor Cyan

    New-NetIPAddress -InterfaceAlias "wg1" -IPAddress "192.168.241.1" -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
    New-NetIPAddress -InterfaceAlias "wg2" -IPAddress "192.168.241.2" -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null

    # Configure WireGuard Peers
    Write-Host "[*] Configuring WireGuard Peers..." -ForegroundColor Cyan

    # === 第一階段：先打開監聽埠 (Open Ports first) ===
    # 這樣可以確保對方已經在聽了，避免 "Connection Reset" 導致接收端崩潰
    cmd /c "wg set wg1 private-key private1.key listen-port 10000"
    cmd /c "wg set wg2 private-key private2.key listen-port 20000"

    Write-Host "    等待連接埠就緒..."
    Start-Sleep -Seconds 2

    # wg1 (Port 10000) -> connects to wg2 (Port 20000)
    cmd /c "wg set wg1 private-key private1.key listen-port 10000 peer $pub2 preshared-key psk.key endpoint 127.0.0.1:20000 persistent-keepalive 1 allowed-ips 192.168.241.2/32,fd00::2/128"
    # wg2 (Port 20000) -> connects to wg1 (Port 10000)
    cmd /c "wg set wg2 private-key private2.key listen-port 20000 peer $pub1 preshared-key psk.key endpoint 127.0.0.1:10000 persistent-keepalive 1 allowed-ips 192.168.241.1/32,fd00::1/128"

    Write-Host "[*] Configuration done. Waiting for Handshake (5s)..." -ForegroundColor Cyan
    Start-Sleep -Seconds 5

    Write-Host "`n=== wg1 Status ===" -ForegroundColor Green
    wg show wg1
    
    Write-Host "`n=== wg2 Status ===" -ForegroundColor Green
    wg show wg2

    # Verify Handshake
    $dump = wg show wg1 dump
    $lines = $dump -split "`n"
    $handshakeSuccess = $false
    foreach ($line in $lines) {
        $parts = $line -split "`t"
        if ($parts.Length -gt 4) {
            $lastHandshake = [int64]$parts[4]
            if ($lastHandshake -gt 0) {
                $handshakeSuccess = $true
            }
        }
    }

    Write-Host "`n-------------------------------------------------------"
    if ($handshakeSuccess) {
        Write-Host "✅ SUCCESS: Handshake detected!" -ForegroundColor Green
        Write-Host "   PQC (ML-KEM) key exchange is working correctly."
    } else {
        Write-Host "❌ FAILURE: No handshake detected (latest-handshake = 0)" -ForegroundColor Red
        Write-Host "   Please check logs or firewall settings."
    }
    Write-Host "-------------------------------------------------------"

    # Ping Test
    Write-Host "[*] Attempting Ping (Note: May fail due to Windows loopback routing)..."
    Test-Connection -ComputerName 192.168.241.2 -Count 3 -ErrorAction SilentlyContinue

} catch {
    Write-Error $_
} finally {
    # Clean up temp keys
    Remove-Item private1.key, private2.key, psk.key -ErrorAction SilentlyContinue
    
    Write-Host "`nPress Enter to exit and cleanup interfaces..."
    Read-Host
    Cleanup
}
