$ErrorActionPreference = "Stop"

function TryExecute {
    param (
        [scriptblock]$ScriptBlock,
        [int]$Retries = 3
    )

    for ($i = 0; $i -lt $Retries; $i++) {
        try {
            & $ScriptBlock
            return
        }
        catch {
            Write-Warning "Attempt $($i + 1) failed: $_"
            if ($i -eq $Retries - 1) {
                throw "All attempts failed."
            }
        }
    }
}

function GenerateSecurePassword {
    param (
        [int]$Length = 16
    )

    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
    -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

$banner = @'
==============================================================
Microsoft RDP Client Deployment Script for Windows Server 2022

                          Version 1.0
==============================================================
'@
Write-Host $banner

# Admin checks
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script!`nPlease run as Administrator."
    exit
}

# Update PowerShellGet to the latest version (if needed)
TryExecute -ScriptBlock {
    Install-PackageProvider -Name NuGet -Force -Verbose
    Install-Module -Name PowerShellGet -Force -Verbose
}

# Ensure the required roles and features for Remote Desktop Services and Remote Desktop Web Access are installed
Write-Host "Installing Remote Desktop Services and Web Access roles..."
TryExecute -ScriptBlock {
    Install-WindowsFeature -Name Remote-Desktop-Services, RDS-RD-Server, RDS-Web-Access, RDS-Gateway, RDS-Licensing -IncludeManagementTools -Verbose
}

# Install IIS (required for RD Web Access)
Write-Host "Installing IIS..."
TryExecute -ScriptBlock {
    Install-WindowsFeature -Name Web-Server, Web-ASP, Web-Asp-Net45, Web-Mgmt-Console, Web-Scripting-Tools -IncludeManagementTools -Verbose
}

# Install Remote Desktop Web Client (HTML5 client)
Write-Host "Installing Remote Desktop Web Client..."
TryExecute -ScriptBlock {
    $repuUrl = "https://api.github.com/repos/twdtech/rdp-webclient/releases/latest"
    $webClientZip = "RDWebClient.zip"
    $webClientPath = "C:\WebClient"

    $releaseInfo = Invoke-RequestMethod -Uri $repuUrl -headers @{ "User-Agent" = "PowerShell" }
    $webClientUrl = $releaseInfo.assets » Where-Object { $_.name -match "\.zip$" } | Select-Object -ExpandProperty browser_download_url

    Invoke-WebRequest -uri $webClientUrl -OutFile $webClientZip

    if (-not (Test-Path $webClientZip)) {
        throw "Download failed. File coudldn't be downloaded!"
    }

    try {
        Expant-Archive -Path $webClientZip -DestinationPath $webClientPath -Force
    } catch {
        throw "Failed to expand archive. File my be corrupted!"
    }

    Install-RDWebClientPackage -path $webClientPath
}

# Deploy the RD Web Client
Write-Host "Deploying RD Web Client..."
TryExecute -ScriptBlock {
    Publish-RDWebClientPackage -Latest
}

# Configure the Remote Desktop Gateway with certificate at C:\RDPWEB
$GatewayCertPath = "C:\RDPWEB\certificate.pfx"  # Specify your certificate path
$CertPassword = GenerateSecurePassword | ConvertTo-SecureString -AsPlainText -Force

# Save the password to a TXT file
$CertPasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertPassword))
$PasswordFilePath = "C:\RDPWEB\certificate_password.txt"
Set-Content -Path $PasswordFilePath -Value $CertPasswordPlainText

Write-Host "Configuring Remote Desktop Gateway..."
TryExecute -ScriptBlock {
    Import-PfxCertificate -FilePath $GatewayCertPath -CertStoreLocation Cert:\LocalMachine\My -Password $CertPassword
}

# Configure RD Gateway authentication
TryExecute -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppSrv\WebAccess" -Name "RDGWAuthMode" -Value 1
}

# Configure Remote Desktop Licensing on the local machine
$LicenseServer = $env:COMPUTERNAME  # Local machine as the license server
Write-Host "Configuring Remote Desktop Licensing on local machine..."
TryExecute -ScriptBlock {
    Add-RDLicenseServer -LicenseServer $LicenseServer
}

# Enable RD Web Access via Group Policy (optional)
Write-Host "Configuring Group Policy for RD Web Access..."
TryExecute -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "WebAccessEnabled" -Value 1
}

# Restart services to apply changes
Write-Host "Restarting services..."
TryExecute -ScriptBlock {
    Restart-Service -Name "TermService"
    Restart-Service -Name "RDWebAccess"
    Restart-Service -Name "RDGateway"
}

# Final check for installed roles and features
Write-Host "Verifying installation..."
TryExecute -ScriptBlock {
    Get-WindowsFeature | Where-Object { $_.Installed -eq $true } | Out-GridView
}

Write-Host "Remote Desktop Web Client has been successfully deployed."
Write-Host "The certificate password has been saved to $PasswordFilePath."
