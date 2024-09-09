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

$banner = @'
==============================================================
Microsoft RDP Client Deployment Script for Windows Server 2022

                            Version 1.0
                         Author: TheWinDev
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
    $outputFilePath = "C:\WebClient.zip"
    [IO.File]::WriteAllBytes($outputFilePath, [Convert]::FromBase64String($webClientPackage))

    $webClientPath = "C:\WebClient"

    # Download the file
    Invoke-WebRequest -Uri $webClientUrl -OutFile $webClientZip

    # Verify the file is a valid ZIP
    if (-not (Test-Path $webClientZip)) {
        throw "Download failed. File not found."
    }

    # Try to expand the archive
    try {
        Expand-Archive -Path $webClientZip -DestinationPath $webClientPath -Force
    }
    catch {
        throw "Failed to expand the archive. The file may be corrupted."
    }

    # Install the RD Web Client package
    Install-RDWebClientPackage -Path $webClientPath
}

# Deploy the RD Web Client
Write-Host "Deploying RD Web Client..."
TryExecute -ScriptBlock {
    Publish-RDWebClientPackage -Latest
}

# Configure the Remote Desktop Gateway with certificate at C:\RDPWEB
$GatewayCertPath = "C:\RDPWEB\certificate.pfx"  # Specify your certificate path
$CertPassword = ConvertTo-SecureString "h6sv&RG56vbda78sh6d7js" -AsPlainText -Force

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