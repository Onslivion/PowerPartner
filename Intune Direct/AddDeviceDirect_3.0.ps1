# Constants

# KEEP THE FOLLOWING CONSISTENT BETWEEN TENANTS! NO CLUTTER!

# Application ID as shown in Entra ID. This is for both the partner tenant and the intended tenant.
$APP_ID = ''
# Friendly / Display name of the application (as shown in Entra ID)
$APP_NAME = ""

# Group tag to be used in Autopilot (we use this for device deployment profile assignment via dynamic device security groups)
$DEFAULT_GROUP_TAG = "Default"





# SCRIPT

# Credit to https://tminus365.com/my-automations-break-with-gdap-the-fix/ for the inspiration / Partner Center implementation to accomodate for GDAP

function Get-TenantID { # Credit to Daniel Kåven | https://teams.se/powershell-script-find-a-microsoft-365-tenantid/
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="The domain name of the tenant")]
        [String]$domain
    )
    $request = Invoke-WebRequest -Uri https://login.windows.net/$domain/.well-known/openid-configuration -UseBasicParsing
    $data = ConvertFrom-Json $request.Content
    return $Data.token_endpoint.split('/')[3]
}

function Get-HWID { # Credit to authors of https://www.powershellgallery.com/packages/Get-WindowsAutoPilotInfo/3.9

        $bad = $false

        $session = New-CimSession

        # Get the common properties.
        Write-Verbose "Checking $comp"
        $serial = (Get-CimInstance -CimSession $session -Class Win32_BIOS).SerialNumber

        # Get the hash (if available)
        $devDetail = (Get-CimInstance -CimSession $session -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")
        if ($devDetail)
        {
            $hash = $devDetail.DeviceHardwareData
        }
        else
        {
            $bad = $true
            $hash = ""
        }

        # Getting the PKID is generally problematic for anyone other than OEMs, so let's skip it here
        $product = ""

        # Depending on the format requested, create the necessary object
        # Create a pipeline object
        $c = New-Object psobject -Property @{
            "Device Serial Number" = $serial
            "Windows Product ID" = $product
            "Hardware Hash" = $hash
        }

        # Write the object to the pipeline or array
        if ($bad)
        {
            # Report an error when the hash isn't available
            Write-Error -Message "Unable to retrieve device hardware data (hash) from computer $comp" -Category DeviceError
        }
        
        Write-Host "Gathered details for device with serial number: $serial"

        Remove-CimSession $session

        return $c

}

function Wait-UntilComplete { # Credit to authors of https://www.powershellgallery.com/packages/Get-WindowsAutoPilotInfo/3.9

    param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="Object representing the Autopilot device identity")]  $Device
    )
        #Import Check
        $importStart = Get-Date
        do {
            $processed = $false
            $importCheck = Get-AutopilotImportedDevice -id $Device.id
            if ($importCheck.state.deviceImportStatus -eq "unknown") {
                Write-Host "Awaiting device import..."
                Start-Sleep 10
            }
            else {
                $processed = $true
            }

        } while (!$processed)

        $importDuration = (Get-Date) - $importStart
        $importSeconds = [Math]::Ceiling($importDuration.TotalSeconds)

        Write-Host "Device imported successfully. Elapsed time to complete import: $importSeconds seconds"
        
        # Sync Check
        $syncStart = Get-Date
        do {
            $processed = $false
            $syncCheck = Get-AutopilotDevice -id $importCheck.state.deviceRegistrationId
            if (!$syncCheck) {
                Write-Host "Awaiting Intune sync..."
                Start-Sleep 15
            }
            else {
                $processed = $true
            }
        } while (!$processed)
        $syncDuration = (Get-Date) - $syncStart
        $syncSeconds = [Math]::Ceiling($syncDuration.TotalSeconds)
        Write-Host "Devices synced. Elapsed time to complete sync: $syncSeconds seconds"
        
        # Assignment Check
        $assignStart = Get-Date
        do {
            $processed = $false
            $assignCheck = $(Get-AutopilotDevice -Expand -id $importCheck.state.deviceRegistrationId).deploymentProfileAssignmentStatus.StartsWith("assigned")
            if (!$assignCheck) {
                Write-Host "Awaiting assignment to a deployment profile..."
                Start-Sleep 30
            }
            else {
                $processed = $true
            }
        } while (!$processed)
        $assignDuration = (Get-Date) - $assignStart
        $assignSeconds = [Math]::Ceiling($assignDuration.TotalSeconds)
        Write-Host "Profile has been assigned to the device. Elapsed time to complete assignment: $assignSeconds seconds"

}

# Install necessary modules

Install-Module -Name WindowsAutoPilotIntune -Force
Install-Module -Name PartnerCenter -Force

# Connect to Partner Center

Write-Host "Opening a window to sign in to Microsoft Partner Center via internal Intune Deployment app registration. Please enter your credentials."
try {
    $partnerToken = New-PartnerAccessToken -ApplicationId "f528e2f0-0f2f-4423-a647-c56c8213d6e5" -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation' -UseAuthorizationCode
    Connect-PartnerCenter -AccessToken $partnerToken.AccessToken
}
catch {
    Write-Host "There was a problem signing in to Microsoft Partner Center. Contact an administrator."
    exit
}

# Obtain tenant ID, group tag (if applicable), and assigned user (if applicable)

do {
    $tenantDomain = Read-Host -Prompt "Please enter a domain belonging to the intended tenant"
    try {
        $tenantId = Get-TenantID $tenantDomain
        Write-Host "$($tenantDomain) | $($tenantId)"
        do {
            $Confirmation = Read-Host -Prompt "Is this correct? (y/N)"
        } while (!(($Confirmation.ToLower() -eq "y" ) -or ($Confirmation.ToLower() -eq "n") -or (!$Confirmation)))
    }
    catch {
        Write-Host "Domain could not be found."
        $Confirmation = "N"
    }
} while ($Confirmation.ToLower() -ne "y")

do {
    $GroupTag = Read-Host -Prompt "Enter the group tag of the device (Default: $($DEFAULT_GROUP_TAG))"
    if (!$GroupTag) {
        $GroupTag = $DEFAULT_GROUP_TAG
        break
    }
    else {
        do {
            $Confirmation = Read-Host -Prompt "Group Tag: '$($GroupTag)' | Correct? (y/N)"
        } while (!(($Confirmation.ToLower() -eq "y" ) -or ($Confirmation.ToLower() -eq "n") -or (!$Confirmation)))
    }
} while ($Confirmation.ToLower() -ne "y")

do {
    $AssignedUser = Read-Host -Prompt "Enter the UPN of the assigned user of the device (Press enter if none)"
    if (!$AssignedUser) {
        break
    }
    else {
        do {
            $Confirmation = Read-Host -Prompt "Assigned User: '$($AssignedUser)' | Correct? (y/N)"
        } while (!(($Confirmation.ToLower() -eq "y" ) -or ($Confirmation.ToLower() -eq "n") -or (!$Confirmation)))
    }
} while ($Confirmation.ToLower() -ne "y")

# Verify there is an "Intune Deployment" partner-managed application in the tenant with the necessary permissions for enrolling devices in Autopilot

Write-Host "Verifying there is an $($APP_NAME) registration in the intended tenant"
$grant = New-Object -TypeName Microsoft.Store.PartnerCenter.Models.ApplicationConsents.ApplicationGrant
$grant.EnterpriseApplicationId = '00000003-0000-0000-c000-000000000000'
$grant.Scope = "DeviceManagementManagedDevices.ReadWrite.All,DeviceManagementServiceConfig.ReadWrite.All"
try {
    New-PartnerCustomerApplicationConsent -ApplicationGrants @($grant) -CustomerId $tenantId -ApplicationId $APP_ID -DisplayName $APP_NAME 
}
catch [PartnerException] {
    if ($_ -eq ("Permission entry already exists.")) {
        Write-Host "The application registration already exists in the tenant. Proceeding."
    }
}
catch {
    Write-Host "An unknown error occurred verifying the app registration's presence in the intended tenant."
}

# Obtain access token

Write-Host "Authenticating to tenant $($tenantDomain) | $($tenantId) through Microsoft Partner Network using the app registration $($APP_NAME) | $($APP_ID)"
$authReq = New-PartnerAccessToken -ApplicationId $APP_ID -RefreshToken $partnerToken.RefreshToken -Scopes "https://graph.microsoft.com/.default" -Tenant $tenantId 
$token = ConvertTo-SecureString -Force -AsPlainText $authReq.AccessToken

# Add device to tenant

Write-Host "Initiating Intune Enrollment"

Connect-MgGraph -AccessToken $token 

$device = Get-HWID
$importIdentity = Add-AutopilotImportedDevice -serialNumber $device."Device Serial Number" -hardwareIdentifier $device."Hardware Hash" -groupTag $GroupTag -assignedUser $AssignedUser
Wait-UntilComplete -Device $importIdentity

# Remove tracks

Uninstall-Module -Name PartnerCenter
Uninstall-Module -Name WindowsAutoPilotIntune
