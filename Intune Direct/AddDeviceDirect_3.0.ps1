# Constants

# The following 3 constants are required for the script to work.

# Application ID of the application used to sign in to to access Partner Portal
# Ensure the principal is in the AdminAgents group, and has the user_impersonation permission
$PARTNER_APP_ID = ''
# Application ID of the application to implement / consent in the intended tenant.
# It's a UUID in a different tenant - use the same one if you'd like or generate a random one.
$APP_ID = ''
# Friendly / Display name of the application (as shown in Entra ID)
$APP_NAME = ""

# Default intended tenant domain or ID to use (this is useful for mass deployment to a single tenant)
$DEFAULT_TENANT = ""
# Group tag to be used in Autopilot. (we use this for device deployment profile assignment via dynamic device security groups)
$DEFAULT_GROUP_TAG = "Default"

# Enable assigned users entry
$ENABLE_ASSIGN_USER = $false
# Enable device code authentication
# Prompts the user to enter a code at https://microsoft.com/devicelogin instead of opening a new browser window
# NOTE: Public client flows in the tenant app registration (in "Authentication") must be enabled, else this will error out.
$DEVICE_CODE_AUTH = $true
# Force all defaults.
# This setting will do the following;
# - Use the default value (defined above) without prompting the user
# - If no default is present, prompt the user for input
$FORCE_DEFAULTS = $true




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

# Check if required parameters are filled

if (!($PARTNER_APP_ID -or $APP_ID -or $APP_NAME)) {
    Write-Error "The script is missing one of the necessary constants: PARTNER_APP_ID, APP_ID, or APP_NAME"
}

# Install necessary modules

Install-Module -Name WindowsAutoPilotIntune -Force
Install-Module -Name PartnerCenter -Force

# Connect to Partner Center
Write-Host "Initiating interactive sign-in. You will be signing in to Microsoft Partner Center, under the application name $($APP_ID)."
try {
    if ($DEVICE_CODE_AUTH) {
        $partnerToken = New-PartnerAccessToken -ApplicationId $PARTNER_APP_ID -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation' -UseDeviceAuthentication
    }
    else {
        $partnerToken = New-PartnerAccessToken -ApplicationId $PARTNER_APP_ID -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation' -UseAuthorizationCode
    }
    Connect-PartnerCenter -AccessToken $partnerToken.AccessToken
}
catch {
    Write-Host "There was a problem signing in to Microsoft Partner Center. Verify your access and the status of Partner Center."
    exit
}

# Obtain tenant ID, group tag and assigned user
if ($DEFAULT_TENANT -and !$FORCE_DEFAULTS) {
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
}
else {
    Write-Host "Using default tenant $($DEFAULT_TENANT)"
    $tenantId = Get-TenantID $DEFAULT_TENANT
}

if ($DEFAULT_GROUP_TAG -and !$FORCE_DEFAULTS) {
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
}
else {
    Write-Host "Using default group tag $($DEFAULT_GROUP_TAG)"
    $GroupTag = $DEFAULT_GROUP_TAG 
}

if ($ENABLE_ASSIGN_USER) {
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
}
else {
    Write-Host "User assignment disabled - skipping user assignment"
}

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
