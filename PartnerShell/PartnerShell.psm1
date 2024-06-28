MODULES_AVAILABLE = [
    "Connect-ExchangeOnline",
    "Connect-IPPSSession",
    "Connect-MicrosoftTeams"
]

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

function Connect-ExchangeOnline-ViaPartner {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Client Tenant ID / Domain")]
        [String] $Tenant
        [Parameter(Mandatory=$true, HelpMessage="Current Partner Authentication Result")]
        [Microsoft.Identity.Client.AuthenticationResult] $authResult
    )
    Process {
        $token = New-PartnerAccessToken -ApplicationId "fb78d390-0c51-40cd-8e17-fdbfab77341b" -RefreshToken $authResult.RefreshToken -Scopes "https://outlook.office365.com/powershell-liveid/" -Tenant $Tenant
        Connect-ExchangeOnline -AccessToken $token.AccessToken
    }
}

function Connect-IPPSSession-ViaPartner {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Client Tenant ID / Domain")]
        [String] $Tenant
        [Parameter(Mandatory=$true, HelpMessage="Current Partner Authentication Result")]
        [Microsoft.Identity.Client.AuthenticationResult] $authResult
    )
    Process {
        $token = New-PartnerAccessToken -ApplicationId "fb78d390-0c51-40cd-8e17-fdbfab77341b" -RefreshToken $authResult.RefreshToken -Scopes "https://ps.compliance.protection.outlook.com/PowerShell-LiveId" -Tenant $Tenant
        Connect-ExchangeOnline -ConnectionUri "https://ps.compliance.protection.outlook.com/PowerShell-LiveId" -AccessToken $token.AccessToken
    }
}

function Connect-MicrosoftTeams-ViaPartner {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Client Tenant ID / Domain")]
        [String] $Tenant
        [Parameter(Mandatory=$true, HelpMessage="Current Partner Authentication Result")]
        [Microsoft.Identity.Client.AuthenticationResult] $authResult
    )
    Process {
        $graphToken = New-PartnerAccessToken -ApplicationId "12128f48-ec9e-42f0-b203-ea49fb6af367" -RefreshToken $authResult.RefreshToken -Scopes "https://graph.microsoft.com/.default" -Tenant $Tenant
        $teamsToken = New-PartnerAccessToken -ApplicationId "12128f48-ec9e-42f0-b203-ea49fb6af367" -RefreshToken $graphToken.RefreshToken -Scopes "https://graph.microsoft.com/.default" -Tenant $Tenant
        Connect-MicrosoftTeams -AccessTokens [$graphToken.AccessToken, $teamsToken.AccessToken]
    }
}

function Connect-MgGraph-ViaPartner { #FIXME: Needs work
    param (
        [Parameter(Mandatory=$true, HelpMessage="Client Tenant ID / Domain")]
        [String] $Tenant
        [Parameter(Mandatory=$true, HelpMessage="Current Partner Authentication Result")]
        [Microsoft.Identity.Client.AuthenticationResult] $authResult
    )
    Process {
        Write-Host @"
        Due to the nature of the Micrsoft Graph plugin and the functionality of Graph itself,
        An application with a set of API permissions must be instantiated in the client tenant.
"@
        do {
            $scopes = Read-Host "Please enter a list of API permissions, separated by commas"
            Write-Output "List of scopes: $scopes"
            $Confirmation = Read-Host "Confirm? (y/N)"
        } while ($Confirmation.ToLower -ne "y")

    }
}

function PartnerShell {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, HelpMessage="Tenant ID / Domain'")]
        [String] $Tenant
    )
    Process {

        # Authenticate to Partner Center and store token information
        $token = New-PartnerAccessToken -ApplicationId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" -Scopes "https://api.partnercenter.microsoft.com/user_impersonation"
        Connect-PartnerCenter -AccessToken $token.AccessToken

        # Acquire all customers associated to partner
        $customers = Get-PartnerCustomer
        
        # Determine client tenant to be authenticated into
        if ($PSBoundParameters.ContainsKey("Tenant")) {
            try {
                $tenantId = Get-TenantID $Tenant
            }
            catch {
                Write-Output "The specified tenant ID / domain threw an error when I attempted to verify it."
                Write-Error -Message $_ -ErrorAction Stop
            }
        }

        # List available modules to authenticate into and prompt for selected modules
        


    }
}