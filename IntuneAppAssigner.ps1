<#PSScriptInfo

.VERSION 0.4.4
.GUID 71c3b7d1-f435-4f11-b7c0-4acf00b7daca
.AUTHOR Nick Benton
.COMPANYNAME
.COPYRIGHT GPL
.TAGS Graph Intune Windows Android iOS macOS Apps
.LICENSEURI https://github.com/ennnbeee/IntuneAppAssigner/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/IntuneAppAssigner
.ICONURI https://raw.githubusercontent.com/ennnbeee/IntuneAppAssigner/refs/heads/main/img/iaa-icon.png
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication Microsoft.PowerShell.ConsoleGuiTools
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.4.4 - Logic improvements and bug fixes
v0.4.3 - Option to export app assignments
v0.4.2 - Logic improvements
v0.4.1 - Bug fixes
v0.4.0 - Updated to include assignment review mode and uninstall intent
v0.3.0 - Support for Windows apps
v0.2.1 - Bug Fixes
v0.2.0 - Supports macOS apps
v0.1.3 - Improvements to App Config creation logic.
v0.1.2 - Bug Fixes
v0.1.1 - Allow for creation of App Config policies.
v0.1.0 - Initial release.

.PRIVATEDATA
#>

<#
.SYNOPSIS
Allows for bulk assignment changes to Intune apps.

.DESCRIPTION
The IntuneAppAssigner script is a PowerShell tool designed to facilitate the bulk assignment of mobile applications within Microsoft Intune.
It provides an interactive interface for administrators to select applications, define assignment parameters, and apply these settings across user and device groups efficiently.

.PARAMETER appConfigPrefix
Used to specify the prefix of the Android or iOS/iPadOS App Config policies, if not configured the default prefix of 'AppConfig-' is used.

.PARAMETER tenantId
Provide the Id of the Entra ID tenant to connect to.

.PARAMETER appId
Provide the Id of the Entra App registration to be used for authentication.

.PARAMETER appSecret
Provide the App secret to allow for authentication to graph

.EXAMPLE
Interactive Authentication
.\IntuneAppAssigner.ps1

.EXAMPLE
Pass through Authentication
.\IntuneAppAssigner.ps1 -tenantId '437e8ffb-3030-469a-99da-e5b527908099'

.EXAMPLE
App Authentication
.\IntuneAppAssigner.ps1 -tenantId '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e72-baaf-a35126464d67' -appSecret 'g708Q~uof4xo9dU_1EjGQIuUr0UyBHNZmY2m3dy6'

#>

[CmdletBinding(DefaultParameterSetName = 'Default')]

param(

    [Parameter(Mandatory = $false, HelpMessage = 'Specify an optional profile name prefix for Android and iOS App Config profiles')]
    [String]$appConfigPrefix,

    [Parameter(Mandatory = $false, HelpMessage = 'Provide the Id of the Entra ID tenant to connect to')]
    [ValidateLength(36, 36)]
    [String]$tenantId,

    [Parameter(Mandatory = $false, ParameterSetName = 'appAuth', HelpMessage = 'Provide the Id of the Entra App registration to be used for authentication')]
    [ValidateLength(36, 36)]
    [String]$appId,

    [Parameter(Mandatory = $true, ParameterSetName = 'appAuth', HelpMessage = 'Provide the App secret to allow for authentication to graph')]
    [ValidateNotNullOrEmpty()]
    [String]$appSecret

)

#region Functions
function Connect-ToGraph {

    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.

.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.

.PARAMETER TenantId
Specifies the tenantId from Entra ID to which to authenticate.

.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.

.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.

.EXAMPLE
Connect-ToGraph -tenantId $tenantId -appId $app -appSecret $secret

#>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$tenantId,
        [Parameter(Mandatory = $false)] [string]$appId,
        [Parameter(Mandatory = $false)] [string]$appSecret,
        [Parameter(Mandatory = $false)] [string[]]$scopes
    )

    process {
        Import-Module Microsoft.Graph.Authentication
        $version = (Get-Module microsoft.graph.authentication | Select-Object -ExpandProperty Version).major

        if ($AppId -ne '') {
            $body = @{
                grant_type    = 'client_credentials';
                client_id     = $appId;
                client_secret = $appSecret;
                scope         = 'https://graph.microsoft.com/.default';
            }

            $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
            $accessToken = $response.access_token

            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
                $accessTokenFinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
                $accessTokenFinal = $accessToken
            }
            $graph = Connect-MgGraph -AccessToken $accessTokenFinal
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -TenantId $tenantId -Scopes $scopes
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}
function Test-JSONData {

    <#
    .SYNOPSIS
    Validates JSON data format.

    .DESCRIPTION
    The Test-JSONData function checks if the provided JSON string is in a valid format.

    .PARAMETER JSON
    Specifies the JSON string to validate.

    .EXAMPLE
    Test-JSONData -JSON '{"key": "value"}'
    #>

    param (
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $TestJSON | Out-Null
        $validJson = $true
    }
    catch {
        $validJson = $false
        $_.ErrorDetails.Message
    }
    if (!$validJson) {
        Write-Host "Provided JSON isn't in valid JSON format" -ForegroundColor Red
        break
    }

}
function Get-MobileApp() {

    <#
    .SYNOPSIS
    Allows for searching for mobile apps or getting mobile app information from Intune.

    .DESCRIPTION
    This function allows for searching for mobile apps or getting mobile app information from Intune.

    .PARAMETER Id
    Specifies the Id of the mobile app to retrieve. If not provided, all mobile apps will be returned.

    #>

    [cmdletbinding()]

    param (
        $Id
    )

    $graphApiVersion = 'Beta'
    if ($null -ne $Id) {
        $Resource = "deviceAppManagement/mobileApps('$Id')"
    }
    else {
        $Resource = 'deviceAppManagement/mobileApps'
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        if ($null -ne $Id) {
            Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
        }
        else {
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        }
    }
    catch {
        Write-Host "❌ Graph request to $uri failed" -ForegroundColor Red
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        }
        else {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        throw
    }
}
function Get-AssignmentFilter() {

    <#
    .SYNOPSIS
    Allows for getting assignment filters from Intune.

    .DESCRIPTION
    This function allows for getting assignment filters from Intune.

    .PARAMETER Id
    Specifies the Id of the assignment filter to retrieve. If not provided, all assignment filters will be returned.

    #>

    param
    (

        [parameter(Mandatory = $false)]
        [string]$Id
    )

    $graphApiVersion = 'beta'

    try {
        if ($Id) {
            $Resource = "deviceManagement/assignmentFilters/$Id"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
        }
        else {
            $Resource = 'deviceManagement/assignmentFilters'
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        }

    }
    catch {
        Write-Host "❌ Graph request to $uri failed" -ForegroundColor Red
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        }
        else {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        throw
    }
}
function Get-MDMGroup() {

    <#
    .SYNOPSIS
    Allows for searching for groups or getting group information from Entra ID.

    .DESCRIPTION
    This function allows for searching for groups or getting group information from Entra ID.

    .PARAMETER groupName
    Specifies a search term for the group name. If not provided, all groups will be returned.

    .PARAMETER Id
    Specifies the Id of the group to retrieve. If not provided, all groups apps will be returned.


    #>

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $false)]
        [string]$groupName,

        [parameter(Mandatory = $false)]
        [string]$Id
    )

    $graphApiVersion = 'beta'
    $Resource = 'groups'

    try {
        if ($groupName) {
            $searchTerm = 'search="displayName:' + $groupName + '"'
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?$searchTerm"
        }
        elseif ($Id) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$Id"
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        }

        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = 'eventual' } -OutputType PSObject

        if ($null -ne $graphResults.value) {
            $results = @()
            $results += $graphResults.value

            $pages = $graphResults.'@odata.nextLink'
            while ($null -ne $pages) {

                $additional = Invoke-MgGraphRequest -Uri $pages -Method Get -Headers @{ConsistencyLevel = 'eventual' } -OutputType PSObject

                if ($pages) {
                    $pages = $additional.'@odata.nextLink'
                }
                $results += $additional.value
            }
            $results
        }
        else {
            $graphResults
        }

    }
    catch {
        Write-Host "❌ Graph request to $uri failed" -ForegroundColor Red
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        }
        else {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        throw
    }
}
function Get-AppAssignment() {

    <#
    .SYNOPSIS
    Allows for getting app assignments from Intune.

    .DESCRIPTION
    This function allows for getting app assignments from Intune.

    .PARAMETER Id
    Specifies the Id of the mobile app to retrieve assignments for.

    #>

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $Id
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/?`$expand=categories,assignments"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
    catch {
        Write-Host "❌ Graph request to $uri failed" -ForegroundColor Red
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        }
        else {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        throw
    }
}
function Remove-AppAssignment() {

    <#
    .SYNOPSIS
    Allows for removing app assignments from Intune.

    .DESCRIPTION
    This function allows for removing app assignments from Intune.

    .PARAMETER Id
    Specifies the Id of the mobile app to remove the assignment from.

    .PARAMETER AssignmentId
    Specifies the Id of the assignment to remove.

    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]

    param
    (
        [parameter(Mandatory = $true)]
        $Id,
        [parameter(Mandatory = $true)]
        $AssignmentId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/assignments/$AssignmentId"

    if ($PSCmdlet.ShouldProcess('Removing App Assignment')) {
        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Delete)
        }
        catch {
            Write-Host "❌ Graph request to $uri failed" -ForegroundColor Red
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                Write-Host $_.ErrorDetails.Message -ForegroundColor Red
            }
            else {
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
            throw
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'App Assignment would have been removed'
    }
    else {
        Write-Output 'App assignment not removed'
    }
}
function Add-AppAssignment() {

    <#
    .SYNOPSIS
    Allows for adding app assignments to Intune.

    .DESCRIPTION
    This function allows for adding app assignments to Intune.

    .PARAMETER Id
    Specifies the Id of the mobile app to add the assignment to.

    .PARAMETER targetGroupId
    Specifies the Id of the group to assign the app to.

    .PARAMETER installIntent
    Specifies the install intent for the app assignment. Valid values are 'Available', 'Required', or 'Uninstall'.

    .PARAMETER filterID
    Specifies the Id of the assignment filter to apply to the assignment.

    .PARAMETER filterMode
    Specifies the filter mode for the assignment. Valid values are 'Include' or 'Exclude'.

    .PARAMETER all
    Specifies if the app should be assigned to all users or all devices. Valid values are 'Users' or 'Devices'.

    .PARAMETER action
    Specifies the action to take when adding the assignment. Valid values are 'Replace' or 'Add'.

    #>

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Id,

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $targetGroupId,

        [parameter(Mandatory = $true)]
        [ValidateSet('Available', 'Required', 'Uninstall')]
        [ValidateNotNullOrEmpty()]
        $installIntent,

        [parameter(Mandatory = $false)]
        $filterID,

        [ValidateSet('Include', 'Exclude')]
        $filterMode,

        [parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Devices')]
        [ValidateNotNullOrEmpty()]
        $all,

        [parameter(Mandatory = $true)]
        [ValidateSet('Replace', 'Add')]
        $action
    )

    $graphApiVersion = 'beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/assign"

    try {
        $TargetGroups = @()

        if ($action -eq 'Add') {
            # Checking if there are Assignments already configured
            $appDetails = Get-AppAssignment -Id $Id
            $assignments = $appDetails.assignments
            if (@($Assignments).count -ge 1) {
                foreach ($Assignment in $Assignments) {

                    if (($null -ne $targetGroupId) -and ($targetGroupId -eq $Assignment.target.groupId)) {
                        Write-Host "❗ The App $($appDetails.displayName) is already assigned to the select Group" -ForegroundColor Yellow
                    }
                    elseif (($all -eq 'Devices') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')) {
                        Write-Host "❗ The App $($appDetails.displayName) is already assigned to the All devices Group" -ForegroundColor Yellow
                    }
                    elseif (($all -eq 'Users') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')) {
                        Write-Host "❗ The App $($appDetails.displayName) is already assigned to the All users Group" -ForegroundColor Yellow
                    }
                    else {
                        $TargetGroup = New-Object -TypeName psobject

                        if (($Assignment.target).'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $Assignment.target.groupId
                        }

                        elseif (($Assignment.target).'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
                        }
                        elseif (($Assignment.target).'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allDevicesAssignmentTarget'
                        }

                        if ($Assignment.target.deviceAndAppManagementAssignmentFilterType -ne 'none') {

                            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value $Assignment.target.deviceAndAppManagementAssignmentFilterId
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value $Assignment.target.deviceAndAppManagementAssignmentFilterType
                        }

                        $Target = New-Object -TypeName psobject
                        $Target | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.mobileAppAssignment'
                        $Target | Add-Member -MemberType NoteProperty -Name 'intent' -Value $Assignment.intent
                        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
                        $TargetGroups += $Target
                    }
                }
            }
        }

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.mobileAppAssignment'
        $Target | Add-Member -MemberType NoteProperty -Name 'intent' -Value $installIntent

        $TargetGroup = New-Object -TypeName psobject
        if ($targetGroupId) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $targetGroupId
        }
        else {
            if ($all -eq 'Users') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
            }
            elseif ($all -eq 'Devices') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allDevicesAssignmentTarget'
            }
        }

        if ($filterMode) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value $filterID
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value $filterMode
        }

        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
        $TargetGroups += $Target
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'mobileAppAssignments' -Value @($TargetGroups)

        $JSON = $Output | ConvertTo-Json -Depth 10

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
    }
    catch {
        Write-Host "❌ Graph request to $uri failed" -ForegroundColor Red
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        }
        else {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        throw
    }
}
function New-ManagedDeviceAppConfig() {

    <#
    .SYNOPSIS
    Allows for creating Managed Device App Config profiles in Intune.

    .DESCRIPTION
    This function allows for creating Managed Device App Config profiles in Intune.

    .PARAMETER JSON
    Specifies the JSON string for the Managed Device App Config profile to create.

    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'

    if ($PSCmdlet.ShouldProcess('Creating new Managed Device App Config Profile')) {
        try {
            Test-JSONData -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType 'application/json' | Out-Null
        }
        catch {
            Write-Host "❌ Graph request to $uri failed" -ForegroundColor Red
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                Write-Host $_.ErrorDetails.Message -ForegroundColor Red
            }
            else {
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
            throw
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'Managed Device App Config Profile would have been created'
    }
    else {
        Write-Output 'Managed Device App Config Profile was not created'
    }
}
function Get-ManagedDeviceAppConfig() {

    <#
    .SYNOPSIS
    Allows for getting Managed Device App Config profiles from Intune.

    .DESCRIPTION
    This function allows for getting Managed Device App Config profiles from Intune.

    #>

    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject).value
    }
    catch {
        Write-Host "❌ Graph request to $uri failed" -ForegroundColor Red
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        }
        else {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        throw
    }
}
function Read-YesNoChoice {
    <#
        .SYNOPSIS
        Prompt the user for a Yes No choice.

        .DESCRIPTION
        Prompt the user for a Yes No choice and returns 0 for no and 1 for yes.

        .PARAMETER Title
        Title for the prompt

        .PARAMETER Message
        Message for the prompt

		.PARAMETER DefaultOption
        Specifies the default option if nothing is selected

        .INPUTS
        None. You cannot pipe objects to Read-YesNoChoice.

        .OUTPUTS
        Int. Read-YesNoChoice returns an Int, 0 for no and 1 for yes.

        .EXAMPLE
        PS> $choice = Read-YesNoChoice -Title "Please Choose" -Message "Yes or No?"

		Please Choose
		Yes or No?
		[N] No  [Y] Yes  [?] Help (default is "N"): y
		PS> $choice
        1

		.EXAMPLE
        PS> $choice = Read-YesNoChoice -Title "Please Choose" -Message "Yes or No?" -DefaultOption 1

		Please Choose
		Yes or No?
		[N] No  [Y] Yes  [?] Help (default is "Y"):
		PS> $choice
        1

        .LINK
        Online version: https://www.chriscolden.net/2024/03/01/yes-no-choice-function-in-powershell/
    #>

    param (
        [Parameter(Mandatory = $true)][String]$Title,
        [Parameter(Mandatory = $true)][String]$Message,
        [Parameter(Mandatory = $false)][Int]$DefaultOption = 0
    )

    $No = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $Yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($No, $Yes)

    return $host.ui.PromptForChoice($Title, $Message, $Options, $DefaultOption)
}
#endregion Functions

#region variables
#$tenantId = ''
$requiredScopes = @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All', 'DeviceManagementConfiguration.Read.All')
[String[]]$scopes = $requiredScopes -join ', '
$rndWait = Get-Random -Minimum 1 -Maximum 2
$noFiltering = @('#microsoft.graph.macOSPkgApp', '#microsoft.graph.macOSDmgApp')
$noUninstall = @('#microsoft.graph.macOSPkgApp', '#microsoft.graph.macOSOfficeSuiteApp', '#microsoft.graph.macOSMicrosoftDefenderApp', '#microsoft.graph.macOSMicrosoftEdgeApp')

$pathToScript = if ( $PSScriptRoot ) {
    # Console or vscode debug/run button/F5 temp console
    $PSScriptRoot
}
else {
    if ( $psISE ) { Split-Path -Path $psISE.CurrentFile.FullPath }
    else {
        if ($profile -match 'VScode') {
            # vscode "Run Code Selection" button/F8 in integrated console
            Split-Path $psEditor.GetEditorContext().CurrentFile.Path
        }
        else {
            Write-Output 'unknown directory to set path variable. exiting script.'
            exit 0
        }
    }
}
#endregion variables

#region intro
Write-Host '
 _______         __
|_     _|.-----.|  |_.--.--.-----.-----.' -ForegroundColor Cyan -NoNewline
Write-Host '
 _|   |_ |     ||   _|  |  |     |  -__|' -ForegroundColor DarkCyan -NoNewline
Write-Host '
|_______||__|__||____|_____|__|__|_____|' -ForegroundColor blue
Write-Host '
 _______               _______               __
|   _   |.-----.-----.|   _   |.-----.-----.|__|.-----.-----.-----.----.
|       ||  _  |  _  ||       ||__ --|__ --||  ||  _  |     |  -__|   _|
|___|___||   __|   __||___|___||_____|_____||__||___  |__|__|_____|__|
         |__|  |__|                             |_____|
' -ForegroundColor Green

Write-Host 'IntuneAppAssigner - Update and review Mobile Apps Assignments in bulk.' -ForegroundColor Green
Write-Host 'Nick Benton - oddsandendpoints.co.uk' -NoNewline;
Write-Host ' | Version' -NoNewline; Write-Host ' 0.4.4 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2026-02-19' -ForegroundColor Magenta
Write-Host "`nIf you have any feedback, open an issue at https://github.com/ennnbeee/IntuneAppAssigner/issues" -ForegroundColor Cyan
Start-Sleep -Seconds $rndWait
#endregion intro

#region preflight
if ($PSVersionTable.PSVersion.Major -eq 5) {
    Write-Host 'WARNING: PowerShell 5 is not supported, use PowerShell 7 or later.' -ForegroundColor Yellow
    exit
}
#endregion preflight

#region module check
$modules = @('Microsoft.Graph.Authentication', 'Microsoft.PowerShell.ConsoleGuiTools')
foreach ($module in $modules) {
    Write-Host "Checking for $module PowerShell module..." -ForegroundColor Cyan
    if (!(Get-Module -Name $module -ListAvailable)) {
        Install-Module -Name $module -Scope CurrentUser -AllowClobber
    }
    Write-Host "PowerShell Module $module found." -ForegroundColor Green
    if (!([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object FullName -Like "*$module*")) {
        Import-Module -Name $module -Force
    }
}
#endregion module check

#region app auth
try {
    if (!$tenantId) {
        Write-Host 'Connecting using interactive authentication' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    }
    else {
        if ((!$appId -and !$appSecret) -or ($appId -and !$appSecret) -or (!$appId -and $appSecret)) {
            Write-Host 'Missing App Details, connecting using user authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -Scopes $scopes -ErrorAction Stop
        }
        else {
            Write-Host 'Connecting using App authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -appId $appId -appSecret $appSecret -ErrorAction Stop
        }
    }
    $context = Get-MgContext
    Write-Host "`nSuccessfully connected to Microsoft Graph tenant $($context.TenantId)." -ForegroundColor Green
}
catch {
    Write-Error $_.ErrorDetails.Message.Message
    exit
}
#endregion app auth

#region scopes
$currentScopes = $context.Scopes
# Validate required permissions
$missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host 'WARNING: The following scope permissions are missing:' -ForegroundColor Yellow
    $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "`nEnsure these permissions are granted to the app registration for full functionality." -ForegroundColor Yellow
    exit
}
else {
    Write-Host 'All required scope permissions are present.' -ForegroundColor Green
}
Start-Sleep -Seconds $rndWait
#endregion scopes

#region Script
do {
    #region clear variables for reruns
    Clear-Variable -Name choice*
    #endregion clear variables for reruns

    #region App Type
    $availableApps = $null
    while ($availableApps.count -eq 0) {
        Start-Sleep -Seconds $rndWait
        Clear-Host
        Write-Host "`n📱 Select which app type:" -ForegroundColor White
        Write-Host "`n  (1) Android App Assignment" -ForegroundColor Green
        Write-Host "`n  (2) iOS/iPadOS App Assignment" -ForegroundColor Blue
        Write-Host "`n  (3) macOS App Assignment" -ForegroundColor Magenta
        Write-Host "`n  (4) Windows App Assignment" -ForegroundColor Cyan
        Write-Host "`n  (E) Exit`n" -ForegroundColor White

        $choiceAppType = Read-Host -Prompt 'Based on which App type, type 1, 2, 3, 4, or E to exit the script, then press enter'
        while ( $choiceAppType -notin ('1', '2', '3', '4', 'E')) {
            $choiceAppType = Read-Host -Prompt 'Based on which App type, type 1, 2, 3, 4, or E to exit the script, then press enter'
        }

        switch ($choiceAppType) {
            '1' {
                $appType = 'android'
                $appTypeDisplay = 'Android'
                $appPackage = 'packageId'
            }
            '2' {
                $appType = 'ios'
                $appTypeDisplay = 'iOS/iPadOS'
                $appPackage = 'bundleId'
            }
            '3' {
                $appType = 'macOS'
                $appTypeDisplay = 'macOS'
            }
            '4' {
                $appType = 'win'
                $appTypeOffice = 'office'
                $appTypeDisplay = 'Windows'
            }
            'E' { exit }
        }

        Write-Host "`nSelect the $appTypeDisplay Apps you wish to modify or review assignments." -ForegroundColor Cyan
        Start-Sleep -Seconds $rndWait
        $apps = $null
        while ($apps.count -eq 0) {
            if ($appType -eq 'ios' -or $appType -eq 'android') {
                $availableApps = Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($appType) } | Select-Object -Property @{Label = 'AppName'; Expression = 'displayName' }, @{Label = 'AppPublisher'; Expression = 'publisher' }, @{Label = 'AppType'; Expression = '@odata.type' }, @{Label = 'AppID'; Expression = 'id' }, @{Label = 'AppPackage'; Expression = $appPackage } | Sort-Object -Property 'AppName'
            }
            elseif ($appType -eq 'macOS') {
                $availableApps = Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($appType) } | Select-Object -Property @{Label = 'AppName'; Expression = 'displayName' }, @{Label = 'AppPublisher'; Expression = 'publisher' }, @{Label = 'AppType'; Expression = '@odata.type' }, @{Label = 'AppID'; Expression = 'id' } | Sort-Object -Property 'AppName'
            }
            else {
                $availableApps = Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($appType) -or ($_.'@odata.type').contains($appTypeOffice) } | Select-Object -Property @{Label = 'AppName'; Expression = 'displayName' }, @{Label = 'AppPublisher'; Expression = 'publisher' }, @{Label = 'AppType'; Expression = '@odata.type' }, @{Label = 'AppID'; Expression = 'id' } | Sort-Object -Property 'AppName'
            }

            if ($null -ne $availableApps) {
                $apps = @($availableApps | Out-ConsoleGridView -Title 'Select apps to assign or review' -OutputMode Multiple)
                if ($apps.count -eq 0) {
                    Clear-Host
                    Start-Sleep -Seconds $rndWait
                    Write-Host "`n Select at least one $appTypeDisplay app to continue." -ForegroundColor Yellow
                    Start-Sleep -Seconds $rndWait
                }
            }
            else {
                Write-Host "`nNo $appTypeDisplay apps found in Intune, please select a new operating system." -ForegroundColor Yellow
                Start-Sleep -Seconds $rndWait
            }
        }
    }
    #endregion App Type

    #region Assignment Type
    do {
        #region assignment actions
        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host "`n🪄  Select the assignment action:" -ForegroundColor White
        Write-Host "`n   (1) Replace all existing assignments" -ForegroundColor Yellow
        Write-Host "`n   (2) Add to the existing assignments" -ForegroundColor Green
        Write-Host "`n   (3) Review existing assignments" -ForegroundColor Cyan
        Write-Host "`n   (E) Exit`n" -ForegroundColor White

        $choiceAssignmentType = Read-Host -Prompt 'Based on which Assignment Action, type 1, 2, 3, or E to exit the script, then press enter'
        while ( ($choiceAssignmentType -notin ('1', '2', '3', 'E'))) {
            $choiceAssignmentType = Read-Host -Prompt 'Based on which Assignment Action, type 1, 2, 3, or E to exit the script, then press enter'
        }
        switch ($choiceAssignmentType) {
            '1' {
                $action = 'Replace'
                $decisionReview = 0
            }
            '2' {
                $action = 'Add'
                $decisionReview = 0
            }
            '3' { $action = 'Review' }
            'E' { exit }
        }
        #endregion assignment actions

        #region Review
        if ($action -eq 'Review') {
            Clear-Host
            Start-Sleep -Seconds $rndWait
            Write-Host "`n🔄 Getting existing assignments for the following $appTypeDisplay apps:`n" -ForegroundColor Cyan
            $appAssignmentReport = @()
            foreach ($app in $apps) {
                Write-Host "$($app.AppName)" -ForegroundColor White
                $appAssignments = (Get-AppAssignment -Id $app.AppID).assignments
                if ($appAssignments.count -gt 0) {
                    foreach ($appAssignment in $appAssignments) {

                        $assignmentGroupType = switch ($appAssignment.target.'@odata.type') {
                            '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'All users' }
                            '#microsoft.graph.allDevicesAssignmentTarget' { 'All devices' }
                            '#microsoft.graph.groupAssignmentTarget' { Get-MDMGroup -id $($appAssignment.target.groupId) | Select-Object -ExpandProperty displayName }
                        }
                        if ($($appAssignment.target.deviceAndAppManagementAssignmentFilterType) -ne 'none') {
                            $assignmentFilterMode = (Get-Culture).TextInfo.ToTitleCase($($appAssignment.target.deviceAndAppManagementAssignmentFilterType).ToLower())
                            $assignmentFilter = (Get-AssignmentFilter -Id $($appAssignment.target.deviceAndAppManagementAssignmentFilterId)).displayName
                        }
                        else {
                            $assignmentFilterMode = 'n/a'
                            $assignmentFilter = 'n/a'
                        }

                        $appAssignmentReport += [PSCustomObject]@{
                            'App'         = $app.AppName
                            'Publisher'   = $app.AppPublisher
                            'Intent'      = $(Get-Culture).TextInfo.ToTitleCase($($appAssignment.intent).ToLower())
                            'Assignment'  = $assignmentGroupType
                            'Filter Mode' = $assignmentFilterMode
                            'Filter'      = $assignmentFilter
                        }
                    }
                }
                else {
                    $appAssignmentReport += [PSCustomObject]@{
                        'App'         = $app.AppName
                        'Publisher'   = $app.AppPublisher
                        'Intent'      = 'n/a'
                        'Assignment'  = 'n/a'
                        'Filter Mode' = 'n/a'
                        'Filter'      = 'n/a'
                    }
                }
            }
            Clear-Host
            Start-Sleep -Seconds $rndWait
            Write-Host "`nThe below are the existing $appTypeDisplay app assignments:" -ForegroundColor Cyan
            $appAssignmentReport | Format-Table -AutoSize
            Write-Host "`n✨ All existing assignments for the selected $appTypeDisplay apps captured." -ForegroundColor Green

            $decisionExport = Read-YesNoChoice -Title '📝 Export Review to CSV' -Message 'Do you want to export the above assignment report to a CSV?' -DefaultOption 1
            if ($decisionExport -eq 1) {
                $timeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                $exportPath = "$pathToScript\AppAssignmentsReview-$appType-$timeStamp.csv"
                $appAssignmentReport | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
                Write-Host "`n✅ Exported app assignments to $exportPath" -ForegroundColor Green
            }
            $decisionReview = Read-YesNoChoice -Title '♻  Continue the Script' -Message 'Do you want to amend these app assignments?' -DefaultOption 1
            if ($decisionReview -eq 0) {
                exit
            }
        }
        #endregion Review
    }
    until ($decisionReview -eq 0)
    #endregion Assignment Type

    #region Install Intent
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host "`n💽  Select the installation intent:" -ForegroundColor White
    Write-Host "`n   (1) Assign Apps as 'Required' to enrolled devices" -ForegroundColor Green
    Write-Host "`n   (2) Assign Apps as 'Available' to enrolled devices" -ForegroundColor Cyan
    Write-Host "`n   (3) Assign Apps as 'Uninstall' to enrolled devices" -ForegroundColor Yellow
    Write-Host "`n   (4) Remove All Assignments types" -ForegroundColor Red
    Write-Host "`n   (E) Exit`n" -ForegroundColor White

    $choiceInstallIntent = Read-Host -Prompt 'Based on which Install Intent type, type 1, 2, 3, 4 or E to exit the script, then press enter'
    while ( $choiceInstallIntent -notin ('1', '2', '3', '4', 'E')) {
        $choiceInstallIntent = Read-Host -Prompt 'Based on which Install Intent type, type 1, 2, 3, 4 or E to exit the script, then press enter'
    }

    switch ($choiceInstallIntent) {
        '1' { $installIntent = 'Required' }
        '2' { $installIntent = 'Available' }
        '3' { $installIntent = 'Uninstall' }
        '4' { $installIntent = 'Remove' }
        'E' { exit }
    }
    #endregion Install Intent

    #region Group Assignment
    Clear-Host
    Start-Sleep -Seconds $rndWait
    if ($installIntent -ne 'Remove') {
        do {
            Clear-Host
            Start-Sleep -Seconds $rndWait
            Write-Host "`n👥  Select which group to assign the apps: " -ForegroundColor White
            Write-Host "`n   (1) Assign Apps to the 'All devices' group" -ForegroundColor Green
            Write-Host "`n   (2) Assign Apps to the 'All users' group" -ForegroundColor Green
            Write-Host "`n   (3) Assign Apps to a selected Group" -ForegroundColor Cyan
            Write-Host "`n   (E) Exit`n" -ForegroundColor White

            $choiceAssignmentTarget = Read-Host -Prompt 'Based on which assignment type, type 1, 2, 3, or E to exit the script, then press enter'
            while ( $choiceAssignmentTarget -notin ('1', '2', '3', 'E')) {
                $choiceAssignmentTarget = Read-Host -Prompt 'Based on which assignment type, type 1, 2, 3, or E to exit the script, then press enter'
            }

            switch ($choiceAssignmentTarget) {
                '1' {
                    $assignmentType = 'Devices'
                    if ($choiceInstallIntent -eq 2) {
                        Start-Sleep -Seconds $rndWait
                        Write-Host "Assigning Apps as 'Available' to the 'All Devices' group will not work, re-select a group." -ForegroundColor Red
                        Start-Sleep -Seconds $rndWait
                        $decisionGroup = 0
                    }
                    $decisionGroup = 1
                }
                '2' {
                    $assignmentType = 'Users'
                    $decisionGroup = 1
                }
                '3' {
                    $assignmentType = 'Group'
                    $groupName = $null
                    $decisionGroup = 1
                    if ($choiceInstallIntent -eq 2) {
                        Write-Host "Assigning Apps as 'Available' to groups containing devices will not work, ensure you select a group containing Users." -ForegroundColor yellow
                    }
                    $groupName = Read-Host 'Enter a search term for the Assignment Group of at least three characters'
                    while ($groupName.Length -lt 3) {
                        $groupName = Read-Host 'Enter a search term for the Assignment Group of at least three characters'
                    }
                    Start-Sleep -Seconds $rndWait
                    Write-Host "`nSelect the Group for the assignment." -ForegroundColor Cyan
                    Start-Sleep -Seconds $rndWait
                    $assignmentGroup = $null
                    while ($null -eq $assignmentGroup) {
                        $assignmentGroup = Get-MDMGroup -GroupName $groupName | Select-Object -Property @{Label = 'GroupName'; Expression = 'displayName' }, @{Label = 'GroupID'; Expression = 'id' } | Sort-Object -Property 'GroupName' | Out-ConsoleGridView -Title 'Select Assignment Group' -OutputMode Single
                    }
                }
                'E' { exit }
            }
        }
        until ($decisionGroup -eq 1)

        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host "`n🎯  Select the Filter mode: " -ForegroundColor White
        Write-Host "`n   (1) Include Filter" -ForegroundColor Green
        Write-Host "`n   (2) Exclude Filter" -ForegroundColor Yellow
        Write-Host "`n   (3) No Filters" -ForegroundColor Cyan
        Write-Host "`n   (E) Exit`n" -ForegroundColor White

        $choiceAssignmentFilter = Read-Host -Prompt 'Based on which Filter mode, type 1, 2, 3, or E to exit the script, then press enter'
        while ( $choiceAssignmentFilter -notin ('1', '2', '3', 'E')) {
            $choiceAssignmentFilter = Read-Host -Prompt 'Based on which Filter mode, type 1, 2, 3, or E to exit the script, then press enter'
        }

        switch ($choiceAssignmentFilter) {
            '1' { $filtering = 'Yes'; $filterMode = 'Include' }
            '2' { $filtering = 'Yes'; $filterMode = 'Exclude' }
            '3' { $filtering = 'No' }
            'E' { exit }
        }
        Start-Sleep -Seconds $rndWait
        if ($filtering -eq 'Yes') {
            $assignmentFilter = $null
            Write-Host "`nSelect the Assignment Filter for the assignment." -ForegroundColor Cyan
            Start-Sleep -Seconds $rndWait
            while ($null -eq $assignmentFilter) {
                $assignmentFilter = Get-AssignmentFilter | Where-Object { ($_.platform) -like ("*$appType*") -and ($_.assignmentFilterManagementType -eq 'devices') } | Select-Object -Property @{Label = 'FilterName'; Expression = 'displayName' }, @{Label = 'FilterRule'; Expression = 'rule' }, @{Label = 'FilterID'; Expression = 'id' } | Sort-Object -Property 'FilterName' | Out-ConsoleGridView -Title 'Select Assignment Filter' -OutputMode Single
            }
        }
    }
    #endregion Group Assignment

    #region App Config
    if (($appType -eq 'ios' -or $appType -eq 'android') -and ($installIntent -ne 'Remove')) {
        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host "`n🪧  Select if Work Account App Config profiles should be created:" -ForegroundColor White
        Write-Host "`n   (1) Create App Config profiles" -ForegroundColor Green
        Write-Host "`n   (2) Do not create App Config profiles" -ForegroundColor Cyan
        Write-Host "`n   (E) Exit`n" -ForegroundColor White

        $choiceAppConfig = Read-Host -Prompt 'Based on whether App Config profiles should be created, type 1, 2, or E to exit the script, then press enter'
        while ( ($choiceAppConfig -notin ('1', '2', 'E'))) {
            $choiceAppConfig = Read-Host -Prompt 'Based on whether App Config profiles should be created, type 1, 2, or E to exit the script, then press enter'
        }

        switch ($choiceAppConfig) {
            '1' {
                $appConfig = 'Yes'
                Clear-Host
                Start-Sleep -Seconds $rndWait
                Write-Host "`n🏢  Select which App Config profiles should be created:" -ForegroundColor White
                Write-Host "`n   (1) Both COPE and BYOD profiles" -ForegroundColor Green
                Write-Host "`n   (2) Only COPE profiles" -ForegroundColor Cyan
                Write-Host "`n   (3) Only BYOD profiles" -ForegroundColor Yellow
                Write-Host "`n   (E) Exit`n" -ForegroundColor White

                $choiceAppConfigOwnership = Read-Host -Prompt 'Based on which App Config profiles should be created, type 1, 2, 3, or E to exit the script, then press enter'
                while ( ($choiceAppConfigOwnership -notin ('1', '2', '3', 'E'))) {
                    $choiceAppConfigOwnership = Read-Host -Prompt 'Based on which App Config profiles should be created, type 1, 2, 3, or E to exit the script, then press enter'
                }

                switch ($choiceAppConfigOwnership) {
                    '1' { $appConfigOwnership = 'Both' }
                    '2' { $appConfigOwnership = 'COPE' }
                    '3' { $appConfigOwnership = 'BYOD' }
                    'E' { exit }
                }
            }
            '2' { $appConfig = 'No' }
            'E' { exit }
        }
    }
    #endregion App Config

    #region App Assignment Check
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host 'App Assignment Summary' -ForegroundColor Green
    Write-Host "`nThe following $appTypeDisplay Apps have been selected:" -ForegroundColor Cyan
    $($apps.'AppName') | Format-List
    if ($installIntent -ne 'Remove') {
        Write-Host "`nThe following Assignment Action has been selected:" -ForegroundColor Cyan
        Write-Host "$action"
        Write-Host "`nThe following Install Intent has been selected:" -ForegroundColor Cyan
        Write-Host "$installIntent"
        if ($installIntent -eq 'Uninstall') {
            Write-Host
            foreach ($app in $apps) {
                if ($app.'AppType' -in $noUninstall) {
                    Write-Host "Note: App $($app.AppName) does not support Uninstall assignments, this app will be skipped." -ForegroundColor Yellow
                }
            }
        }
        Write-Host "`nThe following Assignment Group has been selected:" -ForegroundColor Cyan
        if ($assignmentType -eq 'Group') {
            Write-Host "$($assignmentGroup.GroupName)"
        }
        else {
            Write-Host "All $assignmentType"
        }
        if ($filtering -eq 'Yes') {
            Write-Host "`nThe following Assignment Filter has been selected with Filter mode $filterMode`:" -ForegroundColor Cyan
            Write-Host "$($assignmentFilter.FilterName)"
            Write-Host
            foreach ($app in $apps) {
                if ($app.'AppType' -in $noFiltering) {
                    Write-Host "Note: App $($app.AppName) does not support Assignment Filters, this app will be assigned without a Filter." -ForegroundColor Yellow
                }
            }
        }
    }
    else {
        Write-Host 'All Assignments will be removed.' -ForegroundColor Red
    }
    if ($appConfig -eq 'Yes') {
        Write-Host "`nApp Configuration profiles will be created for apps that support the 'Work/School Account only' setting." -ForegroundColor Cyan
    }

    $decisionConfirm = Read-YesNoChoice -Title '⏯  Review the above settings before proceeding' -Message 'Do you want to assign the selected Apps with above settings?' -DefaultOption 1
    if ($decisionConfirm -eq 0) {
        Write-Host '⛔  Exiting script, re-run the script to make any changes.' -ForegroundColor Yellow
        exit
    }
    else {
        Write-Host '▶  Proceeding with the assignment changes...' -ForegroundColor Green
        Start-Sleep -Seconds $rndWait
    }
    #endregion App Assignment Check

    #region App Assignment
    Clear-Host
    Start-Sleep -Seconds $rndWait
    if ($installIntent -ne 'Remove') {
        if ($installIntent -ne 'Uninstall') {
            if ($assignmentType -eq 'Group') {
                if ($filtering -eq 'Yes') {
                    foreach ($app in $apps) {
                        if ($app.'AppType' -in $noFiltering) {
                            Write-Host "⏭  App $($app.AppName) does not support Assignment Filters, skipping Filter assignment." -ForegroundColor Yellow
                            Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -TargetGroupId $assignmentGroup.GroupID -Action $action
                            Write-Host "✅ Successfully Assigned App: $($app.AppName) as $installIntent to Group $($assignmentGroup.GroupName)" -ForegroundColor Green
                        }
                        else {
                            Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -TargetGroupId $assignmentGroup.GroupID -FilterMode $filterMode -FilterID $assignmentFilter.FilterID -Action $action
                            Write-Host "✅ Successfully Assigned App: $($app.AppName) as $installIntent to Group $($assignmentGroup.GroupName) with Filter $($assignmentFilter.FilterName)" -ForegroundColor Green
                        }
                    }
                }
                else {
                    foreach ($app in $apps) {
                        Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -TargetGroupId $assignmentGroup.GroupID -Action $action
                        Write-Host "✅ Successfully Assigned App: $($app.AppName) as $installIntent to Group $($assignmentGroup.GroupName)" -ForegroundColor Green
                    }
                }
            }
            else {
                if ($filtering -eq 'Yes') {
                    foreach ($app in $apps) {
                        if ($app.'AppType' -in $noFiltering) {
                            Write-Host "⏭  App $($app.AppName) does not support Assignment Filters, skipping Filter assignment." -ForegroundColor Yellow
                            Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -All $assignmentType -Action $action
                            Write-Host "✅ Successfully Assigned App: $($app.AppName) as $installIntent to Group $($assignmentGroup.GroupName)" -ForegroundColor Green
                        }
                        else {
                            Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -All $assignmentType -FilterMode $filterMode -FilterID $assignmentFilter.FilterID -Action $action
                            Write-Host "✅ Successfully Assigned App $($app.AppName) as $installIntent to All $assignmentType with Filter $($assignmentFilter.FilterName)" -ForegroundColor Green
                        }
                    }
                }
                else {
                    foreach ($app in $apps) {
                        Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -All $assignmentType -Action $action
                        Write-Host "✅ Successfully Assigned App $($app.AppName) as $installIntent to All $assignmentType" -ForegroundColor Green
                    }
                }
            }
        }
        else {
            if ($assignmentType -eq 'Group') {
                if ($filtering -eq 'Yes') {
                    foreach ($app in $apps) {
                        if ($app.'AppType' -in $noFiltering) {
                            if ($app.'AppType' -in $noUninstall) {
                                Write-Host "⏭  App $($app.AppName) does not support Uninstall intent, skipping assignment." -ForegroundColor Yellow
                            }
                            else {
                                Write-Host "⏭  App $($app.AppName) does not support Assignment Filters, skipping Filter assignment." -ForegroundColor Yellow
                                Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -TargetGroupId $assignmentGroup.GroupID -Action $action
                                Write-Host "✅ Successfully Assigned App: $($app.AppName) as $installIntent to Group $($assignmentGroup.GroupName)" -ForegroundColor Green
                            }
                        }
                        else {
                            if ($app.'AppType' -in $noUninstall) {
                                Write-Host "⏭  App $($app.AppName) does not support Uninstall intent, skipping assignment." -ForegroundColor Yellow
                            }
                            else {
                                Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -TargetGroupId $assignmentGroup.GroupID -FilterMode $filterMode -FilterID $assignmentFilter.FilterID -Action $action
                                Write-Host "✅ Successfully Assigned App: $($app.AppName) as $installIntent to Group $($assignmentGroup.GroupName) with Filter $($assignmentFilter.FilterName)" -ForegroundColor Green
                            }
                        }
                    }
                }
                else {
                    foreach ($app in $apps) {
                        if ($app.'AppType' -in $noUninstall) {
                            Write-Host "⏭  App $($app.AppName) does not support Uninstall intent, skipping assignment." -ForegroundColor Yellow
                        }
                        else {
                            Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -TargetGroupId $assignmentGroup.GroupID -Action $action
                            Write-Host "✅ Successfully Assigned App: $($app.AppName) as $installIntent to Group $($assignmentGroup.GroupName)" -ForegroundColor Green
                        }
                    }
                }
            }
            else {
                if ($filtering -eq 'Yes') {
                    foreach ($app in $apps) {
                        if ($app.'AppType' -in $noFiltering) {
                            if ($app.'AppType' -in $noUninstall) {
                                Write-Host "⏭  App $($app.AppName) does not support Uninstall intent, skipping assignment." -ForegroundColor Yellow
                            }
                            else {
                                Write-Host "⏭  App $($app.AppName) does not support Assignment Filters, skipping Filter assignment." -ForegroundColor Yellow
                                Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -All $assignmentType -Action $action
                                Write-Host "✅ Successfully Assigned App: $($app.AppName) as $installIntent to Group $($assignmentGroup.GroupName)" -ForegroundColor Green
                            }
                        }
                        else {
                            if ($app.'AppType' -in $noUninstall) {
                                Write-Host "⏭  App $($app.AppName) does not support Uninstall intent, skipping assignment." -ForegroundColor Yellow
                            }
                            else {
                                Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -All $assignmentType -FilterMode $filterMode -FilterID $assignmentFilter.FilterID -Action $action
                                Write-Host "✅ Successfully Assigned App $($app.AppName) as $installIntent to All $assignmentType with Filter $($assignmentFilter.FilterName)" -ForegroundColor Green
                            }
                        }
                    }
                }
                else {
                    foreach ($app in $apps) {
                        if ($app.'AppType' -in $noUninstall) {
                            Write-Host "⏭  App $($app.AppName) does not support Uninstall intent, skipping assignment." -ForegroundColor Yellow
                        }
                        else {
                            Add-AppAssignment -Id $app.AppID -InstallIntent $installIntent -All $assignmentType -Action $action
                            Write-Host "✅ Successfully Assigned App $($app.AppName) as $installIntent to All $assignmentType" -ForegroundColor Green
                        }
                    }
                }
            }
        }
    }
    else {
        foreach ($app in $apps) {
            $Assignments = (Get-AppAssignment -Id $app.AppID).assignments
            foreach ($Assignment in $Assignments) {
                try {
                    Remove-AppAssignment -Id $app.AppID -AssignmentId $Assignment.id
                    Write-Host "✅ Successfully removed App Assignment from $($app.AppName)" -ForegroundColor Green
                }
                catch {
                    Write-Host "❌ Unable to remove App Assignment from $($app.AppName)" -ForegroundColor Red
                }
            }
        }
    }
    #endregion App Assignment

    #region App Config
    if ($appConfig -eq 'Yes') {
        foreach ($app in $apps) {
            switch ($appType) {
                'ios' {
                    $appsIntuneMAM = @(
                        'com.microsoft.officemobile'
                        'com.microsoft.Office.Word'
                        'com.microsoft.Office.Excel'
                        'com.microsoft.Office.Powerpoint'
                        'com.microsoft.office.onenote'
                        'com.microsoft.msedge'
                        'com.microsoft.skydrive'
                        'com.microsoft.Office.Outlook'
                        'com.microsoft.skype.teams'
                        'com.microsoft.copilot'
                        'com.microsoft.onenote'
                    )
                    $appConfigCOPEDisplayName = "$appConfigPrefix`IOS-COPE-$($($app.AppName).Replace(' ',''))"
                    $appConfigBYODDisplayName = "$appConfigPrefix`IOS-BYOD-$($($app.AppName).Replace(' ',''))"
                    $appConfigCOPEJson = @"
{
    "@odata.type": "#microsoft.graph.iosMobileAppConfiguration",
    "displayName": "$appConfigCOPEDisplayName",
    "description": "",
    "targetedMobileApps": [
        "$($app.AppID)"
    ],
    "settings": [
        {
            "appConfigKey": "IntuneMAMUPN ",
            "appConfigKeyType": "StringType",
            "appConfigKeyValue": "{{UserPrincipalName}}"
        }
    ]
}
"@
                    $appConfigBYODJson = @"
{
    "@odata.type": "#microsoft.graph.iosMobileAppConfiguration",
    "displayName": "$appConfigBYODDisplayName",
    "description": "",
    "targetedMobileApps": [
        "$($app.AppID)"
    ],
    "settings": [
        {
            "appConfigKey": "IntuneMAMUPN ",
            "appConfigKeyType": "StringType",
            "appConfigKeyValue": "{{UserPrincipalName}}"
        }
    ]
}
"@
                }
                'android' {
                    $appsIntuneMAM = @(
                        'com.microsoft.office.officehubrow'
                        'com.microsoft.office.word'
                        'com.microsoft.office.excel'
                        'com.microsoft.office.powerpoint'
                        'com.microsoft.office.onenote'
                        'com.microsoft.emmx'
                        'com.microsoft.skydrive'
                        'com.microsoft.office.outlook'
                        'com.microsoft.teams'
                        'com.microsoft.copilot'
                    )
                    $appConfigCOPEDisplayName = "$appConfigPrefix`AND-COPE-$($($app.AppName).Replace(' ',''))"
                    $appConfigBYODDisplayName = "$appConfigPrefix`AND-BYOD-$($($app.AppName).Replace(' ',''))"
                    $appConfigSettingsJSON = @"
{
    "kind": "androidenterprise#managedConfiguration",
    "productId": "app:$($app.'AppPackage')",
    "managedProperty": [
        {
            "key": "com.microsoft.intune.mam.AllowedAccountUPNs",
            "valueString": "{{UserPrincipalName}}"
        }
    ]
}
"@
                    [string]$appConfigSettingsString = $appConfigSettingsJSON | ConvertFrom-Json | ConvertTo-Json -Compress
                    $appConfigSettingsEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$appConfigSettingsString"))
                    $appConfigCOPEJson = @"
{
    "@odata.type": "#microsoft.graph.androidManagedStoreAppConfiguration",
    "displayName": "$appConfigCOPEDisplayName",
    "description": "",
    "profileApplicability": "androidDeviceOwner",
    "targetedMobileApps": [
        "$($app.AppID)"
    ],
    "packageId": "app:$($app.'AppPackage')",
    "payloadJson": "$appConfigSettingsEncoded",
    "permissionActions": [],
    "connectedAppsEnabled": false,
}
"@
                    $appConfigBYODJson = @"
{
    "@odata.type": "#microsoft.graph.androidManagedStoreAppConfiguration",
    "displayName": "$appConfigBYODDisplayName",
    "description": "",
    "profileApplicability": "androidWorkProfile",
    "targetedMobileApps": [
        "$($app.AppID)"
    ],
    "packageId": "app:$($app.'AppPackage')",
    "payloadJson": "$appConfigSettingsEncoded",
    "permissionActions": [],
    "connectedAppsEnabled": false,
}
"@
                }
            }

            if ($($app.'AppPackage') -in $appsIntuneMAM) {

                if ($appConfigOwnership -eq 'Both' -or $appConfigOwnership -eq 'COPE') {
                    $appConfigCOExists = Get-ManagedDeviceAppConfig | Where-Object { $_.displayName -eq $appConfigCOPEDisplayName }
                    if ($null -ne $appConfigCOExists) {
                        Write-Host "⏭  A COPE App Config profile already exists for $($app.AppName), skipping creation" -ForegroundColor Cyan
                    }
                    else {
                        New-ManagedDeviceAppConfig -JSON $appConfigCOPEJson
                        Write-Host "✅ Successfully created COPE $appTypeDisplay App Config profile $appConfigCOPEDisplayName for $($app.AppName)" -ForegroundColor Green
                    }
                }
                if ($appConfigOwnership -eq 'Both' -or $appConfigOwnership -eq 'BYOD') {
                    $appConfigBYODExists = Get-ManagedDeviceAppConfig | Where-Object { $_.displayName -eq $appConfigBYODDisplayName }
                    if ($null -ne $appConfigBYODExists) {
                        Write-Host "⏭  A BYOD App Config profile already exists for $($app.AppName), skipping creation" -ForegroundColor Cyan
                    }
                    else {
                        New-ManagedDeviceAppConfig -JSON $appConfigBYODJson
                        Write-Host "✅ Successfully created BYOD $appTypeDisplay App Config profile $appConfigBYODDisplayName for $($app.AppName)" -ForegroundColor Green
                    }
                }
            }
            else {
                Write-Host "⏭  Skipping creation of App Config profile, $($app.AppName) does not support the 'Work/School account only' setting." -ForegroundColor Cyan
            }
        }
    }
    #endregion App Config

    #region Script Relaunch
    Write-Host "`n✨ All Assignment Settings Complete" -ForegroundColor Green
    $decisionRelaunch = Read-YesNoChoice -Title '♻  Relaunch the Script' -Message 'Do you want to relaunch the Script?' -DefaultOption 1
    #endregion Script Relaunch
}
until ($decisionRelaunch -eq 0)
#endregion Script