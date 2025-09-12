<#PSScriptInfo

.VERSION 0.2.0
.GUID 71c3b7d1-f435-4f11-b7c0-4acf00b7daca
.AUTHOR Nick Benton
.COMPANYNAME
.COPYRIGHT GPL
.TAGS Graph Intune Windows Autopilot GroupTags
.LICENSEURI https://github.com/ennnbeee/IntuneAppAssigner/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/IntuneAppAssigner
.ICONURI https://raw.githubusercontent.com/ennnbeee/IntuneAppAssigner/refs/heads/main/img/iaa-icon.png
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
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

-#>

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
            $graph = Connect-MgGraph -Scopes $scopes -TenantId $tenantId
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}
function Test-JSONData {

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
        $_.Exception
    }
    if (!$validJson) {
        Write-Host "Provided JSON isn't in valid JSON format" -ForegroundColor Red
        break
    }

}
function Get-MobileApp() {
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
        Write-Error $_.Exception.Message
        break
    }
}
function Get-AssignmentFilter() {

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/assignmentFilters'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
function Get-MDMGroup() {

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [string]$groupName
    )

    $graphApiVersion = 'beta'
    $Resource = 'groups'

    try {
        $searchTerm = 'search="displayName:' + $groupName + '"'
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?$searchTerm"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = 'eventual' } -OutputType PSObject).Value
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
function Get-AppAssignment() {

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
        Write-Error $_.Exception.Message
        break
    }
}
function Remove-AppAssignment() {

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
            Write-Error $_.Exception.Message
            break
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
        [ValidateSet('Available', 'Required')]
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
            $Assignments = (Get-AppAssignment -Id $Id).assignments
            if (@($Assignments).count -ge 1) {
                foreach ($Assignment in $Assignments) {

                    if (($null -ne $targetGroupId) -and ($targetGroupId -eq $Assignment.target.groupId)) {
                        Write-Host '❗ The App is already assigned to the Group' -ForegroundColor Yellow
                    }
                    elseif (($all -eq 'Devices') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')) {
                        Write-Host '❗ The App is already assigned to the All Devices Group' -ForegroundColor Yellow
                    }
                    elseif (($all -eq 'Users') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')) {
                        Write-Host '❗ The App is already assigned to the All Users Group' -ForegroundColor Yellow
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

        $JSON = $Output | ConvertTo-Json -Depth 3

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
function New-ManagedDeviceAppConfig() {

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
            Write-Error $_.Exception.Message
            break
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
    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject).value
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
#endregion Functions

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

Write-Host 'IntuneAppAssigner - Update Mobile Apps Assignments in bulk.' -ForegroundColor Green
Write-Host 'Nick Benton - oddsandendpoints.co.uk' -NoNewline;
Write-Host ' | Version' -NoNewline; Write-Host ' 0.2.0 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2025-09-12' -ForegroundColor Magenta
Write-Host "`nIf you have any feedback, please open an issue at https://github.com/ennnbeee/IntuneAppAssigner/issues" -ForegroundColor Cyan
#endregion intro

#region preflight
if ($PSVersionTable.PSVersion.Major -eq 5) {
    Write-Host 'WARNING: PowerShell 5 is not supported, please use PowerShell 7 or later.' -ForegroundColor Red
    exit
}
#endregion preflight

#region variables
$requiredScopes = @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementApps.ReadWrite.All')
[String[]]$scopes = $requiredScopes -join ', '
$rndWait = Get-Random -Minimum 1 -Maximum 2
$noFiltering = @('#microsoft.graph.macOSPkgApp', '#microsoft.graph.macOSDmgApp')
#endregion variables

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
    Write-Error $_.Exception.Message
    exit
}
#endregion app auth

#region scopes
$currentScopes = $context.Scopes
# Validate required permissions
$missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host 'WARNING: The following scope permissions are missing:' -ForegroundColor Red
    $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "`nPlease ensure these permissions are granted to the app registration for full functionality." -ForegroundColor Yellow
    exit
}
Write-Host 'All required scope permissions are present.' -ForegroundColor Green
#endregion scopes

do {

    #region clear variables for reruns
    Clear-Variable -Name choice*
    #endregion clear variables for reruns

    #region App Type
    Start-Sleep -Seconds $rndWait
    Clear-Host
    Write-Host "`n📱 Select which app type:" -ForegroundColor White
    Write-Host "`n  (1) Android App Assignment" -ForegroundColor Green
    Write-Host "`n  (2) iOS/iPadOS App Assignment" -ForegroundColor Cyan
    Write-Host "`n  (3) macOS App Assignment" -ForegroundColor Blue
    Write-Host "`n  (E) Exit`n" -ForegroundColor Red

    $choiceAppType = Read-Host -Prompt 'Based on which App type, please type 1, 2, 3, or E to exit the script, then press enter'
    while ( $choiceAppType -notin ('1', '2', '3', 'E')) {
        $choiceAppType = Read-Host -Prompt 'Based on which App type, please type 1, 2, 3, or E to exit the script, then press enter'
    }
    if ($choiceAppType -eq 'E') {
        break
    }
    if ($choiceAppType -eq '1') {
        $appType = 'android'
        $appPackage = 'packageId'
        $appConfigPrefix = 'POC_AND_AE_D_'
    }
    if ($choiceAppType -eq '2') {
        $appType = 'ios'
        $appPackage = 'bundleId'
        $appConfigPrefix = 'POC_IOS_D_'
    }
    if ($choiceAppType -eq '3') {
        $appType = 'macOS'
    }

    Write-Host "Please select the $appType Apps you wish to modify assignments" -ForegroundColor Cyan
    Start-Sleep -Seconds $rndWait
    $apps = $null
    while ($apps.count -eq 0) {
        if ($appType -eq 'ios' -or $appType -eq 'android') {
            $apps = @(Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($appType) } | Select-Object -Property @{Label = 'App Type'; Expression = '@odata.type' }, @{Label = 'App Name'; Expression = 'displayName' }, @{Label = 'App Publisher'; Expression = 'publisher' }, @{Label = 'App ID'; Expression = 'id' }, @{Label = 'App Package'; Expression = $appPackage } | Out-ConsoleGridView -Title 'Select Apps to Assign' -OutputMode Multiple)
        }
        else {
            $apps = @(Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($appType) } | Select-Object -Property @{Label = 'App Type'; Expression = '@odata.type' }, @{Label = 'App Name'; Expression = 'displayName' }, @{Label = 'App Publisher'; Expression = 'publisher' }, @{Label = 'App ID'; Expression = 'id' } | Out-ConsoleGridView -Title 'Select Apps to Assign' -OutputMode Multiple)
        }
    }
    #endregion App Type

    #region App Config
    if ($appType -eq 'ios' -or $appType -eq 'android') {
        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host "`n🪧  Select if Work Account App Config profiles should be created:" -ForegroundColor White
        Write-Host "`n   (1) Create App Config profiles" -ForegroundColor Green
        Write-Host "`n   (2) Do not create App Config profiles" -ForegroundColor Cyan
        Write-Host "`n   (E) Exit`n" -ForegroundColor Red

        $choiceAppConfig = Read-Host -Prompt 'Based on whether App Config profiles should be created, please type 1, 2, or E to exit the script, then press enter'
        while ( ($choiceAppConfig -notin ('1', '2', 'E'))) {
            $choiceAppConfig = Read-Host -Prompt 'Based on whether App Config profiles should be created, please type 1, 2, or E to exit the script, then press enter'
        }
        if ($choiceAppConfig -eq 'E') {
            break
        }
        if ($choiceAppConfig -eq '1') {
            $appConfig = 'Yes'
            Clear-Host
            Start-Sleep -Seconds $rndWait
            Write-Host "`n🏢  Select which App Config profiles should be created:" -ForegroundColor White
            Write-Host "`n   (1) Both COPE and BYOD profiles" -ForegroundColor Green
            Write-Host "`n   (2) Only COPE profiles" -ForegroundColor Cyan
            Write-Host "`n   (3) Only BYOD profiles" -ForegroundColor Yellow
            Write-Host "`n   (E) Exit`n" -ForegroundColor Red

            $choiceAppConfigOwnership = Read-Host -Prompt 'Based on which App Config profiles should be created, please type 1, 2, 3, or E to exit the script, then press enter'
            while ( ($choiceAppConfigOwnership -notin ('1', '2', '3', 'E'))) {
                $choiceAppConfigOwnership = Read-Host -Prompt 'Based on which App Config profiles should be created, please type 1, 2, 3, or E to exit the script, then press enter'
            }
            if ($choiceAppConfigOwnership -eq 'E') {
                break
            }
            if ($choiceAppConfigOwnership -eq '1') {
                $appConfigOwnership = 'Both'
            }
            if ($choiceAppConfigOwnership -eq '2') {
                $appConfigOwnership = 'COPE'
            }
            if ($choiceAppConfigOwnership -eq '3') {
                $appConfigOwnership = 'BYOD'
            }
        }
        if ($choiceAppConfig -eq '2') {
            $appConfig = 'No'
        }
    }
    #endregion App Config

    #region assignment actions
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host "`n🔀  Select the assignment action:" -ForegroundColor White
    Write-Host "`n   (1) Replace existing assignments" -ForegroundColor Yellow
    Write-Host "`n   (2) Add to existing assignments" -ForegroundColor Green
    Write-Host "`n   (E) Exit`n" -ForegroundColor Red

    $choiceAssignmentType = Read-Host -Prompt 'Based on which Assignment Action, please type 1, 2, or E to exit the script, then press enter'
    while ( ($choiceAssignmentType -notin ('1', '2', 'E'))) {
        $choiceAssignmentType = Read-Host -Prompt 'Based on which Assignment Action, please type 1, 2, or E to exit the script, then press enter'
    }
    if ($choiceAssignmentType -eq 'E') {
        break
    }
    if ($choiceAssignmentType -eq '1') {
        $action = 'Replace'
    }
    if ($choiceAssignmentType -eq '2') {
        $action = 'Add'
    }
    #endregion assignment actions

    #region installation intent
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host "`n💽  Choose the installation intent:" -ForegroundColor White
    Write-Host "`n   (1) Assign Apps as 'Required'" -ForegroundColor Green
    Write-Host "`n   (2) Assign Apps as 'Available'" -ForegroundColor Cyan
    Write-Host "`n   (3) Remove All Assignments" -ForegroundColor Yellow
    Write-Host "`n   (E) Exit`n" -ForegroundColor Red

    $choiceInstallIntent = Read-Host -Prompt 'Based on which Install Intent type, please type 1, 2, 3 or E to exit the script, then press enter'
    while ( $choiceInstallIntent -notin ('1', '2', '3', 'E')) {
        $choiceInstallIntent = Read-Host -Prompt 'Based on which Install Intent type, please type 1, 2, 3 or E to exit the script, then press enter'
    }
    if ($choiceInstallIntent -eq 'E') {
        break
    }
    if ($choiceInstallIntent -eq '1') {
        $installIntent = 'Required'
    }
    if ($choiceInstallIntent -eq '2') {
        $installIntent = 'Available'
    }
    if ($choiceInstallIntent -eq '3') {
        $installIntent = 'Remove'
    }
    #endregion installation intent

    #region group assignment
    Clear-Host
    Start-Sleep -Seconds $rndWait
    if ($installIntent -ne 'Remove') {
        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host "`n🫂  Choose what groups to assign the apps: " -ForegroundColor White
        Write-Host "`n   (1) Assign Apps to 'All Users'" -ForegroundColor Green
        Write-Host "`n   (2) Assign Apps to 'All Devices'" -ForegroundColor Green
        Write-Host "`n   (3) Assign Apps to a Group" -ForegroundColor Green
        Write-Host "`n   (E) Exit`n" -ForegroundColor Red

        $choiceAssignmentTarget = Read-Host -Prompt 'Based on which assignment type, please type 1, 2, 3, or E to exit the script, then press enter'
        while ( $choiceAssignmentTarget -notin ('1', '2', '3', 'E')) {
            $choiceAssignmentTarget = Read-Host -Prompt 'Based on which assignment type, please type 1, 2, 3, or E to exit the script, then press enter'
        }
        if ($choiceAssignmentTarget -eq 'E') {
            break
        }
        if ($choiceAssignmentTarget -eq '1') {
            $assignmentType = 'Users'
        }
        if ($choiceAssignmentTarget -eq '2') {
            $assignmentType = 'Devices'
            if ($choiceInstallIntent -eq 2) {
                Write-Host "Assigning Apps as 'Available' to the 'All Devices' group will not work, please re-run the script and don't make the same mistake again..." -ForegroundColor Red
                break
            }
        }
        if ($choiceAssignmentTarget -eq '3') {
            $assignmentType = 'Group'
            $groupName = $null
            if ($choiceInstallIntent -eq 2) {
                Write-Host "Assigning Apps as 'Available' to groups containing devices will not work, please ensure you select a group containing Users" -ForegroundColor yellow
            }
            $groupName = Read-Host 'Please enter a search term for the Assignment Group of at least three characters'
            while ($groupName.Length -lt 3) {
                $groupName = Read-Host 'Please enter a search term for the Assignment Group of at least three characters'
            }
            Start-Sleep -Seconds $rndWait
            Write-Host 'Please select the Group for the assignment...' -ForegroundColor Cyan
            Start-Sleep -Seconds $rndWait
            $assignmentGroup = $null
            while ($null -eq $assignmentGroup) {
                $assignmentGroup = Get-MDMGroup -GroupName $groupName | Select-Object -Property @{Label = 'Group Name'; Expression = 'displayName' }, @{Label = 'Group ID'; Expression = 'id' } | Out-ConsoleGridView -Title 'Select Assignment Group' -OutputMode Single
            }
        }

        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host "`n🔄  Chose the Filter mode: " -ForegroundColor Yellow
        Write-Host "`n   (1) Include Filter" -ForegroundColor Green
        Write-Host "`n   (2) Exclude Filter" -ForegroundColor Green
        Write-Host "`n   (3) No Filters" -ForegroundColor Cyan
        Write-Host "`n   (E) Exit`n" -ForegroundColor Red

        $choiceAssignmentFilter = Read-Host -Prompt 'Based on which Filter mode, please type 1, 2, 3, or E to exit the script, then press enter'
        while ( $choiceAssignmentFilter -notin ('1', '2', '3', 'E')) {
            $choiceAssignmentFilter = Read-Host -Prompt 'Based on which Filter mode, please type 1, 2, 3, or E to exit the script, then press enter'
        }
        if ($choiceAssignmentFilter -eq 'E') {
            break
        }
        if ($choiceAssignmentFilter -eq '1') {
            $filtering = 'Yes'
            $filterMode = 'Include'
        }
        if ($choiceAssignmentFilter -eq '2') {
            $filtering = 'Yes'
            $filterMode = 'Exclude'
        }
        if ($choiceAssignmentFilter -eq '3') {
            $filtering = 'No'
        }
        Start-Sleep -Seconds $rndWait
        if ($filtering -eq 'Yes') {
            $assignmentFilter = $null
            Write-Host 'Please select the Assignment Filter for the assignment...' -ForegroundColor Cyan
            Start-Sleep -Seconds $rndWait
            while ($null -eq $assignmentFilter) {
                $assignmentFilter = Get-AssignmentFilter | Where-Object { ($_.platform) -like ("*$appType*") -and ($_.assignmentFilterManagementType -eq 'devices') } | Select-Object -Property @{Label = 'Filter Name'; Expression = 'displayName' }, @{Label = 'Filter Rule'; Expression = 'rule' }, @{Label = 'Filter ID'; Expression = 'id' } | Out-ConsoleGridView -Title 'Select Assignment Filter' -OutputMode Single
            }
        }
    }
    #endregion group assignment

    #region assignment
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host 'The following Apps have been selected:' -ForegroundColor Cyan
    $($apps.'App Name') | Format-List
    Write-Host
    if ($installIntent -ne 'Remove') {
        Write-Host "`nThe following Assignment Action has been selected:" -ForegroundColor Cyan
        Write-Host "$action"
        Write-Host "`nThe following Assignment Group has been selected:" -ForegroundColor Cyan
        if ($assignmentType -eq 'Group') {
            Write-Host "$($assignmentGroup.'Group Name')"
        }
        else {
            Write-Host "All $assignmentType"
        }
        Write-Host
        if ($filtering -eq 'Yes') {
            Write-Host 'The following Assignment Filter has been selected:' -ForegroundColor Cyan
            Write-Host "$($assignmentFilter.'Filter Name')"
        }
    }
    else {
        Write-Host 'Assignments will be removed.' -ForegroundColor Red
    }
    if ($appConfig -eq 'Yes') {
        Write-Host "`nApp Configuration profiles will be created for apps that support IntuneMAMUPN." -ForegroundColor Cyan
    }
    Write-Host
    Write-Warning 'Please confirm these settings are correct before continuing' -WarningAction Inquire
    Clear-Host
    Start-Sleep -Seconds $rndWait
    if ($installIntent -ne 'Remove') {
        if ($assignmentType -eq 'Group') {
            if ($filtering -eq 'Yes') {
                foreach ($app in $apps) {
                    if ($app.'App Type' -in $noFiltering) {
                        Write-Host "⏭  App $($app.'App Name') of type $($app.'App Type') does not support Assignment Filters, skipping Filter assignment." -ForegroundColor Yellow
                        Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -TargetGroupId $assignmentGroup.'Group ID' -Action $action
                        Write-Host "✅ Successfully Assigned App: $($app.'App Name') as $installIntent to Group $($assignmentGroup.'Group Name')" -ForegroundColor Green
                    }
                    else {
                        Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -TargetGroupId $assignmentGroup.'Group ID' -FilterMode $filterMode -FilterID $assignmentFilter.'Filter ID' -Action $action
                        Write-Host "✅ Successfully Assigned App: $($app.'App Name') as $installIntent to Group $($assignmentGroup.'Group Name') with Filter $($assignmentFilter.'Filter Name')" -ForegroundColor Green
                    }
                }
            }
            else {
                foreach ($app in $apps) {
                    Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -TargetGroupId $assignmentGroup.'Group ID' -Action $action
                    Write-Host "✅ Successfully Assigned App: $($app.'App Name') as $installIntent to Group $($assignmentGroup.'Group Name')" -ForegroundColor Green
                }
            }
        }
        else {
            if ($filtering -eq 'Yes') {
                foreach ($app in $apps) {
                    if ($app.'App Type' -in $noFiltering) {
                        Write-Host "⏭  App $($app.'App Name') of type $($app.'App Type') does not support Assignment Filters, skipping Filter assignment." -ForegroundColor Yellow
                        Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -All $assignmentType -Action $action
                        Write-Host "✅ Successfully Assigned App: $($app.'App Name') as $installIntent to Group $($assignmentGroup.'Group Name')" -ForegroundColor Green
                    }
                    else {
                        Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -All $assignmentType -FilterMode $filterMode -FilterID $assignmentFilter.'Filter ID' -Action $action
                        Write-Host "✅ Successfully Assigned App $($app.'App Name') as $installIntent to All $assignmentType with Filter $($assignmentFilter.'Filter Name')" -ForegroundColor Green
                    }
                }
            }
            else {
                foreach ($app in $apps) {
                    Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -All $assignmentType -Action $action
                    Write-Host "✅ Successfully Assigned App $($app.'App Name') as $installIntent to All $assignmentType" -ForegroundColor Green
                }
            }
        }
    }
    else {
        foreach ($app in $apps) {
            $Assignments = (Get-AppAssignment -Id $app.'App ID').assignments
            foreach ($Assignment in $Assignments) {
                try {
                    Remove-AppAssignment -Id $app.'App ID' -AssignmentId $Assignment.id
                    Write-Host "✅ Successfully removed App Assignment from $($app.'App Name')" -ForegroundColor Green
                }
                catch {
                    Write-Host "❌ Unable to remove App Assignment from $($app.'App Name')" -ForegroundColor Red
                }

            }
        }
    }
    #endregion assignment

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
                    $appConfigCODisplayName = "$appConfigPrefix`CO_$($($app.'App Name').Replace(' ',''))"
                    $appConfigBYODDisplayName = "$appConfigPrefix`BYOD_$($($app.'App Name').Replace(' ',''))"
                    $appConfigCOJSON = @"
{
    "@odata.type": "#microsoft.graph.iosMobileAppConfiguration",
    "displayName": "$appConfigCODisplayName",
    "description": "",
    "targetedMobileApps": [
        "$($app.'App ID')"
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
                    $appConfigBYODJSON = @"
{
    "@odata.type": "#microsoft.graph.iosMobileAppConfiguration",
    "displayName": "$appConfigBYODDisplayName",
    "description": "",
    "targetedMobileApps": [
        "$($app.'App ID')"
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
                    $appConfigCODisplayName = "$appConfigPrefix`_CO$($($app.'App Name').Replace(' ',''))"
                    $appConfigBYODDisplayName = "$appConfigPrefix`_BYOD$($($app.'App Name').Replace(' ',''))"
                    $appConfigSettingsJSON = @"
{
    "kind": "androidenterprise#managedConfiguration",
    "productId": "app:$($app.'App Package')",
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
                    $appConfigCOJSON = @"
{
    "@odata.type": "#microsoft.graph.androidManagedStoreAppConfiguration",
    "displayName": "$appConfigCODisplayName",
    "description": "",
    "profileApplicability": "androidDeviceOwner",
    "targetedMobileApps": [
        "$($app.'App ID')"
    ],
    "packageId": "app:$($app.'App Package')",
    "payloadJson": "$appConfigSettingsEncoded",
    "permissionActions": [],
    "connectedAppsEnabled": false,
}
"@
                    $appConfigBYODJSON = @"
{
    "@odata.type": "#microsoft.graph.androidManagedStoreAppConfiguration",
    "displayName": "$appConfigBYODDisplayName",
    "description": "",
    "profileApplicability": "androidWorkProfile",
    "targetedMobileApps": [
        "$($app.'App ID')"
    ],
    "packageId": "app:$($app.'App Package')",
    "payloadJson": "$appConfigSettingsEncoded",
    "permissionActions": [],
    "connectedAppsEnabled": false,
}
"@
                }
            }

            if ($($app.'App Package') -in $appsIntuneMAM) {

                if ($appConfigOwnership -eq 'Both' -or $appConfigOwnership -eq 'COPE') {
                    $appConfigCOExists = Get-ManagedDeviceAppConfig | Where-Object { $_.displayName -eq $appConfigCODisplayName }
                    if ($null -ne $appConfigCOExists) {
                        Write-Host "⏭  A COPE App Config profile already exists for $($app.'App Name'), skipping creation" -ForegroundColor Cyan

                    }
                    else {
                        New-ManagedDeviceAppConfig -JSON $appConfigCOJSON
                        Write-Host "✅ Successfully created COPE $appType App Config profile $appConfigCODisplayName for $($app.'App Name')" -ForegroundColor Green
                    }
                }
                if ($appConfigOwnership -eq 'Both' -or $appConfigOwnership -eq 'BYOD') {
                    $appConfigBYODExists = Get-ManagedDeviceAppConfig | Where-Object { $_.displayName -eq $appConfigBYODDisplayName }
                    if ($null -ne $appConfigBYODExists) {
                        Write-Host "⏭  A BYOD App Config profile already exists for $($app.'App Name'), skipping creation" -ForegroundColor Cyan
                    }
                    else {
                        New-ManagedDeviceAppConfig -JSON $appConfigBYODJSON
                        Write-Host "✅ Successfully created BYOD $appType App Config profile $appConfigBYODDisplayName for $($app.'App Name')" -ForegroundColor Green
                    }
                }
            }
            else {
                Write-Host "⏭  Skipping creation of App Config profile as $($app.'App Name') as does not support IntuneMAMUPN settings." -ForegroundColor Cyan
            }
        }
    }
    #endregion App Config

    #endregion Script

    #region Script Relaunch
    Write-Host "`n✨ All Assignment Settings Complete" -ForegroundColor Green
    $relaunchTitle = '♻  Relaunch the Script'
    $relaunchQuestion = 'Do you want to relaunch the Script?'
    $relaunchChoices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $relaunchChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $relaunchChoices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
    $relaunchDecision = $Host.UI.PromptForChoice($relaunchTitle, $relaunchQuestion, $relaunchChoices, 1)
    #endregion Script Relaunch

}
until ($relaunchDecision -eq 1)
