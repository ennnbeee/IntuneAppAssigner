<#PSScriptInfo

.VERSION 0.5
.GUID 63c8809e-5c8a-4ddc-82a4-29706992802f
.AUTHOR Nick Benton
.COMPANYNAME
.COPYRIGHT GPL
.TAGS Graph Intune Windows Autopilot GroupTags
.LICENSEURI https://github.com/ennnbeee/AutopilotGroupTagger/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/AutopilotGroupTagger
.ICONURI https://raw.githubusercontent.com/ennnbeee/AutopilotGroupTagger/refs/heads/main/img/agt-icon.png
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.1 - Initial release
v0.2 - Included functionality to update group tags based on Purchase order
v0.3 - Updated logic around Autopilot device selection
v0.4 - Configured to run on PowerShell 5
v0.4.1 - Updated authentication and module detection
v0.4.2 - Bug fixes and improvements
v0.4.3 - Improvements to user interface and error handling
v0.4.4 - Added 'WhatIf' mode, and updated user experience of output of the progress of Group Tag updates
v0.4.5 - Function rework to support PowerShell gallery requirements
v0.5 - Now supports PowerShell 7 on macOS, removal of Group Tags, and Dynamic Group creation

.PRIVATEDATA
#>

<#
.SYNOPSIS
Autopilot GroupTagger - Update Autopilot Device Group Tags in bulk.

.DESCRIPTION
The Autopilot GroupTagger script is designed to allow for bulk updating of Autopilot device group tags in Microsoft Intune.
The script will connect to the Microsoft Graph API and retrieve all Autopilot devices, then allow for bulk updating of group tags based on various criteria.

.PARAMETER whatIf
Switch to enable WhatIf mode to simulate changes.

.PARAMETER createGroups
Switch to enable the creation of dynamic groups based on Group Tags.

.PARAMETER tenantId
Provide the Id of the Entra ID tenant to connect to.

.PARAMETER appId
Provide the Id of the Entra App registration to be used for authentication.

.PARAMETER appSecret
Provide the App secret to allow for authentication to graph

.EXAMPLE
Interactive Authentication
.\AutopilotGroupTagger.ps1

.EXAMPLE
Pass through Authentication
.\AutopilotGroupTagger.ps1 -tenantId '437e8ffb-3030-469a-99da-e5b527908099'

.EXAMPLE
App Authentication
.\AutopilotGroupTagger.ps1 -tenantId '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e72-baaf-a35126464d67' -appSecret 'g708Q~uof4xo9dU_1EjGQIuUr0UyBHNZmY2mcdy6'

.NOTES
Version:        0.5
Author:         Nick Benton
WWW:            oddsandendpoints.co.uk
Creation Date:  10/02/2025
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
Function Connect-ToGraph {
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

    Process {
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
Function Get-MobileApp() {
    [cmdletbinding()]

    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileApps'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get).Value
    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
Function Get-DeviceFilter() {

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/assignmentFilters'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get).Value
    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
Function Get-MDMGroup() {

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
        (Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = 'eventual' }).Value
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function Get-ApplicationAssignment() {

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
        (Invoke-MgGraphRequest -Uri $uri -Method Get)
    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
Function Remove-ApplicationAssignment() {

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        $Id,
        [parameter(Mandatory = $true)]
        $AssignmentId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/assignments/$AssignmentId"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method Delete)
    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
Function Add-ApplicationAssignment() {

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Id,

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,

        [parameter(Mandatory = $true)]
        [ValidateSet('Available', 'Required')]
        [ValidateNotNullOrEmpty()]
        $InstallIntent,

        [parameter(Mandatory = $false)]
        $FilterID,

        [ValidateSet('Include', 'Exclude')]
        $FilterMode,

        [parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Devices')]
        [ValidateNotNullOrEmpty()]
        $All,

        [parameter(Mandatory = $true)]
        [ValidateSet('Replace', 'Add')]
        $Action
    )

    $graphApiVersion = 'beta'
    $Resource = "deviceAppManagement/mobileApps/$Id/assign"

    try {
        $TargetGroups = @()

        If ($Action -eq 'Add') {
            # Checking if there are Assignments already configured
            $Assignments = (Get-ApplicationAssignment -Id $Id).assignments
            if (@($Assignments).count -ge 1) {
                foreach ($Assignment in $Assignments) {

                    If (($null -ne $TargetGroupId) -and ($TargetGroupId -eq $Assignment.target.groupId)) {
                        Write-Host 'The App is already assigned to the Group' -ForegroundColor Yellow
                    }
                    ElseIf (($All -eq 'Devices') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')) {
                        Write-Host 'The App is already assigned to the All Devices Group' -ForegroundColor Yellow
                    }
                    ElseIf (($All -eq 'Users') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')) {
                        Write-Host 'The App is already assigned to the All Users Group' -ForegroundColor Yellow
                    }
                    Else {
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
        $Target | Add-Member -MemberType NoteProperty -Name 'intent' -Value $InstallIntent

        $TargetGroup = New-Object -TypeName psobject
        if ($TargetGroupId) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $TargetGroupId
        }
        else {
            if ($All -eq 'Users') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
            }
            ElseIf ($All -eq 'Devices') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allDevicesAssignmentTarget'
            }
        }

        if ($FilterMode) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value $FilterID
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value $FilterMode
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
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}

#endregion

#region intro
Write-Host '
 _______         __                __ __         __
|   _   |.--.--.|  |_.-----.-----.|__|  |.-----.|  |_
|       ||  |  ||   _|  _  |  _  ||  |  ||  _  ||   _|
|___|___||_____||____|_____|   __||__|__||_____||____|
                           |__|
' -ForegroundColor Cyan
Write-Host '
 _______                          _______
|     __|.----.-----.--.--.-----.|_     _|.---.-.-----.-----.-----.----.
|    |  ||   _|  _  |  |  |  _  |  |   |  |  _  |  _  |  _  |  -__|   _|
|_______||__| |_____|_____|   __|  |___|  |___._|___  |___  |_____|__|
                          |__|                  |_____|_____|
' -ForegroundColor Red

Write-Host 'Intune AppAssigner - Update Mobile Apps Assignments in bulk.' -ForegroundColor Green
Write-Host 'Nick Benton - oddsandendpoints.co.uk' -NoNewline;
Write-Host ' | Version' -NoNewline; Write-Host ' 0.1 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2025-03-17' -ForegroundColor Magenta
Write-Host ''
Write-Host 'If you have any feedback, please open an issue at https://github.com/ennnbeee/IntuneAppAssigner/issues' -ForegroundColor Cyan
Write-Host ''
#endregion intro

#region variables
$scopes = 'DeviceManagementManagedDevices.ReadWrite.All,DeviceManagementConfiguration.ReadWrite.All,DeviceManagementApps.ReadWrite.All'
$requiredScopes = @('Device.Read.All', 'DeviceManagementServiceConfig.ReadWrite.All', 'DeviceManagementManagedDevices.Read.All', 'Group.ReadWrite.All')
[String[]]$scopes = $requiredScopes -join ', '
$rndWait = Get-Random -Minimum 1 -Maximum 2
#endregion variables

#region module check
if ($PSVersionTable.PSVersion.Major -eq 7) {
    $modules = @('Microsoft.Graph.Authentication', 'Microsoft.PowerShell.ConsoleGuiTools')
}
else {
    $modules = @('Microsoft.Graph.Authentication')
}
foreach ($module in $modules) {
    Write-Host "Checking for $module PowerShell module..." -ForegroundColor Cyan
    Write-Host ''
    If (!(Get-Module -Name $module -ListAvailable)) {
        Install-Module -Name $module -Scope CurrentUser -AllowClobber
    }
    Write-Host "PowerShell Module $module found." -ForegroundColor Green
    Write-Host ''
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
    Write-Host ''
    Write-Host "Successfully connected to Microsoft Graph tenant $($context.TenantId)." -ForegroundColor Green
}
catch {
    Write-Error $_.Exception.Message
    Exit
}
#endregion app auth

#region scopes
$currentScopes = $context.Scopes
# Validate required permissions
$missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host 'WARNING: The following scope permissions are missing:' -ForegroundColor Red
    $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host 'Please ensure these permissions are granted to the app registration for full functionality.' -ForegroundColor Yellow
    exit
}
Write-Host ''
Write-Host 'All required scope permissions are present.' -ForegroundColor Green
#endregion scopes

Do {

    #region Script
    Clear-Host
    $rndWait = '1'
    Write-Host '************************************************************************************'
    Write-Host '****    Welcome to the Microsoft Intune App Assignment Tool                     ****' -ForegroundColor Green
    Write-Host '****    Please select the Mobile App type to Assign                             ****' -ForegroundColor Cyan
    Write-Host '************************************************************************************'
    Write-Host
    Write-Host ' Please Choose one of the options below: ' -ForegroundColor Yellow
    Write-Host
    Write-Host ' (1) Android App Assignment' -ForegroundColor Green
    Write-Host
    Write-Host ' (2) iOS App Assignment' -ForegroundColor Green
    Write-Host
    Write-Host ' (E) EXIT SCRIPT ' -ForegroundColor Red
    Write-Host
    $ChoiceA_Number = ''
    $ChoiceA_Number = Read-Host -Prompt 'Based on which App type, please type 1, 2, or E to exit the script, then press enter '
    while ( !($ChoiceA_Number -eq '1' -or $ChoiceA_Number -eq '2' -or $ChoiceA_Number -eq 'E')) {
        $ChoiceA_Number = Read-Host -Prompt 'Based on which App type, please type 1, 2, or E to exit the script, then press enter '
    }
    if ($ChoiceA_Number -eq 'E') {
        Break
    }
    if ($ChoiceA_Number -eq '1') {
        $AppType = 'android'
    }
    if ($ChoiceA_Number -eq '2') {
        $AppType = 'ios'
    }

    Write-Host 'Please select the Apps you wish to modify assignments from the pop-up' -ForegroundColor Cyan
    Start-Sleep -Seconds $rndWait
    $Apps = @(Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($AppType) } | Select-Object -Property @{Label = 'App Type'; Expression = '@odata.type' }, @{Label = 'App Name'; Expression = 'displayName' }, @{Label = 'App Publisher'; Expression = 'publisher' }, @{Label = 'App ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Apps to Assign...')
    while ($Apps.count -eq 0) {
        $Apps = @(Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($AppType) } | Select-Object -Property @{Label = 'App Type'; Expression = '@odata.type' }, @{Label = 'App Name'; Expression = 'displayName' }, @{Label = 'App Publisher'; Expression = 'publisher' }, @{Label = 'App ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Apps to Assign...')
    }
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host '************************************************************************************'
    Write-Host '****    Welcome to the Microsoft Intune App Assignment Tool                     ****' -ForegroundColor Green
    Write-Host '****    This Script will allow bulk assignment of Apps to User and Devices      ****' -ForegroundColor Cyan
    Write-Host '************************************************************************************'
    Write-Host
    Write-Host ' Please Choose one of the options below:' -ForegroundColor Yellow
    Write-Host
    Write-Host ' (1) Replace Existing Assignments' -ForegroundColor Green
    Write-Host
    Write-Host ' (2) Add to Existing Assignments' -ForegroundColor Green
    Write-Host
    Write-Host ' (E) EXIT SCRIPT ' -ForegroundColor Red
    Write-Host
    $ChoiceB_Number = ''
    $ChoiceB_Number = Read-Host -Prompt 'Based on which Assignment Action, please type 1, 2, or E to exit the script, then press enter '
    while ( !($ChoiceB_Number -eq '1' -or $ChoiceB_Number -eq '2' -or $ChoiceB_Number -eq 'E')) {
        $ChoiceB_Number = Read-Host -Prompt 'Based on which Assignment Action, please type 1, 2, or E to exit the script, then press enter '
    }
    if ($ChoiceB_Number -eq 'E') {
        Break
    }
    if ($ChoiceB_Number -eq '1') {
        $Action = 'Replace'
    }
    if ($ChoiceB_Number -eq '2') {
        $Action = 'Add'
    }


    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host '************************************************************************************'
    Write-Host '****    Welcome to the Microsoft Intune App Assignment Tool                     ****' -ForegroundColor Green
    Write-Host '****    Select the Assignment Group                                             ****' -ForegroundColor Cyan
    Write-Host '************************************************************************************'
    Write-Host
    Write-Host ' Please Choose one of the options below:' -ForegroundColor Yellow
    Write-Host
    Write-Host " (1) Assign Apps as 'Required'" -ForegroundColor Green
    Write-Host
    Write-Host " (2) Assign Apps as 'Available'" -ForegroundColor Green
    Write-Host
    Write-Host ' (3) Remove All Assignments' -ForegroundColor Green
    Write-Host
    Write-Host ' (E) EXIT SCRIPT ' -ForegroundColor Red
    Write-Host
    $ChoiceC_Number = ''
    $ChoiceC_Number = Read-Host -Prompt 'Based on which Install Intent type, please type 1, 2, 3 or E to exit the script, then press enter '
    while ( !($ChoiceC_Number -eq '1' -or $ChoiceC_Number -eq '2' -or $ChoiceC_Number -eq '3' -or $ChoiceC_Number -eq 'E')) {
        $ChoiceC_Number = Read-Host -Prompt 'Based on which Install Intent type, please type 1, 2, 3 or E to exit the script, then press enter '
    }
    if ($ChoiceC_Number -eq 'E') {
        Break
    }
    if ($ChoiceC_Number -eq '1') {
        $InstallIntent = 'Required'
    }
    if ($ChoiceC_Number -eq '2') {
        $InstallIntent = 'Available'
    }
    if ($ChoiceC_Number -eq '3') {
        $InstallIntent = 'Remove'
    }
    Clear-Host
    Start-Sleep -Seconds $rndWait

    if ($InstallIntent -ne 'Remove') {
        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host '************************************************************************************'
        Write-Host '****    Welcome to the Microsoft Intune App Assignment Tool                     ****' -ForegroundColor Green
        Write-Host '****    Select the Assignment Group                                             ****' -ForegroundColor Cyan
        Write-Host '************************************************************************************'
        Write-Host
        Write-Host ' Please Choose one of the options below: ' -ForegroundColor Yellow
        Write-Host
        Write-Host " (1) Assign Apps to 'All Users'" -ForegroundColor Green
        Write-Host
        Write-Host " (2) Assign Apps to 'All Devices'" -ForegroundColor Green
        Write-Host
        Write-Host ' (3) Assign Apps to a Group' -ForegroundColor Green
        Write-Host
        Write-Host ' (E) EXIT SCRIPT ' -ForegroundColor Red
        Write-Host
        $ChoiceD_Number = ''
        $ChoiceD_Number = Read-Host -Prompt 'Based on which assignment type, please type 1, 2, 3, or E to exit the script, then press enter '
        while ( !($ChoiceD_Number -eq '1' -or $ChoiceD_Number -eq '2' -or $ChoiceD_Number -eq '3' -or $ChoiceD_Number -eq 'E')) {
            $ChoiceD_Number = Read-Host -Prompt 'Based on which assignment type, please type 1, 2, 3, or E to exit the script, then press enter '
        }
        if ($ChoiceD_Number -eq 'E') {
            Break
        }
        if ($ChoiceD_Number -eq '1') {
            $AssignmentType = 'Users'
        }
        if ($ChoiceD_Number -eq '2') {
            $AssignmentType = 'Devices'
            if ($ChoiceC_Number -eq 2) {
                Write-Host "Assigning Apps as 'Available' to the 'All Devices' group will not work, please re-run the script and don't make the same mistake again..." -ForegroundColor Red
                Break
            }
        }
        if ($ChoiceD_Number -eq '3') {
            $AssignmentType = 'Group'
            if ($ChoiceC_Number -eq 2) {
                Write-Host "Assigning Apps as 'Available' to Device groups will not work, please ensure you select a group of Users" -ForegroundColor yellow
            }
            $GroupName = Read-Host 'Please enter a search term for the Assignment Group'
            While ($GroupName.Length -eq 0) {
                $GroupName = Read-Host 'Please enter a search term for the Assignment Group'
            }
            Write-Host
            Start-Sleep -Seconds $rndWait
            Write-Host 'Please select the Group for the assignment...' -ForegroundColor Cyan
            Start-Sleep -Seconds $rndWait
            $Group = Get-MDMGroup -GroupName $GroupName | Select-Object -Property @{Label = 'Group Name'; Expression = 'displayName' }, @{Label = 'Group ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Group...'

            while ($Group.Count -gt 1) {
                Write-Host 'Please select only one Group...' -ForegroundColor Yellow
                $Group = Get-MDMGroup -GroupName $GroupName | Select-Object -Property @{Label = 'Group Name'; Expression = 'displayName' }, @{Label = 'Group ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Group...'
            }
        }
        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host '************************************************************************************'
        Write-Host '****    Welcome to the Microsoft Intune App Assignment Tool                     ****' -ForegroundColor Green
        Write-Host '****    Select the Device Filter                                                ****' -ForegroundColor Cyan
        Write-Host '************************************************************************************'
        Write-Host
        Write-Host ' Please Choose one of the options below: ' -ForegroundColor Yellow
        Write-Host
        Write-Host ' (1) Include Device Filter' -ForegroundColor Green
        Write-Host
        Write-Host ' (2) Exclude Device Filter' -ForegroundColor Green
        Write-Host
        Write-Host ' (3) No Filters' -ForegroundColor Green
        Write-Host
        Write-Host ' (E) EXIT SCRIPT ' -ForegroundColor Red
        Write-Host
        $ChoiceE_Number = ''
        $ChoiceE_Number = Read-Host -Prompt 'Based on which Device Filter, please type 1, 2, 3, or E to exit the script, then press enter'
        while ( !($ChoiceE_Number -eq '1' -or $ChoiceE_Number -eq '2' -or $ChoiceE_Number -eq '3' -or $ChoiceE_Number -eq 'E')) {
            $ChoiceE_Number = Read-Host -Prompt 'Based on which Device Filter, please type 1, 2, 3, or E to exit the script, then press enter'
        }
        if ($ChoiceE_Number -eq 'E') {
            Break
        }
        if ($ChoiceE_Number -eq '1') {
            $Filtering = 'Yes'
            $FilterMode = 'Include'
        }
        if ($ChoiceE_Number -eq '2') {
            $Filtering = 'Yes'
            $FilterMode = 'Exclude'
        }
        if ($ChoiceE_Number -eq '3') {
            $Filtering = 'No'
        }
        Start-Sleep -Seconds $rndWait
        If ($Filtering -eq 'Yes') {
            Write-Host 'Please select the Device Filter for the assignment...' -ForegroundColor Cyan
            Start-Sleep -Seconds $rndWait
            $Filter = Get-DeviceFilter | Where-Object { ($_.platform) -like ("*$AppType*") } | Select-Object -Property @{Label = 'Filter Name'; Expression = 'displayName' }, @{Label = 'Filter Rule'; Expression = 'rule' }, @{Label = 'Filter ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Device Filter...'

            while ($Filter.Count -gt 1) {
                Write-Host 'Please select only one Device Filter...' -ForegroundColor Yellow
                $Filter = Get-DeviceFilter | Where-Object { ($_.platform) -like ("*$AppType*") } | Select-Object -Property @{Label = 'Filter Name'; Expression = 'displayName' }, @{Label = 'Filter Rule'; Expression = 'rule' }, @{Label = 'Filter ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Device Filter...'
            }
        }
    }
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host 'The following Apps have been selected:' -ForegroundColor Cyan
    $($Apps.'App Name') | Format-List
    Write-Host
    If ($InstallIntent -ne 'Remove') {
        Write-Host 'The following Assignment Action has been selected:' -ForegroundColor Cyan
        Write-Host "$Action"
        Write-Host
        Write-Host 'The following Assignment Group has been selected:' -ForegroundColor Cyan
        if ($AssignmentType -eq 'Group') {
            Write-Host "$($Group.'Group Name')"
        }
        Else {
            Write-Host "All $AssignmentType"
        }
        Write-Host
        if ($Filtering -eq 'Yes') {
            Write-Host 'The following Device Filter has been selected:' -ForegroundColor Cyan
            Write-Host "$($Filter.'Filter Name')"
        }
    }
    Else {
        Write-Host 'Assignments will be removed.' -ForegroundColor Red
    }

    Write-Host
    Write-Warning 'Please confirm these settings are correct before continuing' -WarningAction Inquire
    Clear-Host
    Start-Sleep -Seconds $rndWait

    If ($InstallIntent -ne 'Remove') {
        If ($AssignmentType -eq 'Group') {
            If ($Filtering -eq 'Yes') {
                foreach ($App in $Apps) {
                    Add-ApplicationAssignment -Id $App.'App ID' -InstallIntent $InstallIntent -TargetGroupId $Group.'Group ID' -FilterMode $FilterMode -FilterID $Filter.'Filter ID' -Action $Action
                    Write-Host "Successfully Assigned App: $($App.'App Name') as $InstallIntent to Group $($Group.'Group Name') with Filter $($Filter.'Filter Name')" -ForegroundColor Green
                }
            }
            Else {
                foreach ($App in $Apps) {
                    Add-ApplicationAssignment -Id $App.'App ID' -InstallIntent $InstallIntent -TargetGroupId $Group.'Group ID' -Action $Action
                    Write-Host "Successfully Assigned App: $($App.'App Name') as $InstallIntent to Group $($Group.'Group Name')" -ForegroundColor Green
                }
            }
        }
        Else {
            If ($Filtering -eq 'Yes') {
                foreach ($App in $Apps) {
                    Add-ApplicationAssignment -Id $App.'App ID' -InstallIntent $InstallIntent -All $AssignmentType -FilterMode $FilterMode -FilterID $Filter.'Filter ID' -Action $Action
                    Write-Host "Successfully Assigned App $($App.'App Name') as $InstallIntent to All $AssignmentType with Filter $($Filter.'Filter Name')" -ForegroundColor Green
                }
            }
            Else {
                foreach ($App in $Apps) {
                    Add-ApplicationAssignment -Id $App.'App ID' -InstallIntent $InstallIntent -All $AssignmentType -Action $Action
                    Write-Host "Successfully Assigned App $($App.'App Name') as $InstallIntent to All $AssignmentType" -ForegroundColor Green
                }
            }
        }
    }
    Else {
        Foreach ($App in $Apps) {
            $Assignments = (Get-ApplicationAssignment -Id $App.'App ID').assignments
            foreach ($Assignment in $Assignments) {
                Try {
                    Remove-ApplicationAssignment -Id $App.'App ID' -AssignmentId $Assignment.id
                    Write-Host "Successfully removed App Assignment from $($App.'App Name')" -ForegroundColor Green
                }
                Catch {
                    Write-Host "Unable to remove App Assignment from $($App.'App Name')" -ForegroundColor Red
                }

            }
        }
    }
    #endregion Script

    # Script Relaunch
    Write-Host
    Write-Host 'All Assignment Settings Complete' -ForegroundColor Green
    Write-Host
    $Title = 'Relaunch the Script'
    $Question = 'Do you want to relaunch the Script?'

    $Choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $Choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $Choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

    $Decision = $Host.UI.PromptForChoice($Title, $Question, $Choices, 1)



}
until ($Decision -eq 1)
