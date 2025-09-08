<#PSScriptInfo

.VERSION 0.1
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
v0.1 - Initial release

.PRIVATEDATA
#>

<#
.SYNOPSIS


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
.\IntuneAppAssigner.ps1-tenantId '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e72-baaf-a35126464d67' -appSecret 'g708Q~uof4xo9dU_1EjGQIuUr0UyBHNZmY2mcdy6'

.NOTES
Version:        0.1
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
    [String]$appsecret

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
        [Parameter(Mandatory = $false)] [string]$appsecret,
        [Parameter(Mandatory = $false)] [string[]]$scopes
    )

    process {
        Import-Module Microsoft.Graph.Authentication
        $version = (Get-Module microsoft.graph.authentication | Select-Object -ExpandProperty Version).major

        if ($AppId -ne '') {
            $body = @{
                grant_type    = 'client_credentials';
                client_id     = $appId;
                client_secret = $appsecret;
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
function Get-MobileApp() {
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
function Get-AssignmentFilter() {

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
        (Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = 'eventual' }).Value
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
        (Invoke-MgGraphRequest -Uri $uri -Method Get)
    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
function Remove-AppAssignment() {

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
function Add-AppAssignment() {

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
        $installIntent,

        [parameter(Mandatory = $false)]
        $FilterID,

        [ValidateSet('Include', 'Exclude')]
        $filterMode,

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

        if ($action -eq 'Add') {
            # Checking if there are Assignments already configured
            $Assignments = (Get-AppAssignment -Id $Id).assignments
            if (@($Assignments).count -ge 1) {
                foreach ($Assignment in $Assignments) {

                    if (($null -ne $TargetGroupId) -and ($TargetGroupId -eq $Assignment.target.groupId)) {
                        Write-Host 'The App is already assigned to the Group' -ForegroundColor Yellow
                    }
                    elseif (($All -eq 'Devices') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget')) {
                        Write-Host 'The App is already assigned to the All Devices Group' -ForegroundColor Yellow
                    }
                    elseif (($All -eq 'Users') -and ($Assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')) {
                        Write-Host 'The App is already assigned to the All Users Group' -ForegroundColor Yellow
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
        if ($TargetGroupId) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $TargetGroupId
        }
        else {
            if ($All -eq 'Users') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
            }
            elseif ($All -eq 'Devices') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allDevicesAssignmentTarget'
            }
        }

        if ($filterMode) {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value $FilterID
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
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
#endregion Functions

#region intro

Write-Host 'IntuneAppAssigner - Update Mobile Apps Assignments in bulk.' -ForegroundColor Green
Write-Host 'Nick Benton - oddsandendpoints.co.uk' -NoNewline;
Write-Host ' | Version' -NoNewline; Write-Host ' 0.1 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2025-03-17' -ForegroundColor Magenta
Write-Host ''
Write-Host 'If you have any feedback, please open an issue at https://github.com/ennnbeee/IntuneAppAssigner/issues' -ForegroundColor Cyan
Write-Host ''
#endregion intro

#region variables
$requiredScopes = @('DeviceManagementApps.ReadWrite.All', 'Group.Read.All')
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
    if (!(Get-Module -Name $module -ListAvailable)) {
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
        if ((!$appId -and !$appsecret) -or ($appId -and !$appsecret) -or (!$appId -and $appsecret)) {
            Write-Host 'Missing App Details, connecting using user authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -Scopes $scopes -ErrorAction Stop
        }
        else {
            Write-Host 'Connecting using App authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -appId $appId -appSecret $appsecret -ErrorAction Stop
        }
    }
    $context = Get-MgContext
    Write-Host ''
    Write-Host "Successfully connected to Microsoft Graph tenant $($context.TenantId)." -ForegroundColor Green
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
    Write-Host ''
    Write-Host 'Please ensure these permissions are granted to the app registration for full functionality.' -ForegroundColor Yellow
    exit
}
Write-Host ''
Write-Host 'All required scope permissions are present.' -ForegroundColor Green
#endregion scopes

do {

    #region Script
    Clear-Host
    Write-Host '************************************************************************************'
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
    $choiceAppType = ''
    $choiceAppType = Read-Host -Prompt 'Based on which App type, please type 1, 2, or E to exit the script, then press enter '
    while ( $choiceAppType -notin ('1', '2', 'E')) {
        $choiceAppType = Read-Host -Prompt 'Based on which App type, please type 1, 2, or E to exit the script, then press enter '
    }
    if ($choiceAppType -eq 'E') {
        break
    }
    if ($choiceAppType -eq '1') {
        $appType = 'android'
    }
    if ($choiceAppType -eq '2') {
        $appType = 'ios'
    }

    Write-Host 'Please select the Apps you wish to modify assignments' -ForegroundColor Cyan
    Start-Sleep -Seconds $rndWait
    $apps = @()
    while ($apps.count -eq 0) {
        if ($PSVersionTable.PSVersion.Major -eq 7) {
            $apps = @(Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($appType) } | Select-Object -Property @{Label = 'App Type'; Expression = '@odata.type' }, @{Label = 'App Name'; Expression = 'displayName' }, @{Label = 'App Publisher'; Expression = 'publisher' }, @{Label = 'App ID'; Expression = 'id' } | Out-ConsoleGridView -Title 'Select Apps to Assign...' -OutputMode Multiple)

        }
        else {
            $apps = @(Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($appType) } | Select-Object -Property @{Label = 'App Type'; Expression = '@odata.type' }, @{Label = 'App Name'; Expression = 'displayName' }, @{Label = 'App Publisher'; Expression = 'publisher' }, @{Label = 'App ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Apps to Assign...')
        }
    }
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host '************************************************************************************'
    Write-Host '****    Select the assignment type                                              ****' -ForegroundColor Cyan
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
    $choiceAssignmentType = ''
    $choiceAssignmentType = Read-Host -Prompt 'Based on which Assignment Action, please type 1, 2, or E to exit the script, then press enter '
    while ( ($choiceAssignmentType -notin ('1', '2', 'E'))) {
        $choiceAssignmentType = Read-Host -Prompt 'Based on which Assignment Action, please type 1, 2, or E to exit the script, then press enter '
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

    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host '************************************************************************************'
    Write-Host '****    Select the Assignment Install Intent                                    ****' -ForegroundColor Cyan
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
    $choiceInstallIntent = ''
    $choiceInstallIntent = Read-Host -Prompt 'Based on which Install Intent type, please type 1, 2, 3 or E to exit the script, then press enter '
    while ( !($choiceInstallIntent -eq '1' -or $choiceInstallIntent -eq '2' -or $choiceInstallIntent -eq '3' -or $choiceInstallIntent -eq 'E')) {
        $choiceInstallIntent = Read-Host -Prompt 'Based on which Install Intent type, please type 1, 2, 3 or E to exit the script, then press enter '
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
    Clear-Host
    Start-Sleep -Seconds $rndWait

    if ($installIntent -ne 'Remove') {
        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host '************************************************************************************'
        Write-Host '****    Select the Assignment Target                                            ****' -ForegroundColor Cyan
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
        $choiceAssignmentTarget = ''
        $choiceAssignmentTarget = Read-Host -Prompt 'Based on which assignment type, please type 1, 2, 3, or E to exit the script, then press enter '
        while ( $choiceAssignmentTarget -notin ('1', '2', '3', 'E')) {
            $choiceAssignmentTarget = Read-Host -Prompt 'Based on which assignment type, please type 1, 2, 3, or E to exit the script, then press enter '
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
            if ($choiceInstallIntent -eq 2) {
                Write-Host "Assigning Apps as 'Available' to Device groups will not work, please ensure you select a group of Users" -ForegroundColor yellow
            }
            $groupName = Read-Host 'Please enter a search term for the Assignment Group'
            while ($groupName.Length -eq 0) {
                $groupName = Read-Host 'Please enter a search term for the Assignment Group'
            }
            Write-Host
            Start-Sleep -Seconds $rndWait
            Write-Host 'Please select the Group for the assignment...' -ForegroundColor Cyan
            Start-Sleep -Seconds $rndWait
            $assignmentGroup = Get-MDMGroup -GroupName $groupName | Select-Object -Property @{Label = 'Group Name'; Expression = 'displayName' }, @{Label = 'Group ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Group...'

            while ($assignmentGroup.Count -gt 1) {
                Write-Host 'Please select only one Group...' -ForegroundColor Yellow
                $assignmentGroup = Get-MDMGroup -GroupName $groupName | Select-Object -Property @{Label = 'Group Name'; Expression = 'displayName' }, @{Label = 'Group ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Group...'
            }
        }
        Clear-Host
        Start-Sleep -Seconds $rndWait
        Write-Host '************************************************************************************'
        Write-Host '****    Select the Assignment Filter                                            ****' -ForegroundColor Cyan
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
        $choiceAssignmentFilter = ''
        $choiceAssignmentFilter = Read-Host -Prompt 'Based on which Device Filter, please type 1, 2, 3, or E to exit the script, then press enter'
        while ( $choiceAssignmentFilter -notin ('1', '2', '3', 'E')) {
            $choiceAssignmentFilter = Read-Host -Prompt 'Based on which Device Filter, please type 1, 2, 3, or E to exit the script, then press enter'
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
            Write-Host 'Please select the Assignment Filter for the assignment...' -ForegroundColor Cyan
            Start-Sleep -Seconds $rndWait
            $assignmentFilter = Get-AssignmentFilter | Where-Object { ($_.platform) -like ("*$appType*") } | Select-Object -Property @{Label = 'Filter Name'; Expression = 'displayName' }, @{Label = 'Filter Rule'; Expression = 'rule' }, @{Label = 'Filter ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Device Filter...'

            while ($assignmentFilter.Count -gt 1) {
                Write-Host 'Please select only one Device Filter...' -ForegroundColor Yellow
                $assignmentFilter = Get-AssignmentFilter | Where-Object { ($_.platform) -like ("*$appType*") } | Select-Object -Property @{Label = 'Filter Name'; Expression = 'displayName' }, @{Label = 'Filter Rule'; Expression = 'rule' }, @{Label = 'Filter ID'; Expression = 'id' } | Out-GridView -PassThru -Title 'Select Device Filter...'
            }
        }
    }
    Clear-Host
    Start-Sleep -Seconds $rndWait
    Write-Host 'The following Apps have been selected:' -ForegroundColor Cyan
    $($apps.'App Name') | Format-List
    Write-Host
    if ($installIntent -ne 'Remove') {
        Write-Host 'The following Assignment Action has been selected:' -ForegroundColor Cyan
        Write-Host "$Action"
        Write-Host
        Write-Host 'The following Assignment Group has been selected:' -ForegroundColor Cyan
        if ($assignmentType -eq 'Group') {
            Write-Host "$($assignmentGroup.'Group Name')"
        }
        else {
            Write-Host "All $assignmentType"
        }
        Write-Host
        if ($filtering -eq 'Yes') {
            Write-Host 'The following Device Filter has been selected:' -ForegroundColor Cyan
            Write-Host "$($assignmentFilter.'Filter Name')"
        }
    }
    else {
        Write-Host 'Assignments will be removed.' -ForegroundColor Red
    }

    Write-Host
    Write-Warning 'Please confirm these settings are correct before continuing' -WarningAction Inquire
    Clear-Host
    Start-Sleep -Seconds $rndWait

    if ($installIntent -ne 'Remove') {
        if ($assignmentType -eq 'Group') {
            if ($filtering -eq 'Yes') {
                foreach ($app in $apps) {
                    Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -TargetGroupId $assignmentGroup.'Group ID' -FilterMode $filterMode -FilterID $assignmentFilter.'Filter ID' -Action $Action
                    Write-Host "Successfully Assigned App: $($app.'App Name') as $installIntent to Group $($assignmentGroup.'Group Name') with Filter $($assignmentFilter.'Filter Name')" -ForegroundColor Green
                }
            }
            else {
                foreach ($app in $apps) {
                    Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -TargetGroupId $assignmentGroup.'Group ID' -Action $Action
                    Write-Host "Successfully Assigned App: $($app.'App Name') as $installIntent to Group $($assignmentGroup.'Group Name')" -ForegroundColor Green
                }
            }
        }
        else {
            if ($filtering -eq 'Yes') {
                foreach ($app in $apps) {
                    Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -All $assignmentType -FilterMode $filterMode -FilterID $assignmentFilter.'Filter ID' -Action $Action
                    Write-Host "Successfully Assigned App $($app.'App Name') as $installIntent to All $assignmentType with Filter $($assignmentFilter.'Filter Name')" -ForegroundColor Green
                }
            }
            else {
                foreach ($app in $apps) {
                    Add-AppAssignment -Id $app.'App ID' -InstallIntent $installIntent -All $assignmentType -Action $Action
                    Write-Host "Successfully Assigned App $($app.'App Name') as $installIntent to All $assignmentType" -ForegroundColor Green
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
                    Write-Host "Successfully removed App Assignment from $($app.'App Name')" -ForegroundColor Green
                }
                catch {
                    Write-Host "Unable to remove App Assignment from $($app.'App Name')" -ForegroundColor Red
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
