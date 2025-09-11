# iOS
$appType = 'ios'
$appPackage = 'bundleId'
$appConfigCOPrefix = 'POC_IOS_D_CO_'
$appConfigBYODPrefix = 'POC_IOS_D_BYOD_'
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
)

# android
$appType = 'android'
$appPackage = 'packageId'
$appConfigCOPrefix = 'POC_AND_AE_D_CO_'
$appConfigBYODPrefix = 'POC_AND_AE_D_BYOD_'
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

$apps = @(Get-MobileApp | Where-Object { (!($_.'@odata.type').Contains('managed')) -and ($_.'@odata.type').contains($appType) } | Select-Object -Property @{Label = 'App Type'; Expression = '@odata.type' }, @{Label = 'App Name'; Expression = 'displayName' }, @{Label = 'App Publisher'; Expression = 'publisher' }, @{Label = 'App ID'; Expression = 'id' }, @{Label = 'App Package'; Expression = $appPackage } | Out-ConsoleGridView -Title 'Select Apps to Assign' -OutputMode Multiple)

foreach ($app in $apps) {
    if ($($app.'App Package') -in $appsIntuneMAM) {

        switch ($appType) {
            'ios' {
                $appConfigCODisplayName = "$appConfigCOPrefix$($($app.'App Name').Replace(' ',''))"
                $appConfigBYODDisplayName = "$appConfigBYODPrefix$($($app.'App Name').Replace(' ',''))"
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
                $appConfigCODisplayName = "$appConfigCOPrefix$($($app.'App Name').Replace(' ',''))"
                $appConfigBYODDisplayName = "$appConfigBYODPrefix$($($app.'App Name').Replace(' ',''))"
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
$appConfigSettingsEncoded  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$appConfigSettingsString"))

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

        New-ManagedDeviceAppConfig -JSON $appConfigCOJSON
        Write-Host "Successfully created $appType App Config profile $appConfigCODisplayName for $($app.'App Name')" -ForegroundColor Green

        New-ManagedDeviceAppConfig -JSON $appConfigBYODJSON
        Write-Host "Successfully created $appType App Config profile $appConfigBYODDisplayName for $($app.'App Name')" -ForegroundColor Green

    }
    else {
        Write-Host "Skipping creation of App Config profile as $($app.'App Name') as does not support IntuneMAMUPN settings." -ForegroundColor Cyan
    }
}
