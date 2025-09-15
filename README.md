# 📲 IntuneAppAssigner

The IntuneAppAssigner script is a PowerShell tool designed to facilitate the bulk assignment of mobile applications within Microsoft Intune.
It provides an interactive interface for administrators to select applications, define assignment parameters, and apply these settings across user and device groups efficiently.

## ⚠ Public Preview Notice

IntuneAppAssigner is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🌟 Features

Once authenticated navigate the options to bulk assign your **Android**, **iOS/iPadOS**, or **macOS** apps, with the following options:

- 📱 Select the app type
- 🎁 Select the apps you want to update the assignments of
- 🪧 Select whether you want to create Android/iOS App Config profiles for COPE, BYOD, or both
- 🔀 Select whether you want to replace existing or add to existing assignments
- 💽 Select the installation intent of the assignment from Required or Available
- 🫂 Select the group for assignment from 'All users', 'All devices', or an Entra ID group
- 🔄 Select whether you want use Assignment filters and the mode from 'Include' or 'Exclude'
- 🗒 Select the Assignment Filter you wish to use as part of the assignment

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows and macOS
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - `Microsoft.PowerShell.ConsoleGuiTools` module should be installed when using PowerShell 7, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account

## 🔄 Updates

- **v0.2.1**
  - Bug fixes
- v0.2.0
  - Supports macOS apps
- v0.1.3
  - Logic and interface improvements
- v0.1.2
  - Bug fixes
- v0.1.1
  - Updated to add App Config profiles for IntuneMAMUPN apps
- v0.1.0
  - Initial release

## ⏯ Usage

Running the script without any parameters for interactive authentication:

```powershell
.\IntuneAppAssigner.ps1
```

OR

Run the script with the your Entra ID Tenant ID passed to the `tenantID` parameter:

```powershell
.\IntuneAppAssigner.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099'
```

![AutoPilotGroupTagger Authentication using tenantID](img/agt-demo-auth-tenant.gif)

OR

Create an Entra ID App Registration with the following Graph API Application permissions:

- `DeviceManagementApps.ReadWrite.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementApps.ReadWrite.All`
- `Group.Read.All`

Create an App Secret for the App Registration to be used when running the script.

Then run the script with the corresponding Entra ID Tenant ID, AppId and AppSecret passed to the parameters:

```powershell
.\IntuneAppAssigner.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e63-baaf-a35123164d78' -appSecret 'g708Q~uot4xo9dU_1TjGQIuUr0UyBHNZmY2m3cy6'
```

## 🎬 Demos

Coming soon.

## 🚑 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ennnbeee/IntuneAppAssigner/issues) page
2. Open a new issue if needed

- 📝 [Submit Feedback](https://github.com/ennnbeee/IntuneAppAssigner/issues/new?labels=feedback)
- 🐛 [Report Bugs](https://github.com/ennnbeee/IntuneAppAssigner/issues/new?labels=bug)
- 💡 [Request Features](https://github.com/ennnbeee/IntuneAppAssigner/issues/new?labels=enhancement)

Thank you for your support.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Created by [Nick Benton](https://github.com/ennnbeee) of [odds+endpoints](https://www.oddsandendpoints.co.uk/)
