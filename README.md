# 📲 IntuneAppAssigner

The IntuneAppAssigner script is a PowerShell tool designed to facilitate the bulk assignment of mobile applications within Microsoft Intune.
It provides an interactive interface for administrators to select applications, define assignment parameters, and apply these settings across user and device groups efficiently.

## ⚠ Public Preview Notice

IntuneAppAssigner is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🌟 Features

Once authenticated navigate the options to bulk assign your Android, iOS/iPadOS, macOS, or Windows apps, with the following options:

- 📱 Select the app type from **Android**, **iOS/iPadOS**, **macOS**, or **Windows** apps.
- 🎁 Select the apps you want to update or review the assignments.
- 🔀 Select whether you want to **replace**, **add to**, or **review** the existing assignments.
- 📝 Select whether you want to export the review of assignments to CSV.
- 💽 Select the installation intent of the assignment from **Required**, **Available**, or **Uninstall**.
- 🫂 Select the group for assignment from '**All users**', '**All devices**', or an **Entra ID group** with group usage logic built in.
- 🔄 Select whether you want use **Assignment filters** and with mode '**Include**' or '**Exclude**', with prompts where apps do not support filters.
- 🎯 Select the **Assignment Filter** you wish to use as part of the assignment
- 🪧 If Android or iOS/iPadOS apps select whether you want to create managed device **App Config profiles** for COPE, BYOD, or both.
- 🗒 Option to add a prefix to the Android or iOS/iPadOS App Config Profiles using the `appConfigPrefix` parameter.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows and macOS
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - `Microsoft.PowerShell.ConsoleGuiTools` module should be installed when using PowerShell 7, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account

## 🔄 Updates

- **v0.4.3**
  - Added option to export the review of assignments to CSV
  - Fixed issue with infinite loop when no applications are available for an OS
- v0.4.2
  - Logic improvements
- v0.4.1
  - Bug fixes
- v0.4.0
  - Supports the Uninstall assignment intent
  - Allows for review of existing assignments
- v0.3.0
  - Supports Windows app assignment
- v0.2.1
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

OR

Create an Entra ID App Registration with the following Graph API Application permissions:

- `DeviceManagementApps.ReadWrite.All`
- `DeviceManagementConfiguration.Read.All`
- `Group.Read.All`

Create an App Secret for the App Registration to be used when running the script.

Then run the script with the corresponding Entra ID Tenant ID, AppId and AppSecret passed to the parameters:

```powershell
.\IntuneAppAssigner.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e63-baaf-a35123164d78' -appSecret 'g708Q~uot4xo9dU_1TjGQIuUr0UyBHNZmY2m3cy6'
```

## 🎬 Demos

### Android Apps

![IntuneAppAssigner](img/iaa-demo-android.gif)

### iOS/iPadOS Apps

![IntuneAppAssigner](img/iaa-demo-ios.gif)

### macOS Apps

![IntuneAppAssigner](img/iaa-demo-macos.gif)

### Windows Apps

![IntuneAppAssigner](img/iaa-demo-windows.gif)

### Review App Assignments

![IntuneAppAssigner](img/iaa-demo-review.gif)

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
