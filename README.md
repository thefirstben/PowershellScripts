**Requirements for all my PS Scripts** : Powershell 7+, i do not create script for older PS since PS7 is available on most OS.
Many functions will work on older Powershell versions, but since Microsoft will not do any update to Powershell 5 and lower (and there are multiple existing bugs) i do not plan and doing the support for them ;)

I just uploaded all my functions that i used for all kinds of stuff in iClic-Shared.psm1, do not hesitate to give me feedback if you find anything that is not working as expected.
I will add function descriptions as soon as i find a little time

## Bulk Enterprise App Permission Export

`Get-AzureServicePrincipalPermissionsForAllApps` reports granted application and delegated permissions. It retrieves service principals and their role definitions once, collects delegated grants tenant-wide, and queries application-role assignments once per selected app. Collections are paginated automatically; additional page requests and throttling retries may be necessary.

```powershell
$ServicePrincipalPermission = Get-AzureServicePrincipalPermissionsForAllApps -Token $tokens.AppToken
$ServicePrincipalPermission | Export-Csv -Path './ServicePrincipalPermissions.csv' -NoTypeInformation
```

By default, `ServiceIdentity`, `ManagedIdentity`, and `SocialIdp` are excluded, matching the existing audit workflow. To include all service principal types, including managed identities:

```powershell
Get-AzureServicePrincipalPermissionsForAllApps -Token $tokens.AppToken -ExcludedServicePrincipalTypes @()
```

`-HideGUID`, `-HideDate`, and `-Readable` are supported, as in `Get-AzureServicePrincipalPermissions`. Delegated grants produce one row per scope and preserve admin versus user consent. Graph request failures terminate the function before it emits report rows; assignments with unresolved role metadata remain in the output with their IDs.

The token needs permission to read service principals, application-role assignments, and tenant-wide delegated grants (for example, Microsoft Graph `Directory.Read.All` with admin consent). This report shows granted permissions, not unconsented permissions configured on app registrations. Token lifetime and tenant throttling still apply; runtime should be measured in the target tenant.
