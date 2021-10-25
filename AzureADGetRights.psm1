Function Get-AzureSubscriptions {
 az account list --all --query '[].{id:id, name:name}' -o json | convertfrom-json | select-object id,name
}

Function Get-AzureADUserRights {
 Param (
  [Parameter(Mandatory=$true)]$UserName,
  [Parameter(Mandatory=$true)]$SubscriptionID,
  $SubscriptionName,
  $UserDisplayName
 )
 #Add check for UserName and Subscription

 #If the subscription name does not exist replace it with the subscription ID
 if (! $SubscriptionName) { $SubscriptionName = $Subscription }
 if (! $UserDisplayName) { $UserDisplayName = $UserName }

 az role assignment list --all --assignee $UserName `
  --include-classic-administrators --include-groups `
  --include-inherited --subscription $SubscriptionID `
  --query '[].{principalName:principalName, principalType:principalType, roleDefinitionName:roleDefinitionName, scope:scope, resourceGroup:resourceGroup} '`
  -o json | ConvertFrom-Json | `
    Select-object @{Name="UserUPN";Expression={$UserName}},
    @{Name="UserDisplay";Expression={$UserDisplayName}},
    @{Name="Subscription";Expression={$SubscriptionName}},
    @{Name="SubscriptionID";Expression={$SubscriptionID}},
    resourceGroup,principalType,roleDefinitionName,
    @{Name="ResourceName";Expression={$_.scope.split("/")[-1]}},
    scope,principalName
}

Function Get-AzureSubscriptionNameFromID {
 Param (
  $SubscriptionID,
  $SubscriptionList = $(Get-AzureSubscriptions)
 )
 ($SubscriptionList | Where-Object id -eq $SubscriptionID).Name
}
Function Get-AzureGetAllUserAssignedRigts {
 Param (
  $ExportFileLocation = "C:\Temp\AzureAllUserList.csv",
  $SubscriptionList = $(Get-AzureSubscriptions)
 )
 az ad user list --query '[].{userPrincipalName:userPrincipalName}' --output json | ConvertFrom-Json | ForEach-Object {
  $UserNameUpn = $_.userPrincipalName
  $SubscriptionList | ForEach-Object {
   Get-AzureAdUserRights -UserName $UserNameUpn -SubscriptionID $_.ID -SubscriptionName $_.Name | Export-Csv $ExportFileLocation -Append -Delimiter ";"
  }
 }
}
