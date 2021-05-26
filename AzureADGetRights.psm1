Function Get-AzureSubscriptions {
 az account list --all --query '[].{id:id, name:name}' -o json | convertfrom-json | select-object id,name
}
Function Get-AzureAdUserRights {
 Param (
  [Parameter(Mandatory=$true)]$UserName,
  [Parameter(Mandatory=$true)]$SubscriptionID,
  $SubscriptionName
 )
 #Add check for UserName and Subscription

 #If the subscription name does not exist replace it with the subscription ID
 if (! $SubscriptionName) {
  $SubscriptionName = $Subscription
 }

 az role assignment list --all --assignee $UserName `
  --include-classic-administrators --include-groups `
  --include-inherited --subscription $SubscriptionID `
  --query '[].{principalName:principalName, principalType:principalType, roleDefinitionName:roleDefinitionName, scope:scope} '`
  -o json | ConvertFrom-Json | `
    Select-object @{Name="UserUPN";Expression={$UserName}},`
    @{Name="Subscription";Expression={$SubscriptionName}},`
    principalName,principalType,roleDefinitionName,scope
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
