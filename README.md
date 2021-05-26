# Functions of AzureADGetRights.ps1 :

## Get-AzureSubscriptions
  * _What is it_ : List all subscription of currently connected user
  * _Params_ : None
  * _Usage_ : 
```powershell
Get-AzureSubscriptions
```
  * _Note_ : N/A
  * _Perf_ : For 90 subscriptions ~0.5s

## Get-AzureSubscriptionNameFromID
  * _What is it_ : Get the name of subscription from the ID
  * _Param_ :
    * SubscriptionID : Mandatory ; Azure Subscription ID
    * SubscriptionList : Not mandatory - by default all current user subscriptions are searched, without a list it will be slower ; A list of subscription as a PS Object with the following members: **ID,Name**
  * _Usage_ : 
```powershell
Get-AzureSubscriptionNameFromID -SubscriptionID 00000000-0000-0000-0000-000000000000
Get-AzureSubscriptionNameFromID -SubscriptionID 00000000-0000-0000-0000-000000000000 -SubscriptionList $SubscriptionListObj
```
  _Note_ : N/A
  _Perf_ : ~0,5s
    
## Get-AzureAdUserRights
  * _What is it_ : Get all azure rights of a user for one subscription
  * _Param_ :
    * UserName : Mandatory ; Azure Ad User UPN
    * SubscriptionID : Mandatory ; Azure Subscription ID
    * SubscriptionName : Not mandatory - by default will be the subscription ID ; Name of a subscription - if automatic will add a couple seconds to each request
  * _Usage_ :
```powershell
Get-AzureAdUserRights -UserName 'user@upn' -SubscriptionID '00000000-0000-0000-0000-000000000000' -SubscriptionName 'Subscription Name'
```
  * _Note_ : N/A
  * _Perf_ : ~2s
    
 ## Get-AzureGetAllUserAssignedRigts
  * _What is it_ : Get all azure rights for all user
  * _Param_ :
    * ExportFileLocation : Location of exported file - Default is *C:\Temp\*
    * SubscriptionList : List of Subscription - by default all current user subscription are searched ; A list of subscription as a PS Object with the following members: ID,Name
  * _Usage_ :
```powershell
Get-AzureGetAllUserAssignedRigts
```
  * _Note_ : N/A
  * _Perf_ : ~2s per user per subscription
