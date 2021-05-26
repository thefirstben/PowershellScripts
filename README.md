# PowershellScripts

Functions of AzureADGetRights.ps1 :

Get-AzureSubscriptions : 
  What is it : List all subscription of currently connected user
  Params : None
  Usage : Get-AzureSubscriptions
  Note : N/A
  Perf : For 90 subscriptions ~0.5s

Get-AzureSubscriptionNameFromID : 
  What is it : Get the name of subscription from the ID
  Param : 
    SubscriptionID : Mandatory ; Azure Subscription ID
    SubscriptionList : Not mandatory - by default all current user subscriptions are searched, without a list it will be slower ; A list of subscription as a PS Object with the following members: ID,Name
  Usage : 
    Get-AzureSubscriptionNameFromID -SubscriptionID 00000000-0000-0000-0000-000000000000
    Get-AzureSubscriptionNameFromID -SubscriptionID 00000000-0000-0000-0000-000000000000 -SubscriptionList $SubscriptionListObj
  Note : N/A
  Perf : ~0,5s
    
Get-AzureAdUserRights
  What is it : Get all azure rights of a user for one subscription
  Param :
    UserName : Mandatory ; Azure Ad User UPN
    SubscriptionID : Mandatory ; Azure Subscription ID
    SubscriptionName : Not mandatory - by default will be the subscription ID ; Name of a subscription - if automatic will add a couple seconds to each request
  Usage :
    Get-AzureAdUserRights -UserName 'user@upn' -SubscriptionID '00000000-0000-0000-0000-000000000000' -SubscriptionName 'Subscription Name'
  Note : N/A
  Perf : ~2s
    
 Get-AzureGetAllUserAssignedRigts
  What is it : Get all azure rights for all user
  Param :
    ExportFileLocation : Location of exported file
    SubscriptionList : List of Subscription - by default all current user subscription are searched ; A list of subscription as a PS Object with the following members: ID,Name
  Note : N/A
  Perf : ~2s per user per subscription
