# EXCLUDED Get-KPI functions from the main script to avoid cluttering the main script with too many lines of code. And they are quite old and not maintained. They are kept here for reference and potential future use.
# These functions are used to gather Key Performance Indicators (KPIs) from various systems such as Active Directory, WSUS, VMware, and Linux servers.

# KPI Active Directory
Function Get-KPIADComputer {
 Param (
  $Path="$iClic_TempPath\KPI\"
 )
 $IsOSServerOrWorkstation = {
  param($TypeOfOS)
  if ((! $TypeOfOS) -or ($TypeOfOS -eq "unknown")) { return "Unknown" }
  elseif (($TypeOfOS.contains("Server")) -or ($TypeOfOS -eq "Samba")) { return "Server" }
  else { return "Workstation" }
 }

 if ( ! (test-path $Path)) { write-Colored -Color "Red" -ColoredText "Unavailable path : $Path" ; return }

 $StartDate=$(get-date -uformat "%Y-%m-%d %T")

 get-adcomputer -filter * -properties * | Select-Object Name,
  @{name="FQDN";expression={Progress "Checking Computer: " "$($_.DNSHostName)";$_.DNSHostName}},
  @{name="OU";expression={$_.CanonicalName | ForEach-Object {(($_ -split('/'))| Select-Object -skiplast 1) -join '/'}}},
  @{name="Enabled";expression={ if ($_.Enabled) {"TRUE"} else {"FALSE"} }},
  ObjectClass,OperatingSystem,IPv4Address,
  @{name="whenChanged";expression={Format-Date $_.whenChanged}},
  @{name="whenCreated";expression={Format-Date $_.whenCreated}},
  @{name="LastLogonDate";expression={Format-Date $_.LastLogonDate}},
  @{name="TypeOS";expression={& $IsOSServerOrWorkstation $_.OperatingSystem}},
  @{name="BitlockerKeyLastCreation";expression={$Date=(Get-BitLockerKeyInAD -ServerName $_.Name | Select-Object -Last 1).Created;if ($Date){Format-Date $Date}}} |
  Export-Csv "$Path\ComputerList-$(get-date -uformat '%Y-%m-%d').csv" -encoding "unicode" -notypeinformation -Delimiter ";"
 ProgressClear
 write-host
 $EndDate=$(get-date -uformat "%Y-%m-%d %T")
 $Duration=(New-TimeSpan -Start $StartDate -End $EndDate)
 write-colored -Color "Green" -ColoredText "$($MyInvocation.MyCommand) Finished in $Duration"
}
Function Get-KPIADUser {
 Param (
  $Path="$iClic_TempPath\KPI\"
 )
 if ( ! (test-path $Path)) { write-Colored -Color "Red" -ColoredText "Unavailable path : $Path" ; return }

 $StartDate=$(get-date -uformat "%Y-%m-%d %T")

 get-aduser -filter * -properties * | Select-Object @{name="SamAccountName";expression={Progress "Checking User: " "$($_.SamAccountName)";$_.SamAccountName}},
  DisplayName,UserPrincipalName,EmailAddress,Description,
  @{name="OU";expression={$_.CanonicalName -replace '/[^/]+$'}},
  @{name="Enabled";expression={ if ($_.Enabled) {"TRUE"} else {"FALSE"} }},
  @{name="LockedOut";expression={ if ($_.LockedOut) {"TRUE"} else {"FALSE"} }},
  logonCount,
  @{name="Created";expression={Format-Date $_.Created}},
  @{name="PasswordLastSet";expression={Format-Date $_.PasswordLastSet}},
  @{name="AccountExpirationDate";expression={Format-Date $_.AccountExpirationDate}},
  @{name="LastLogonDate";expression={Format-Date $_.LastLogonDate}},
  @{name="whenChanged";expression={Format-Date $_.whenChanged}} `
  | Export-Csv "$Path\UserList-$(get-date -uformat '%Y-%m-%d').csv"  -encoding "unicode" -notypeinformation -Delimiter ";"
 ProgressClear
 write-host
 $EndDate=$(get-date -uformat "%Y-%m-%d %T")
 $Duration=(New-TimeSpan -Start $StartDate -End $EndDate)
 write-colored -Color "Green" -ColoredText "$($MyInvocation.MyCommand) Finished in $Duration"
}
# KPI WSUS
Function Get-KPIWsus {
 Param (
  [Parameter(Mandatory=$true)]$WsusServersADGroup,
  $Path="$iClic_TempPath\KPI"
 )

 $OutputFileWSUS="$Path\WSUS-$(get-date -uformat '%Y-%m-%d').csv"

 $StartDate=$(get-date -uformat "%Y-%m-%d %T")

 $ServerList=(Get-ADGroupMember $WsusServersADGroup).Name

 $ServerList | ForEach-Object {

  $WsusServer=$_

  #BEGIN REMOTE BLOC
  Write-Host -ForegroundColor Magenta "Remotely Checking WSUS Server $WsusServer"
  $ExtractTMP=Invoke-Command -ComputerName $WsusServer -ScriptBlock {
   #Load Assembly
   [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
   #Create Objects
   $computerscope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
   $updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
   try {
    #Create WSUS connection Object
    $AdminProxyObj = New-Object Microsoft.UpdateServices.Administration.AdminProxy
    $wsus = $AdminProxyObj.GetUpdateServerInstance()
    #Getting Computer Summary
    $wsus.GetSummariesPerComputerTarget($updatescope,$computerscope) | Select-Object *,
     @{Label='ComputerTarget';Expression={($wsus.GetComputerTarget([guid]$_.ComputerTargetId))}},
     @{Label='NeededCount';Expression={($_.DownloadedCount + $_.NotInstalledCount)}}
   } catch {
    write-host -foregroundcolor "red" "$WsusServer : $($error[0])" ; return
   }
  }
  #END REMOTE BLOC

  $Extract=$ExtractTMP | Select-Object @{Label='Server';Expression={$WsusServer}},
   @{Label='ComputerName';Expression={Progress "KPIWsus - $WsusServer - Checking Computer: " "$($_.ComputerTarget.fulldomainname)";$_.ComputerTarget.fulldomainname.split(".")[0].toupper()}},
   UnknownCount,NotApplicableCount,NotInstalledCount,DownloadedCount,InstalledCount,InstalledPendingRebootCount,FailedCount,NeededCount,
   @{Label='LastUpdated';Expression={Format-Date $_.LastUpdated}},
   @{Label='IPAddress';Expression={$_.ComputerTarget.IPAddress}},
   @{Label='Make';Expression={$_.ComputerTarget.Make}},
   @{Label='Model';Expression={$_.ComputerTarget.Model}},
   @{Label='OSArchitecture';Expression={$_.ComputerTarget.OSArchitecture}},
   @{Label='ClientVersion';Expression={$_.ComputerTarget.ClientVersion}},
   @{Label='OSFamily';Expression={$_.ComputerTarget.OSFamily}},
   @{Label='OSDescription';Expression={$_.ComputerTarget.OSDescription}},
   @{Label='ComputerRole';Expression={$_.ComputerTarget.ComputerRole}},
   @{Label='LastSyncTime';Expression={Format-Date $_.ComputerTarget.LastSyncTime}},
   @{Label='LastSyncResult';Expression={Format-Date $_.ComputerTarget.LastSyncResult}},
   @{Label='LastReportedStatusTime';Expression={Format-Date $_.ComputerTarget.LastReportedStatusTime}},
   @{Label='RequestedTargetGroupName';Expression={$_.ComputerTarget.RequestedTargetGroupName}}

  $result=$result+$Extract
  ProgressClear
  write-host
 }

 #Get Status per group:
 # $wsus.GetUpdateApprovals($updatescope) | Select-Object @{L='ComputerTargetGroup';E={$_.GetComputerTargetGroup().Name}},@{L='UpdateTitle';E={($wsus.GetUpdate([guid]$_.UpdateId.UpdateId.Guid)).Title}},GoLiveTime,AdministratorName,Deadline,Action,IsOptional,State

 # Get Group
 # $wsus.GetComputerTargetGroups()

 $result | Export-Csv $OutputFileWSUS -encoding "unicode" -notypeinformation -Delimiter ";"

 $EndDate=$(get-date -uformat "%Y-%m-%d %T")
 $Duration=(New-TimeSpan -Start $StartDate -End $EndDate)
 write-colored -Color "Green" -ColoredText "$($MyInvocation.MyCommand) Finished in $Duration"

 write-host
 return $OutputFileWSUS
}
Function Get-KPIWsusFull {
 Param (
  [Parameter(Mandatory=$true)]$WsusServersADGroup,
  $Path = "$iClic_TempPath\KPI"
 )

 $OutputFile = "$Path\WSUS-GlobalInfo-$(get-date -uformat '%Y-%m-%d').csv"

 #Get Start Time to calculate duration
 $StartDate = $(get-date -uformat "%Y-%m-%d %T")

 #Get computers from AD Group
 $ServerList = (Get-ADGroupMember $WsusServersADGroup).Name

 $ServerList | ForEach-Object {

  #BEGIN REMOTE BLOC
  $Extract = Invoke-Command -ComputerName $_ -ScriptBlock {

   $WsusServer=$Env:COMPUTERNAME

   #Load WSUS Module
   [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

   #Create Scope Objects
   $computerscope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
   $updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope

   #Exclude values for much faster search
   $updatescope.ExcludedInstallationStates = 'NotApplicable','Installed','Unknown'

   #WSUS Connection
   $AdminProxyObj = New-Object Microsoft.UpdateServices.Administration.AdminProxy
   try {
    $wsus = $AdminProxyObj.GetUpdateServerInstance()
   } catch {
    write-host -foregroundcolor "red" "$WsusServer : $($error[0])"
    return
   }

   #Initialize counters
   $global:ServerCount=0

   #Get ComputerList
   $ServerList = $wsus.GetComputerTargets($computerscope) | Sort-Object LastReportedStatusTime

   #Get Total Computers Count
   $ServerListCount = $ServerList.Count

   $ServerList | ForEach-Object {
    #Put computer info in variable for later use
    $ComputerInfo = $_

    #Counter management (Increment Server Number & Reset Update Number)
    $global:ServerCount++
    $global:UpdateCount=1

    #Get UpdateList
    $UpdateList = $ComputerInfo.GetUpdateInstallationInfoPerUpdate($updatescope)

    #If computer has not reported skip
    if ($ComputerInfo.LastReportedStatusTime -eq [DateTime]0) {
     Write-Host -ForegroundColor Cyan -NoNewline "`rWSUS | $WsusServer | Computer: $global:ServerCount`/$ServerListCount`: $($ComputerInfo.FullDomainName) | Never reported status$(" "*15)"
     return
    }

    #Get Total Updates Count
    $UpdateListCount = $UpdateList.Count

    #Return Info :
    $UpdateList | Select-Object UpdateInstallationState,UpdateApprovalAction,
     @{Label='Progress';Expression={Write-Host -ForegroundColor Cyan -NoNewline "`rWSUS | $WsusServer | Computer: $global:ServerCount`/$ServerListCount`: $($ComputerInfo.FullDomainName) | Update: $global:UpdateCount`/$UpdateListCount$(" "*15)"}},
     @{Label='WSUS';Expression={$WsusServer}},
     @{Label='ComputerInfo';Expression={$ComputerInfo}},
     @{Label='BiosInfo';Expression={$ComputerInfo.BiosInfo}},
     @{Label='OsInfo';Expression={$ComputerInfo.OsInfo}},
     @{Label='UpdateInfo';Expression={$global:UpdateCount++;$wsus.GetUpdate([guid]$_.UpdateId)}} | Select-Object * -ExcludeProperty Progress
   }
  }
  #END REMOTE BLOC
  $result = $result + $Extract
 }

 #Clear Progress
 Write-Host -NoNewline "`r$(" "*100)"
 write-host

 write-host -ForegroundColor Magenta "Finished getting remote information - Please Wait"

 $result | Select-Object UpdateInstallationState,UpdateApprovalAction,WSUS,
 @{Label='C_FullDomainName';Expression={$_.ComputerInfo.FullDomainName}},
 @{Label='C_GroupInfo';Expression={$_.ComputerInfo.RequestedTargetGroupName}},
 @{Label='C_IPAddress';Expression={$_.ComputerInfo.IPAddress}},
 @{Label='C_Make';Expression={$_.ComputerInfo.Make}},
 @{Label='C_Model';Expression={$_.ComputerInfo.Model}},
 @{Label='C_ClientVersion';Expression={$_.ComputerInfo.ClientVersion}},
 @{Label='C_DefaultUILanguage';Expression={$_.osinfo.DefaultUILanguage}},
 @{Label='C_BiosName';Expression={$_.BiosInfo.Name}},
 @{Label='C_BiosVersion';Expression={$_.BiosInfo.Version}},
 @{Label='C_OSDescription';Expression={$_.ComputerInfo.OSDescription}},
 @{Label='C_OSArchitecture';Expression={$_.ComputerInfo.OSArchitecture}},
 @{Label='C_ComputerRole';Expression={$_.ComputerInfo.ComputerRole}},
 @{Label='C_LastSyncTime';Expression={Format-Date  $_.ComputerInfo.LastSyncTime}},
 @{Label='C_LastSyncResult';Expression={$_.ComputerInfo.LastSyncResult}},
 @{Label='C_LastReportedStatusTime';Expression={Format-Date $_.ComputerInfo.LastReportedStatusTime}},
 @{Label='U_KnowledgebaseArticles';Expression={$_.UpdateInfo.KnowledgebaseArticles -join ","}},
 @{Label='U_UpdateClassificationTitle';Expression={$_.UpdateInfo.UpdateClassificationTitle}},
 @{Label='U_UpdateType';Expression={$_.UpdateInfo.UpdateType}},
 @{Label='U_LegacyName';Expression={$_.UpdateInfo.LegacyName}},
 @{Label='U_Title';Expression={$_.UpdateInfo.Title}},
 @{Label='U_Description';Expression={$_.UpdateInfo.Description}},
 @{Label='U_IsApproved';Expression={ if ($_.UpdateInfo.IsApproved) {"TRUE"} else {"FALSE"} }} | Export-Csv $OutputFile -encoding "UTF8" -notypeinformation -Delimiter ";"

 #Get end Time and calculate duration
 $EndDate=$(get-date -uformat "%Y-%m-%d %T")
 $Duration=(New-TimeSpan -Start $StartDate -End $EndDate)
 write-colored -Color "Green" -ColoredText "$($MyInvocation.MyCommand) Finished in $Duration"

 #Clear Progress
 Write-Host -NoNewline "`r$(" "*100)"
 write-host

 return $OutputFile
}
# KPI VMWare
Function Get-KPIVMwarePerHost {
Param (
 $ESX,
 $ClusterList,
 $Path="$iClic_TempPath\KPI",
 $OutputFile="$Path\KPI-VMware-PerHost-$(get-date -uformat '%Y-%m-%d').csv"
)
Connect-vCenter
#Note : Cannot add as default param as it will fail if vCenter connection is not up
If (! $ClusterList) {
 $ClusterList=$(VMware.VimAutomation.Core\get-cluster)
}

if ($ESX) {
 $ESXList=VMware.VimAutomation.Core\Get-VMHost $ESX
} else {
 $ESXList=VMware.VimAutomation.Core\Get-VMHost | Sort-Object Name
}

$SumValues=$ESXList | Measure-Object NumCpu,CpuUsageMhz,CpuTotalMhz,MemoryUsageGB,MemoryTotalGB -Sum

$ESXListResult=$ESXList | Select-Object Name,NumCpu,
@{Label='CPUCurrent'; Expression={$_.CpuUsageMhz}},
@{Label='VMCluster'; Expression={VMware.VimAutomation.Core\get-cluster -VMHost $_.Name}},
@{Label='CPUTotal'; Expression={$_.CpuTotalMhz}},
@{Label='CPU%'; Expression={[math]::round((($_.CpuUsageMhz/$_.CpuTotalMhz)*100),2)}},
@{Label='MemoryCurrent'; Expression={[math]::round($_.MemoryUsageGB,2)}},
@{Label='MemoryTotal'; Expression={[math]::round($_.MemoryTotalGB,2)}},
@{Label='Memory%'; Expression={[math]::round((($_.MemoryUsageGB/$_.MemoryTotalGB)*100),2)}},
@{Label='VMCount'; Expression={(VMware.VimAutomation.Core\Get-VMHost $_.Name | Get-VM).Count}},
Version,MaxEVCMode

$TotalResult=$ESXListResult | Measure-Object 'CPU%','Memory%',VMCount -Sum

$ESXListResultTotal=New-Object PSObject -Property @{
 Name="TOTAL";
 VMCluster="N/A";
 NumCpu=($SumValues | Where-Object Property -eq NumCpu).Sum;
 CPUCurrent=($SumValues | Where-Object Property -eq CpuUsageMhz).Sum;
 CPUTotal=($SumValues | Where-Object Property -eq CpuTotalMhz).Sum;
 'CPU%'=[math]::round(($TotalResult | Where-Object Property -eq 'CPU%').Sum/$ESXListResult.count,2);
 MemoryCurrent=[math]::round(($SumValues | Where-Object Property -eq MemoryUsageGB).Sum,2);
 MemoryTotal=[math]::round(($SumValues | Where-Object Property -eq MemoryTotalGB).Sum,2);
 'Memory%'=[math]::round(($TotalResult | Where-Object Property -eq 'Memory%').Sum/$ESXListResult.count,2);
 Version='N/A';
 MaxEVCMode='N/A';
 VMCount=[math]::round(($TotalResult | Where-Object Property -eq VMCount).Sum)
}

$ESXListResult+=$ESXListResultTotal

$ESXListResult | Select-Object Name,VMCluster,NumCpu,CPUCurrent,CPUTotal,'CPU%',MemoryCurrent,MemoryTotal,'Memory%',VMCount,Version,MaxEVCMode | Export-Csv -Path $OutputFile -Delimiter ";"
}
Function Get-KPIVMwarePerCluster {
Param (
 $ClusterList,
 $Path="$iClic_TempPath\KPI",
 $OutputFile="$Path\KPI-VMware-PerCluster-$(get-date -uformat '%Y-%m-%d').csv"
)
Connect-vCenter

#Note : Cannot add as default param as it will fail if vCenter connection is not up
If (! $ClusterList) {
 $ClusterList=$(VMware.VimAutomation.Core\get-cluster)
}

$ClusterList | ForEach-Object {
 $CurrentCluster=$_.Name
 $ClusterInfo=VMware.VimAutomation.Core\Get-VMHost -Location $CurrentCluster
 $ClusterSumValues=$clusterinfo | Measure-Object CpuUsageMhz,CpuTotalMhz,MemoryUsageGB,MemoryTotalGB -Sum
 $CPUCurrent=($ClusterSumValues | Where-Object Property -eq CpuUsageMhz).Sum
 $CPUTotal=($ClusterSumValues | Where-Object Property -eq CpuTotalMhz).Sum
 $CPUUsage=[math]::round((($CPUCurrent/$CPUTotal)*100),2)
 $MemoryCurrent=($ClusterSumValues | Where-Object Property -eq MemoryUsageGB).Sum
 $MemoryTotal=($ClusterSumValues | Where-Object Property -eq MemoryTotalGB).Sum
 $MemoryUsage=[math]::round((($MemoryCurrent/$MemoryTotal)*100),2)
 $VMCount=(VMware.VimAutomation.Core\Get-Cluster $CurrentCluster | VMware.VimAutomation.Core\Get-VM).Count
 New-Object PSObject -Property @{
  Name=$CurrentCluster;
  CPUCurrent=$CPUCurrent;
  CPUTotal=$CPUTotal;
  'CPU%'=$CPUUsage;
  MemoryCurrent=[math]::round($MemoryCurrent,2);
  MemoryTotal=[math]::round($MemoryTotal,2);
  'Memory%'=$MemoryUsage;
  VMCount=$VMCount
 } | Select-Object Name,CPUCurrent,CPUTotal,'CPU%',MemoryCurrent,MemoryTotal,'Memory%',VMCount
} | Export-Csv -Path $OutputFile -Delimiter ";"
}
Function Get-KPIVMWareDiskSpaceDataStore {
 Param (
  $Path="$iClic_TempPath\KPI",
  $OutputFile="$Path\KPI-VMware-DiskSpaceDataStore-$(get-date -uformat '%Y-%m-%d').csv"
 )
 Connect-vCenter
 VMware.VimAutomation.Core\Get-Cluster | Sort-Object Name | ForEach-Object {
  $ClusterName=$_.Name
  $_ | VMware.VimAutomation.Core\Get-Datastore | Sort-Object Name | Select-Object `
   @{Label='Cluster'; Expression={$ClusterName}},Name,CapacityGB,FreeSpaceGB,
   @{Label='UsedSpaceGB'; Expression={$($_.CapacityGB-$_.FreeSpaceGB)}},
   @{Label='FreePercent'; Expression={[math]::round((($_.FreeSpaceMB/$_.CapacityMB)*100),2)}}
 } | Export-Csv -Path $OutputFile -Delimiter ";"
}
Function Get-KPIVMWareDiskSpaceReal {
Param (
 $Path="$iClic_TempPath\KPI",
 $OutputFile="$Path\KPI-VMware-DiskSpaceReal-$(get-date -uformat '%Y-%m-%d').csv"
)
Connect-vCenter
VMware.VimAutomation.Core\Get-Cluster | Sort-Object Name | ForEach-Object {
 $ClusterName=$_.Name
 $_ | VMware.VimAutomation.Core\Get-VM | Sort-Object Name | ForEach-Object {
  #Init Variable
  $DiskSizeResult=""
  #If server is available check disk space locally
  if ($_.PowerState) {
   $DiskSizeResult=df -Object $_.Name | Select-Object *,
   @{Label='PowerState'; Expression={"PoweredOn"}},
   @{Label='Cluster'; Expression={$ClusterName}},
   @{Label='Progress'; Expression={Progress -Message "Current check : " -Value "$ClusterName\$($_.ServerName)\$($_.Name)"}}
  }
  #If nothing was found (computer OFF or inaccessible (Linux etc.)) get full VM used size
  if (!$DiskSizeResult) {
   New-Object PSObject -Property @{
    Type="DataStore";
    PowerState=$_.PowerState;
    ServerName=$_.Name;
    Cluster=$ClusterName;
    TotalSize=[Math]::Round($_.UsedSpaceGB*1Gb);TotalSizeH="";
    UsedSpace=[Math]::Round($_.UsedSpaceGB*1Gb);UsedSpaceH="";
    FreeSpace=0;FreeSpaceH="";
    Name="";Letter="";Label="";FileSystem="";ClusterSize="";Indexing="";BootVolume="";Swap="";FreePercent="";Progress="";
   }
  } else {
   $DiskSizeResult
  }
 }
} | Select-Object ServerName,PowerState,Letter,Label,Type,FileSystem,ClusterSize,Indexing,BootVolume,Swap,FreePercent,
TotalSize,TotalSizeH,UsedSpace,UsedSpaceH,FreeSpace,FreeSpaceH,
Name,Cluster | Export-Csv -Path $OutputFile -Delimiter ";"
}
# Linux
Function Get-KPILinux {
Param (
 [Parameter(Mandatory=$true)]$MachineGroup,
 [Parameter(Mandatory=$true)]$ScriptLocation,
 $ResultFile = "$iClic_TempPath\LinuxStatus.csv",
 [Parameter(Mandatory=$true)]$User
)

$FirstRun=$True
Get-ADGroupMember $MachineGroup | Sort-Object Name | ForEach-Object {
 $CurrentServer = $_.Name
 Progress  -Message "Checking : " -Value  $CurrentServer
 $RemoteResult = plink -l $User -no-antispoof -ssh -batch -m $ScriptLocation $CurrentServer
 $Header="" ; $Content=""
 $RemoteResult  -split ";" -replace "^ ","" | ForEach-Object { $Header+="$(($_ -split ":")[0]);" ; $Content+="$(($_ -split ":")[1].trim());" }
 if ($FirstRun) { $Header > $ResultFile ;  $FirstRun=$False }
 $Content >> $ResultFile
}
}
