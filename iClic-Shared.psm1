# Notes
#   Type of indentation : K&R 1TBS
# Add de Beep to functions / commands
#   [console]::Beep()
# Mod default error output :
#   $ErrorView="CategoryView"
#   $ErrorView="Normal"
# List all Profiles
#   $PROFILE | Format-List * -Force
# To log all commands
#   $outputfile="d:\iClicLog_"+(get-date -uformat "%Y%m%d")+".log"
#   Start-Transcript -path $outputfile -append
# Change Security Protocol of NetFramework
#   [System.Net.ServicePointManager]::SecurityProtocol
#   [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'
# Remote Launch Function
#   Invoke-Command -ScriptBlock ${function:FUNCTIONNAME} -ComputerName LCBVMP13
# Add NuGet as package source
#   Register-PackageSource -Name NuGet.Org -Location https://www.nuget.org/api/v2 -ProviderName NuGet
# See security applied to PsSession and update them if needed
#   List : Get-PSSessionConfiguration
#   Modify : Set-PSSessionConfiguration -showSecurityDescriptorUI
# To pass variable from a function to the inside of a function use Splatting:
#   https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_splatting
#   Example with AZ Cli : Get-AzureServicePrincipal
# Create Objects
#   $Lic_List=@()
#   $Lic_List+=[pscustomobject]@{Name="Windows Server 2016 Datacenter";Key="1"}
#   $Lic_List+=[pscustomobject]@{Name="Windows Server 2016 Standard (MSDN)";Key="2"}
# Add comment only if verbose is set
#  $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

# Required Modules
# ActiveDirectory for : Set-AdUser, Get-AdUser etc.
# AzureAD for : Set-AzureADUser, Get-AzureADUser etc.

# ToDo : add measure-command function to time functions whenever possible

# Version of Script
$iClicVersion="50.0"
# Set future console in QuickEdit mode
set-itemproperty -path "HKCU:\Console" -name QuickEdit -Value 1
# Set Path to C:\

if (Test-Path "C:\Temp\") {
 Set-Location -Path "C:\Temp\"
}

# Set default colors used in functions
$defaultblue="Cyan"
# Set Azure Prompt as False by default as this slows down display
[Switch]$global:AzurePrompt=$False

if ($IsLinux) {
 $username=users
} else {
 $username=([System.Security.Principal.WindowsIdentity]::GetCurrent().name).ToUpper()
}

# TO CLEAN
Function PSElevate {
 Param (
  $User
 )
 $NewVer = $(Assert-MinPSVersion 6 -Silent)

 if ($NewVer) {
  $ShellName='pwsh.exe'
 } else {
  $ShellName='powershell.exe'
 }

 $ErrorActionPreference='Stop'

 try {

 if ($user) {
  while (! $Password) {$Password=read-host -AsSecureString "Enter Password of account `"$User`" "}
  $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User,$Password
  Start-Process $ShellName -Credential $Credential -UseNewEnvironment -WindowStyle Hidden -ArgumentList "-NoProfile -Command Start-Process $ShellName -Verb runAs"
 } else {
  Start-Process $ShellName -Verb runAs
 }

 } catch {
  write-colored "Red" "Error while Elevate : " $error[0]
 }
}
Function Get-UptimePerso {
 Param (
  $ServerName=$env:ComputerName,
  [switch]$Obj
 )
 try {
  if ($ServerName -ne $env:ComputerName) {

   $WSmanTest=Test-Wsman $ServerName -ErrorAction Stop
   $WSmanTest=[Int]($WSmanTest.ProductVersion -split "Stack: ")[-1]

   if ($WSmanTest -gt 2) {
    # Win 2008 R2+
    $os = Get-CimInstance win32_operatingsystem -computername $ServerName -ErrorAction Stop -OperationTimeoutSec 1
    $UnformatedDate=($os.lastbootuptime)
   } else {
     # Win 2003+
    $os = Get-WmiObject  win32_operatingsystem -ComputerName $ServerName -ErrorAction Stop
    $UnformatedDate=($os.ConvertToDateTime($os.lastbootuptime))
   }
  } else {
    $os = Get-CimInstance win32_operatingsystem -ErrorAction Stop -OperationTimeoutSec 1
    $UnformatedDate=($os.lastbootuptime)
  }

  $uptime = (Get-Date) - $UnformatedDate
  $LastRebootDate=get-date $UnformatedDate -uformat '%Y-%m-%d %T'
  if ($Obj) {
   $returnmessage=$($LastRebootDate;"$($Uptime.Days) days $($Uptime.Hours) hours $($Uptime.Minutes) minutes $($Uptime.Seconds) seconds")
  } else {
   $returnmessage="$LastRebootDate - $($Uptime.Days) days $($Uptime.Hours) hours $($Uptime.Minutes) minutes $($Uptime.Seconds) seconds"
  }
 } catch {
  if ($Obj) {
   $returnmessage=$($($Error[0].Exception.Message.Trim());"N/A")
  } else {
   $returnmessage=$Error[0].Exception.Message.Trim()
  }
 }
 return $returnmessage
}
Function KillAllPsSessions {
 $Sessions=get-pssession
 try {
  $Sessions | Remove-PSSession -ErrorAction Stop
 } catch {
  write-colored "Red" -ColoredText $Error[0]
 }
 write-colored "Magenta" -ColoredText "$($Sessions.Count) session(s) deleted"
 #Remove Temporary Modules
 Title
 Remove-Module -Name "tmp_*"
}
Function Get-LastStart {
 Param (
  [switch]$ShowAll
 )
 if ($ShowAll) {
  Get-WinEvent -FilterHashtable @{LogName='System';ID='6009'} | Select-Object RecordID,@{name="Date";expression={$(get-date -Date $_.TimeCreated -UFormat "%Y-%m-%d %T")}}
 } else {
  (Get-WinEvent -FilterHashtable @{LogName='System';ID='6009'} -MaxEvents 1 | Select-Object RecordID,@{name="Date";expression={$(get-date -Date $_.TimeCreated -UFormat "%Y-%m-%d %T")}}).Date
 }
}

# Display Functions
Function Title {
 Param (
  $PostMsg
 )
 # $Host.UI.RawUI.WindowTitle = "PowerShell " + (get-host).Version.Major + "." + (get-host).Version.Minor + " $username`@$($env:computername)" + " (" + $pwd.Provider.Name + ") " + $pwd.Path
 if (Assert-IsAdmin) {$TitleAdmin="[*]"} else {$TitleAdmin=""}
 if (! $([Environment]::Is64BitProcess)) {$TitleArchitecture="<32>"} else {$TitleArchitecture=""}
 $TitleUsername=$env:USERNAME
 $TitleHostname=$env:COMPUTERNAME
 $TitleUserInfo="[$TitleUsername`@$TitleHostname]"
 #Check if in RemoteSession
 if (! $PSSenderInfo) {
  # $HostInfo=get-host
  # $TitlePsVersion="PS$($psversiontable.PSVersion)"
 }
 #Add this to be able to import profile in parallele PS commands (Noninteractive check do not work)
 try {
  $Host.UI.RawUI.WindowTitle = "$TitleUserInfo$TitleAdmin$TitlePsVersion$PostMsg$TitleArchitecture"
 } catch {}
}
Function prompt {

 # $backcolor=[console]::backgroundcolor
 # $frontcolor=[console]::foregroundcolor

 #When using admin session :
 if ($IsLinux) {
  $promptcolor="green"
  $ColorGray="Gray"
  $P_UserName=$username
  $P_ComputerName=hostname
 } else {
   if( Assert-IsAdmin ) { $promptcolor = "red" } else {$promptcolor = "green"}
   if ($PSSenderInfo) {$promptcolor = "Magenta"}
   $ColorGray = "DarkGray"
   $P_UserName = $env:USERNAME
   $P_ComputerName = $($env:COMPUTERNAME).tolower()
 }

 # Show providername if you are outside FileSystem
 if ($($pwd.Provider.Name) -ne "FileSystem") {
  Write-Colored $ColorGray -ColoredText "[" -nonewline
  Write-Colored "Gray" -ColoredText $($pwd.Provider.Name) -nonewline
  Write-Colored $ColorGray -ColoredText "]"
 }

 # $userathostname="$P_UserName@$P_ComputerName"
 write-colored $ColorGray -ColoredText "[$(get-date -uformat '%Y-%m-%d %T')] [" -nonewline
 write-colored $promptcolor -ColoredText $P_UserName -nonewline
 write-colored $ColorGray -ColoredText "@" -nonewline
 write-colored $promptcolor -ColoredText $P_ComputerName -nonewline
 write-colored $ColorGray -ColoredText "] " -nonewline

 if ($Global:AzurePrompt) {
  if (get-command kubectl -CommandType Application -ErrorAction SilentlyContinue){
   $PromptAzure = Set-PromptAzure $(kubectl config current-context)
   write-colored -Color $PromptAzure[0] -ColoredText "$([char]16)$($PromptAzure[1])$([char]17) " -nonewline
  }
 }

 $CurrentPath = "$($executionContext.SessionState.Path.CurrentLocation)" -replace "Microsoft.PowerShell.Core\\FileSystem::",""

 #If Remote Session
 if ($PSSenderInfo) {
  # $cn = $env:computername
  $cn = $PSSenderInfo.ConnectionString -replace ".*://","" -replace ":.*",""

  # generate backspaces to cover [computername]: pre-prompt printed by powershell
  $backspaces = "`b" * ($cn.Length + 4)

  # compute how much extra, if any, needs to be cleaned up at the end
  $remainingChars = [Math]::Max(($cn.Length + 4) - $CurrentPath.Length, 0)
  $tail = (" " * $remainingChars) + ("`b" * $remainingChars)
  # Check Ascii table for consolas font : https://www.fileformat.info/info/unicode/font/consolas/list.htm
  $EndChar=[char]0x25BA

  "${backspaces}${CurrentPath}${tail} $EndChar "
 } else {
  # Backspace last \ and write >
  write-colored $promptcolor -NonColoredText ${CurrentPath} -ColoredText " >" -nonewline
  return " "
 }

 # Title $($myinvocation.Line)
}
Function Question {
 Param (
  $message,
  [int]$defaultChoice=0,
  $helpforYes="No Information",
  $helpforNo="No Information",
  $title=""
 )
 # For default choice : -1 for none, 0 for yes, 1 for N
 $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", $helpforYes
 $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", $helpforNo
 $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
 $result = $host.ui.PromptForChoice($title, $message, $options, $defaultChoice)
 if ($result -eq 0) {
  return $true
 } else {
  return $false
 }
}
Function Banner {
 Param (
  [string]$title
 )
 $date=get-date -uformat "%Y-%m-%d"
 Write-Blank
 Write-StarLine
 if ( $title ) { Write-Centered $title }
 Write-Centered "User $username"
 Write-Centered "Server $($env:COMPUTERNAME)"
 Write-Centered "$date"
 Write-StarLine
 Write-Blank
}
Function ClearProgressBar {
 for ($i = 1; $i -le 100; $i++ ) {write-progress -activity "Finishing" -status "$i% Complete:" -percentcomplete $i -Completed}
}
Function PSWindowResize {
 Param (
  $windowsize="100"
 )
 #Console Size
 try {
  [console]::windowwidth=$windowsize
  [console]::SetBufferSize($windowsize,"999")
 # [console]::windowheight=(get-host).UI.RawUI.MaxPhysicalWindowSize.Height
 } catch {}
}
Function PSWindowsColors {
 Param (
  [switch]$Dark=$false
 )
 #Console Colors
 if ($Dark) { $BG_Color="Black" ; $FG_Color="white" } else { $BG_Color="white" ; $FG_Color="Black" }
 # if (! (Assert-MinPSVersion 7 -Silent)) {$BG_Color = "White" ; $FG_Color = "Black"}
 [console]::backgroundcolor=$BG_Color
 [console]::foregroundcolor=$FG_Color
 if ( ! (Assert-MinPSVersion 5 -CurrentFunction $($MyInvocation.MyCommand)) ) {return}
 try {
  $host.PrivateData.ErrorBackgroundColor = $BG_Color
 } catch {}
}
Function Progress {
 Param (
  $Message,
  $Value,
  [Switch]$PrintTime
 )
 try {
  $blanklinesize=" "*([console]::windowwidth -2)
 } catch {$blanklinesize=" "*100}
 if ($PrintTime) {
  $Time="$(Get-Date -uformat '%Y-%m-%d %T') | "
 } else {
  $Time=""
 }
 Write-Colored $defaultblue "`r$blanklinesize" -nonewline
 Write-Colored $defaultblue "`r$Time$Message" $Value -nonewline
}
Function ProgressClear {
 try {
  $blanklinesize=" "*([console]::windowwidth -2)
 } catch {$blanklinesize=" "*100}
 Write-Colored $defaultblue "`r$blanklinesize" -nonewline
}
Function Align {
 Param (
  $variable,
  $size,
  $ending=""
 )
 if ($variable.length -lt $size) {$variable=$variable+(" "*($size-$variable.length))+$ending}
 return $variable
}
# Write functions
Function Write-Centered {
 Param (
  [string]$message,
  [string]$Color = $defaultblue,
  [switch]$NoNewLine=$false
 )
 try {
  $offsetvalue = [Math]::Round(([Console]::WindowWidth / 2) + ($message.Length / 2))
 } catch {
  $offsetvalue=50
 }
 if ($NoNewLine) {$NoNewLineValue="-nonewline"} else {$NoNewLineValue=""}
 Write-Colored $Color "" ("{0,$offsetvalue}" -f $message) $NoNewLineValue
}
Function Write-StarLine {
 Param (
  $character,
  $color="Blue"
 )
 if (!$character){$character="*"}
 try {
  $starsize=$character * ([console]::windowwidth - 2)
 } catch {
  $starsize=$character * 100
 }
 Write-Centered $starsize $color
}
Function Write-Blank {
 Write-Host
}
Function Write-Colored {
 Param (
  $Color=$defaultblue,
  $NonColoredText,
  $ColoredText,
  [switch]$NoNewLine=$false,
  [Switch]$PrintDate,
  $filepath
 )
 If (! $Color) { $Color = "Cyan" }
 if ($PrintDate) {
  $Date="$(get-date -uformat '%Y-%m-%d %T') " } else { $Date= ""
 }
 write-host -nonewline "$Date$NonColoredText"
 if ($NoNewLine) {
  write-host -nonewline -foregroundcolor $Color $ColoredText
 } else {
  write-host -foregroundcolor $Color $ColoredText
 }
 if ($filepath) {
  write-output "$Date$NonColoredText $ColoredText" | out-file -append $filepath
 }
}

# Format conversion Function
Function Format-FileSize {
 Param (
  $size
 )
 If ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
 ElseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
 ElseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
 ElseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
 ElseIf ($size -gt 0) {[string]::Format("{0:0.00} B", $size)}
 Else {""}
}
Function Format-Color {
 Param (
  [hashtable] $Colors = @{}
 )
 #To add color to a table depending on a patern
 $lines = ($input | Out-String) -replace "`r", "" -split "`n"
 foreach($line in $lines) {
  $color = ''
  foreach($pattern in $Colors.Keys){ if ($line -match $pattern) { $color = $Colors[$pattern] }}
  write-Colored $color "" $line
 }
}
Function Format-TypeServices {
 Param (
  $Service,
  [switch]$formattable=$false
 )
 # if ($_.displayname -eq $_.name) { $RealName=(get-service -ComputerName $servername -name $_.name).DisplayName } else {$RealName=$_.displayname}
 if ( ! $_.startname) { $LoginName="Unknown"} else {$LoginName=$_.startname}
 if ( ! $_.CommandLine) { if ( ! $_.PathName) { $CommandLine="Unknown" } else {$CommandLine=$_.PathName} } else {$CommandLine=$_.CommandLine}

 # write-colored "Magenta" "" ($RealName,"(",$_.name,")")
 if (! $formattable) {
  write-colored "Magenta" "" ($_.displayname,"(",$_.name,")")
  Write-Colored $defaultblue " Start Mode : " $_.startmode -nonewline
  Write-Colored $defaultblue " | Status : " $_.state -nonewline
  Write-Colored $defaultblue " | Login Name : " $LoginName
  Write-Colored $defaultblue " CommandLine : " $CommandLine
 } else {
  $obj=@()
  $obj+=[pscustomobject]@{
   DisplayName=$_.displayname
   name=$_.name
   startmode=$_.startmode
   state=$_.state
   LoginName=$LoginName
   CommandLine=$CommandLine
  }
  return $obj
 }
}
Function Format-TypeDNS {
 Param (
  $NSLOOKUP_RESULT
 )
 #Put all on one line then replace multiple spaces with one then replace tabs with ; then replace ,, with a ! then remove ending , and finally split lines containing !
 # $NSLOOKUP_RESULT=($NSLOOKUP_RESULT -join "," -replace '\s+', ' ' -replace ",\t",";" -replace ",,","!" -replace ",$","").split("!")
 # $NSLOOKUP_RESULT=($NSLOOKUP_RESULT -join "," -replace '\s+', ' ' -replace ",\t",";" -replace ",,","!" -replace ",$","").split("!")
 $NSLOOKUP_RESULT=($NSLOOKUP_RESULT -join "," -replace "\s+"," " -replace ",\t",";" -replace ",,","" -replace ",$","" -replace "Name:","SplitHereName:" -split "SplitHere")
 #Get DNS Server Info
 $DNSServerNAME=($NSLOOKUP_RESULT | Select-string -pattern "Server: ").line.split(',')[0].TrimStart("Server:").trim()
 $DNSServerIP=($NSLOOKUP_RESULT | Select-string -pattern "Server: ").line.split(',')[1].TrimStart("Address:").trim()
 #Get Server Name (with Name: (space) it does not work)
 $ServerNAME=($NSLOOKUP_RESULT | Select-string -pattern "Name: ").line.split(',')[0].TrimStart("Name:").trim()
 #Get Server IP
 $NumberOfIP=($NSLOOKUP_RESULT | Select-string -pattern "Name: ").line.split(',').Count
 $IpLOOP=1

 #Create a list
 $ServerIPv4 = New-Object System.Collections.Generic.List[System.Object]
 $ServerIPv6 = New-Object System.Collections.Generic.List[System.Object]
 while ( $IpLOOP -lt $NumberOfIP ) {
  $ServerIP=($NSLOOKUP_RESULT | Select-string -pattern "Name: ").line.split(',')["$IpLOOP"].TrimStart("Address:").trim()
  if ( ([ipaddress]$ServerIP).AddressFamily -eq "InterNetwork" ) { $ServerIPv4.add($ServerIP) } elseif ( ([ipaddress]$ServerIP).AddressFamily -eq "InterNetworkV6" ) { $ServerIPv6=$ServerIP}
  $IpLOOP++
 }

 if (! $ServerIPv6) {$ServerIPv6="N/A"}

 $returnvalue = New-Object PsObject
 Add-Member -InputObject $returnvalue -MemberType NoteProperty -Name "DNSServerNAME" -value "$DNSServerNAME"
 Add-Member -InputObject $returnvalue -MemberType NoteProperty -Name "DNSServerIP" -value "$DNSServerIP"
 Add-Member -InputObject $returnvalue -MemberType NoteProperty -Name "ServerNAME" -value "$ServerNAME"
 Add-Member -InputObject $returnvalue -MemberType NoteProperty -Name "ServerIPv4" -value "$ServerIPv4"
 Add-Member -InputObject $returnvalue -MemberType NoteProperty -Name "ServerIPv6" -value "$ServerIPv6"
 return $returnvalue
}
Function Format-TypeGPO {
 Param (
  $gpresult,
  $policy
 )
 $TabSize = 25

 $POLICYTOCHECK=$gpresult | Select-String "$policy" -context 0,1
 if ($null -eq $gpresult ) {Write-colored "red" (Align $policy $TabSize " : ") "UNABLE TO CHECK GPOs - Please run script as Admin";return}
 if ($null -eq $POLICYTOCHECK) {Write-colored "red" (Align $policy $TabSize " : ") "NOT CONFIGURED (KO)" -foregroundcolor "red";return}

 #GetPosition of ":" | Get only end of name of GPO
 #$position=$POLICYTOCHECK.Line.indexof(":")
 #$policy=( $POLICYTOCHECK.Line.substring($position+1).trim() ).split('\')[-1]

 #Get Policy Value
 $value=$POLICYTOCHECK.Context.DisplayPostContext | Out-String

 #Check Policy Value
 if ( $policy -eq "MaxCompressionLevel" -and $value.Contains("3, 0, 0, 0")) {Write-colored "darkgreen" (Align $policy $TabSize " : ") "ENABLED (OK)" ; return}

 if ($value.Contains("1, 0, 0, 0")) {Write-colored "darkgreen" (Align $policy $TabSize " : ") "ENABLED (OK)"} else {
  If ($value.Contains("0, 0, 0, 0")) {Write-colored "red" (Align $policy $TabSize " : ") "DISABLED (KO)"}
  else {Write-colored "red" (Align $policy $TabSize " : ") "ERROR DURING CHECK - PLEASE CHECK MANUALLY"}
 }
}
Function Format-TypeMSDTC {
 Param (
  $ValueToCheck,
  $ValueText
 )
 if ( $ValueToCheck ) {
  write-colored "darkgreen" "" "$ValueText : 1"
 } else {
  write-colored "red" "" "$ValueText : 0"
 }
}
Function Format-TypeLogcat {
 Process {
  if ($_) {
   $color = "black"
   if($_ -like "* V *"){ $color = "darkgray"}
   elseif($_ -like "* D *") { $color = "darkgreen"}
   elseif($_ -like "* I *") { $color = "gray" }
   elseif($_ -like "* w *") { $color = "magenta" }
   elseif($_ -like "* E *") { $color = "red" }
   elseif($_ -like "* F *") { $color = "yellow" }
   write-colored "$color" "" $_
  }
 }
}
Function Format-PrintLineByLine {
 Param (
  $variable,
  $color
 )
 $tmpcolor=[console]::foregroundcolor
 [console]::foregroundcolor=$color
 $variable
 [console]::foregroundcolor=$tmpcolor
}
Function Format-ADUserExtract {
 Param (
  $ADUserInfo
 )
 $ADUserInfo | Select-Object SamAccountName,EmployeeNumber,GivenName,Surname,DisplayName,EmailAddress,autocontactBirthdayDate,
  HomePhone,mobile,personalTitle,Department,OfficePhone,telephoneNumber,MobilePhone,Fax,
  @{name="ManagerFirstName,ManagerLastName";expression={Split-FirstAndLastName($_.Manager.split(",")[0].split("=")[1])}},
  StreetAddress,physicalDeliveryOfficeName,PostalCode,Country,autocontactMatricule,Company,targetAddress,Description,
  @{name="OU";expression={$_.CanonicalName -replace '/[^/]+$'}},proxyAddresses,info,UserPrincipalName,ServerName
}
Function Format-Date {
 Param (
  $Date,
  $DateFormat='%Y-%m-%d %T'
 )
 try {
  $ReturnValue=get-date -uformat $DateFormat $Date -ErrorAction SilentlyContinue
  if (! ($(get-date $ReturnValue) -eq 0)) { return $ReturnValue }
 } catch {
 }
}
# Convert Function
Function Convert-DateSpecific {
 Param (
  $Date,
  $EntryFormat="dd/MM/yyyy H:mm"
 )
 Format-Date $([datetime]::ParseExact($date, $EntryFormat, [cultureinfo]::InvariantCulture))
}
Function Convert-TimeZones {
 Param (
  $time,
  $fromTimeZone,
  $toTimeZone
 )
 Function ConvertTime($time, $fromTimeZone, $toTimeZone) {
   $oFromTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($fromTimeZone)
   $oToTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($toTimeZone)
   $utc = [System.TimeZoneInfo]::ConvertTimeToUtc($time, $oFromTimeZone)
   $newTime = [System.TimeZoneInfo]::ConvertTime($utc, $oToTimeZone)
   return $newTime
 }
 Function ConvertUTC ($time, $fromTimeZone){
   $oFromTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById($fromTimeZone)
   $utc = [System.TimeZoneInfo]::ConvertTimeToUtc($time, $oFromTimeZone)
   return $utc
 }
 if ($toTimeZone){
   [datetime]$time = $time
   $toUTC = ConvertUTC -time $time -fromTimeZone $fromTimeZone
   $toNewTimeZone = ConvertTime -time $time -fromTimeZone $fromTimeZone -toTimeZone $toTimeZone
   Write-Host ("Original Time ({0}): {1}" -f $fromTimeZone, $time)
   Write-Host ("UTC Time: {0}" -f $toUTC)
   Write-Host ("{0}: {1}" -f $toTimeZone, $toNewTimeZone)
 } else {
   if (!($time)) {
     $fromTimeZone = (([System.TimeZoneInfo]::Local).Id).ToString()
     $time = [DateTime]::SpecifyKind((Get-Date), [DateTimeKind]::Unspecified)
   }
   else { [datetime]$time = $time }
   Write-Host ("Original Time - {0}: {1}" -f $fromTimeZone, $time)
   $toUTC = ConvertUTC -time $time -fromTimeZone $fromTimeZone
   $times = @()
   foreach ($timeZone in ([system.timezoneinfo]::GetSystemTimeZones()))
   {
    $times += (New-Object psobject -Property @{'Name' = $timeZone.DisplayName; 'ID' = $timeZone.id; 'Time' = (ConvertTime -time $time -fromTimeZone $fromTimeZone -toTimeZone $timeZone.id); 'DST' = $timeZone.SupportsDaylightSavingTime})
   }
   $times | Sort-Object Time | Format-Table -Property * -AutoSize
 }
}
Function Convert-StringToBase64UTF8 {
 Param (
  $ValueToEncode
 )
 [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ValueToEncode))
}
Function Convert-Base64UTF8ToString {
 Param (
  $ValueToDecode
 )
 [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ValueToDecode))
}
Function Convert-BytesToHex {
 Param (
  $GUID
 )
 ($GUID -split " " | ForEach-Object {[convert]::tostring($_,16)}) -join " "
}
Function Convert-HexToBytes {
 Param (
  $HEX
 )
 ($HEX -split " " | ForEach-Object {[convert]::ToInt32($_,16)})
}
Function Convert-BytesToGUID {
 Param (
  $ByteArray
 )
 [Guid]$ByteArray
}
Function Convert-GUIDToBytes {
 Param (
  $GUID
 )
 $GUID.ToByteArray()
}
Function Convert-HexToASCII {
 Param (
  $HEX
 )
 ($HEX -split " " | ForEach-Object {[char][byte]"0x$_"}) -join ''
}

# Linux equivalent
Function Watch { # 'watch' equivalent
 Param (
  $commandline,
  $timeout="1",
  [switch]$clear,
  [switch]$NoNewLine,
  [switch]$PrintCommand,
  [switch]$HideTime
 )
 # Example : watch "test-port devgrl-01 514" 2 ; watch uptime
 while ($true) {
  if ($clear) {clear-host}
  if (! $HideTime) {Write-Colored $defaultblue "Test Date/Time : " $(get-date -uformat '%Y-%m-%d %T') -nonewline}

  if ($PrintCommand) {
   if ($NoNewLine) {Write-Colored $defaultblue " | Command : " $commandline -nonewline ; Write-Colored $defaultblue " | " -nonewline}
   else { Write-Colored $defaultblue " | Command : " $commandline}
  } else {
   if ($NoNewLine) {Write-Colored $defaultblue " | " "" -nonewline}
   else {Write-Colored $defaultblue " " ""}
  }

  Invoke-Expression $($commandline)
  Start-Sleep $timeout
 }
}
Function Fuser { # 'fuser' equivalent
 Param (
  $relativeFile
 )
 #Who uses what
 try {
 $file = Resolve-Path $relativeFile -ErrorAction Stop
  foreach ( $Process in (Get-Process -ErrorAction Stop)) {
   foreach ( $Module in $Process.Modules) {
    if ( $Module.FileName -like "$file*" ) {
     $Process | Select-Object ID, Path,@{Name="CommandLine";Expression={ (Get-CimInstance Win32_Process -Filter "ProcessId='$($_.ID)'").commandline }}
    }
   }
  }
 } catch {write-colored "red" -ColoredText $error[0]}
}
Function Tail { # 'tail' equivalent
 Param (
  $filename,
  $tailsize=10
 )
 if ( ! (test-path $filename)) { write-Colored "Red" "" "Unavailable path : $filename" ; return }
 get-content $filename -wait -tail $tailsize
}
Function Get-LastReboots {
 Param (
  $Server=$Env:COMPUTERNAME
 )
 $xml=@'
<QueryList>
<Query Id="0" Path="System">
<Select Path="System">*[System[(EventID=6005)]]</Select>
</Query>
</QueryList>
'@

 Get-WinEvent -FilterXml $xml -MaxEvents 20 -ComputerName $Server | Select-Object @{Name="Reboots";Expression={Format-Date $_.TimeCreated}}
}
Function Get-TopProcesses {
 Param (
  $NumberOfProcess = 25
 )
 $LogicalProc =  (Get-CimInstance win32_Processor).NumberOfLogicalProcessors
 Get-Process | Sort-Object -Descending cpu | Select-Object -First 15 ProcessName,ID,@{N="Memory";E={Format-Filesize $_.PrivateMemorySize}},StartTime,
 @{N="TotalProcessorTime";E={($_.TotalProcessorTime).ToString().Split(".")[0]}},Path | Sort-Object CPU -Descending | Format-Table
}
Function Top { # 'top' equivalent
 Param (
  $MaxProcess = 25
 )
 $ProcNum = $env:NUMBER_OF_PROCESSORS
 while ($true) {
   $Counter = Get-Counter '\Process(*)\% Processor Time' | `
   Select-Object -ExpandProperty countersamples | `
   Select-Object -Property instancename, cookedvalue | `
   Where-Object {$_.instanceName -notmatch "^(idle|_total|system)$"} | `
    Sort-Object -Property cookedvalue -Descending | `
    Select-Object -First $MaxProcess | Format-Table InstanceName,@{Label='CPU';Expression={($_.Cookedvalue/100/$ProcNum).toString('P')}} -AutoSize
   Clear-Host
   $Counter
 }
}
Function Get-ChildItemBen { # 'ls' equivalent
 Param (
  $Path,
  [ValidateSet("Name","Length","LastWrite","Mode")][string]$Sort,
  [switch]$NoColor
 )
 #Available only in powershell 5 or more : https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#span-idtextformattingspanspan-idtextformattingspanspan-idtextformattingspantext-formatting
 #Get Colors : https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#text-formatting

 $ErrorActionPreference='Stop'

 try {

 #Test path before anything else
 if ($path) { test-path $path | Out-Null }

 #Set Colors
 $OrigFore = [console]::foregroundcolor
 $CompressedList = @(".7z", ".gz", ".rar", ".tar",".zip",".jar")
 $TextList = @(".csv", ".log", ".markdown", ".srt",".txt",".ini",".pem",".req",".cer")
 $ExecutableList = @(".exe", ".bat", ".cmd", ".py", ".pl", ".ps1",".psm1", ".vbs", ".rb", ".reg", ".fsx", ".sh")
 # $DllPdbList = @(".dll", ".pdb")
 $ConfigsList = @(".cfg", ".conf", ".config", ".json")
 $Multimedia = @(".mp3", ".avi", ".mkv")
 $OfficeDocuments = @(".doc",".xls",".xlsx",".docx")

 #Search
 $Result = Get-ChildItem -ErrorAction Stop -force -Path $Path | Select-Object Mode,Name,Length,
  @{Label='LastWrite'; Expression={Get-Date $_.LastWriteTime -uformat '%Y-%m-%d %T'}},
  @{Label='Size'; Expression={ if ($_.Length -gt '1') {format-FileSize $_.Length }}},
  @{Label='Type'; Expression={ $Type=$($_.GetType().Name) ; if (! ($Type -like 'DirectoryInfo')) {$Type=$_.Extension.ToLower()};$Type}}

 #Sort result
 if ($sort) { $Result=$Result | Sort-Object $sort }

 #Under powershell 5 we cannot colorize Tables so we add a column with color
 if ( ! $(Assert-MinPSVersion -Silent -Version 5)) {
  $Result=$Result | Select-Object *,
   @{Label='Color'; Expression={
    if ($_.Type -eq 'DirectoryInfo') { $color = 'DarkCyan' }
    elseif ($TextList -Contains($_.Type)) {$color = 'Cyan'}
    elseif ($CompressedList -Contains($_.Type)) {$color = 'Yellow'}
    elseif ($ExecutableList -Contains($_.Type)) {$color = 'Red'}
    elseif ($ConfigsList -Contains($_.Type)) {$color = 'Cyan'}
    elseif ($Multimedia -Contains($_.Type)) {$color = 'DarkGreen'}
    elseif ($OfficeDocuments -Contains($_.Type)) {$color = 'Green'}
    else {$color = $OrigFore}
    $color
   }}

   if (! ($result.count -eq 0)) {
    #Print Header
    write-colored -Color "DarkGreen" -ColoredText "[----LastWrite----] [Mode]  $(Align '[-Size-]' 10) $(Align '[Name]')"
    $result | ForEach-Object {
     #print text in color
     write-colored -Color $_.Color -ColoredText "$(Align $($_.LastWrite) 19) $(Align $($_.Mode) 7) $(Align $($_.Size) 10) $($_.Name)"
    }
   }
   return
  }

  $EscapeChar=[char]27
  # When in remote session disable color for alignement
  if ($NoColor -or $PSSenderInfo) {
   $Result | Format-Table LastWrite,Mode,Name,Length,Size
  } else {
   $EscapeChar=[char]27
   $Result | Format-Table LastWrite,
    @{Label = "Mode" ; Expression = {
      if ($($_.Mode).Contains('s')) { $color = '91' } else {$color = '0'}
      "${EscapeChar}[${color}m$($_.Mode)${EscapeChar}[0m"
     }
     },
    @{Label = "Name" ; Expression = {
      if ($_.Type -eq 'DirectoryInfo') { $color = '95' }
      elseif ($TextList.Contains($_.Type)) {$color = '32'}
      elseif ($CompressedList.Contains($_.Type)) {$color = '93'}
      elseif ($ExecutableList.Contains($_.Type)) {$color = '91'}
      elseif ($ConfigsList.Contains($_.Type)) {$color = '94'}
      elseif ($Multimedia.Contains($_.Type)) {$color = '96'}
      elseif ($OfficeDocuments.Contains($_.Type)) {$color = '92'}
      else {$color = '0'}
      "${EscapeChar}[${color}m$($_.Name)${EscapeChar}[0m"
     }
     },Length,Size
  }

 } catch { write-host -foregroundcolor "Red" $Error[0] ; return }

}
Function Get-DiskUsage { # 'du' equivalent
 Param (
  [string]$path="."
 )

 $global:TotalSize=0
 $global:TotalCount=0

 #Added '-Attributes !ReparsePoint' to ignore Links
 Get-ChildItem $path -Attributes !ReparsePoint -Directory -force -ErrorAction SilentlyContinue | ForEach-Object {
  $CurrentFolder=$_
  try {
   # Progress "Checking Folder : " $CurrentFolder
   #Recurse Folder
   Get-ChildItem $_.FullName -Attributes !ReparsePoint -recurse -force -ErrorAction SilentlyContinue |
    measure-object -property length -sum -ErrorAction SilentlyContinue |
    Select-Object  @{Name="Name"; Expression={Progress "Checking Folder : " $_.Directory ; $CurrentFolder}},
            @{Name="Size(Auto)"; Expression={Format-FileSize $_.sum}},
            @{Name="Size"; Expression={$_.Sum ; $global:TotalSize+=$_.Sum}},
            @{Name="Count"; Expression={$_.Count; $global:TotalCount+=$_.Count}}
  } catch {
  }

  ProgressClear

 } | Sort-Object -Descending Size

 # Current Files
 Get-ChildItem $path -force -ErrorAction SilentlyContinue -Attributes !Directory |
   measure-object -property length -sum -ErrorAction SilentlyContinue |
   Select-Object  @{Name="Name"; Expression={"."}},
           @{Name="Size(Auto)"; Expression={Format-FileSize $_.sum}},
           @{Name="Size"; Expression={$_.Sum ; $global:TotalSize+=$_.Sum}},
           @{Name="Count"; Expression={$_.Count; $global:TotalCount+=$_.Count}}



 New-Object PSObject -Property @{Name="[Total]";'Size(Auto)'=$(Format-FileSize $global:TotalSize);Size=$global:TotalSize;Count=$global:TotalCount}

}

# SID Convert
Function Get-SIDFromUser {
 Param (
  [string]$user
 )
 try {
  $objUser = New-Object System.Security.Principal.NTAccount("$user")
  $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
  $strSID.Value
 } catch {
 }
}
Function Get-UserFromSID {
 Param (
  [string] $sid
 )
 # $user=[wmi]"Win32_SID.SID='$sid'"
 try {
  $user=[wmi]"Win32_SID.SID='$sid'"
  if (! $user.AccountName) {$sid} else {$user.AccountName}
 } catch {
  return $sid
 }
}
Function Get-UPNFromADUser {
 Param (
  $User=$Env:USERNAME
 )
 try {
   $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
   $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
   $objSearcher.PageSize = 1
   $objSearcher.Filter = "(&(objectCategory=User)(SAMAccountName=$User))"
   $objSearcher.SearchScope = "Subtree"
   $objSearcher.PropertiesToLoad.Add("userprincipalname") | Out-Null
   $colResults = $objSearcher.FindAll()
   $colResults[0].Properties.userprincipalname
 } catch {write-colored "red" -ColoredText $Error[0]}
}

# Wait for User Interractions
Function WaitForKeyPressAdvanced {
 Param (
  $Message = "Press any key to continue . . . "
 )
 If ($psISE) {
  # The "ReadKey" functionality is not supported in Windows PowerShell ISE.
  $Shell = New-Object -ComObject "WScript.Shell"
  $Shell.Popup("Click OK to continue.", 0, "Script Paused", 0)
  Return
 }

 write-colored -NonColoredText $Message -nonewline

 $Ignore =
  16, # Shift (left or right)
  17, # Ctrl (left or right)
  18, # Alt (left or right)
  20, # Caps lock
  91, # Windows key (left)
  92, # Windows key (right)
  93, # Menu key
  144, # Num lock
  145, # Scroll lock
  166, # Back
  167, # Forward
  168, # Refresh
  169, # Stop
  170, # Search
  171, # Favorites
  172, # Start/Home
  173, # Mute
  174, # Volume Down
  175, # Volume Up
  176, # Next Track
  177, # Previous Track
  178, # Stop Media
  179, # Play
  180, # Mail
  181, # Select Media
  182, # Application 1
  183 # Application 2

 While ((! $KeyInfo.VirtualKeyCode) -Or $Ignore -Contains $KeyInfo.VirtualKeyCode) { $KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown") }

 Write-Blank
}
Function WaitForKeyPress {
write-centered "Press a key to continue" "Red"
#Below function looses focus when pressing on ALT (ALT+TAB for example)
# $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
#Below function should work correctly
[void][System.Console]::ReadKey($FALSE)
}

# Check
Function Assert-IsNumeric {
 Param (
  $Value
 )
 #Check if passed value is numeric (for IP for example)
 return $Value -match "^[\d\.]+$"
}
Function Assert-IsAdmin {
 if( ( New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  return $true
 } else {
  return $false
 }
}
Function Assert-IsInExchange {
 Param (
  $AdUser
 )
 if ( $(get-mailbox $AdUser -ErrorAction SilentlyContinue) ) {return $true} else {return $false}
}
Function Assert-IsUserInGroup {
 Param (
  $AdUser,
  $AdGroup
 )
 if ((Get-ADUser $AdUser -Properties memberof).memberof -like "*$AdGroup*") { $true } Else { $false }
}
Function Assert-IsComputerInGroup {
 Param (
  $AdComputer,
  $AdGroup
 )
 $ErrorActionPreference='Stop'
 Try {
  if ((Get-ADComputer $AdComputer -Properties memberof).memberof -like "*$AdGroup*") { $True } Else { $False }
 } Catch {
  $False
 }
}
Function Assert-IsFileWritable {
 Param (
  $Filename
 )
 Try { [io.file]::OpenWrite($Filename).close() ; return $true } Catch { return $false }
}
Function Assert-MinPSVersion {
 Param (
  [int]$Version = 5,
  [switch]$Silent,
  $CurrentFunction
 )
 $CurrentPSVersion=$PSVERSIONTABLE.PSVersion.major
 if ($CurrentPSVersion -lt $Version ) {
  if (! $Silent) { Write-Host -ForegroundColor "red" "This function ($CurrentFunction) does not work on powershell lower than $Version" }
  return $false
 } else {
  return $true
 }
}
Function Assert-MinOSVersion {
 Param (
  [int]$OSVersion
 )
 $CurrentOSVersion=(Get-CimInstance -class Win32_OperatingSystem).BuildNumber
 if ( ! $OSVersion ) {Write-Colored $defaultblue "Current OS Version : " $CurrentOSVersion ; return $true}
 elseif ( [int]$CurrentOSVersion -lt [int]$OSVersion ) { Write-Colored "red" "" "This function does not work on older than Windows Build $OSVersion OS (Current build : $CurrentOSVersion)" ; return $false}
 else {return $true}
}
Function Assert-OSType {
 Param (
  [switch]$PrintMessage
 )
 #Currently Only Check if Workstation OS is being used
 if ( (Get-CimInstance Win32_OperatingSystem).ProductType -eq "1" ) { if ($PrintMessage) {Write-Colored "red" "" "This function does not work on workstation OS"} ; return $false} else {return $true}
}
Function Assert-IsCommandAvailable {
 Param (
  $commandname,
  [switch]$NoError
 )
 if (!$commandname) {Write-Colored "red" "" "Provide command name";return}

 if ( !(Get-Command "$commandname" -ErrorAction SilentlyContinue)) {
  if (! $NoError) {Write-Colored "red" "" "$commandname is not available (not in path or cmdlet not available)"}
  return $false
 } else { return $true }
}
Function Assert-IsDLLInRegistry {
 Param (
  $DllName,
  [Switch]$Detailed,
  $RegPath="SOFTWARE\Classes\TypeLib"
 )
 if ($Detailed) {
  $ValueFound=$False
  Get-ChildItem HKLM:\$RegPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
   $CurrentProperty=(Get-ItemProperty -Path $_.PsPath)
   if($CurrentProperty -match $DllName) {
    $TypeLibLocation=$_.PsPath.split("\").indexof("TypeLib")
    $CLSID=$_.PsPath.split("\")[$TypeLibLocation+1]
    $Value=$CurrentProperty.'(default)'
    $ValueFound=$True
   }
  }
  Return $ValueFound,$CLSID,$Value
 } else {
  $Dump=reg query HKLM\$RegPath /s /f $DllName
  $Result=$LastExitCode
  if ($Result) { return $False } else { Return $True }
 }
}
Function Assert-IsInAAD {
 Param (
  [Parameter(Mandatory=$true)]$UPNorID
 )
 $Result = az ad user show --id $UPNorID --only-show-errors 2>$ErrorMessage
 if ($Result) { return $True } else { return $False }
}

# Tests
Function Test-Port {
 Param (
  $server,
  $port,
  $timeout=1000,
  [switch]$verbose
 )
 # Code based on http://poshcode.org/85

 if ( ! (Assert-IsCommandAvailable Resolve-DNSName) ) { write-colored "red" "Resolve-DNSName if not available, please use Test-PortOld (IPv6 test will not be available)" ; return $false }
 if( ! $server -or ! $port ) { write-colored "red" "" "Please enter at least the server name (server = $server) and the port (port= $port) to test" ; return $false }

 #If it is a name that is used as argument
 try {
  $IPType=([ipaddress]$server).AddressFamily
 } catch {
  # if ($server.contains(".")) { $ServerName=$server.split(".")[0] } else {$ServerName=$server}
  try {
   $ServerIP=(Resolve-DNSName -ErrorAction Stop $server)
  } catch {
   if ($verbose) {write-colored "red" "Error during dns check : " $error[0]}
   return $false
  }
  #Check if a CNAME responds
  if ($ServerIP.Type -eq "CNAME") {
   #Added [0] when more than one IPv4 answers
   $ServerIP=($ServerIP.IP4Address)[0]
  } else {
   #Added [0] when more than one IPv4 answers
   if ($ServerIP.Count -gt 1) {$ServerIP=($ServerIP | Where-Object {$_.IP4Address})[0]}
   $ServerIP=$ServerIP.ipaddress
  }
  $IPType=([ipaddress]$ServerIP).AddressFamily
 }

 if ($IPType -eq "InterNetwork" ) {
  #OK
 } elseif ($IPType -eq "InterNetworkV6" ) {
  write-colored "red" "" "Test does not work with IPv6 - Please enter IPv4 $((Resolve-DNSName $server)[1].ipaddress)"
  return $false
 } else {
  write-colored "red" "Error while checking IP type : " $error[0]
  return $false
 }

 # Create TCP Client
 $tcpclient = new-Object system.Net.Sockets.TcpClient
 # Tell TCP Client to connect to machine on Port
 $iar = $tcpclient.BeginConnect($server,$port,$null,$null)
 # Set the wait time
 $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)

 #If connection failed return error
 $error.Clear()
 if( ! $wait ) {
  $tcpclient.Close()
  if ($verbose) {write-colored "red" "" "$server : No response from port $port"}
  return $false
 }

 # Close the connection and report the error if there is one
 $error.Clear()
 try {
  $tcpclient.EndConnect($iar) 2>&1 | out-Null
 } catch {
  write-colored "red" "" $error[0];return $false
 }
 $tcpclient.Close()

 # If no failure return $true
 return $true
}
Function Test-PortOld {
 Param (
  $server,
  $port,
  $timeout=1000,
  $verbose
 )
 #Does not require anything
 # Found part of code on http://poshcode.org/85

 if( ! $server -or ! $port ) { write-host -foregroundcolor "Red" "Please enter at least the server name (server = $server) and the port (port= $port) to test" ; return }

 # Create TCP Client
 $tcpclient = new-Object system.Net.Sockets.TcpClient

 # Tell TCP Client to connect to machine on Port
 $iar = $tcpclient.BeginConnect($server,$port,$null,$null)

 # Set the wait time
 $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)

 # Check to see if the connection is done
 if( ! $wait ) {
  # Close the connection and report timeout
  $tcpclient.Close()
  if ( $verbose ) { Write-host -foregroundcolor "Red" "Connection Timeout" }
  $failed = $true
 } else {
  # Close the connection and report the error if there is one
  $error.Clear()
  try { $tcpclient.EndConnect($iar) 2>&1 | out-Null } catch {if($verbose){write-host -foregroundcolor "Red" $error[0]};$failed = $true}
  $tcpclient.Close()
 }

 # Return $true if connection Establish else $False
 if($failed){return $false}else{return $true}
}
Function Test-PortList {
 Param (
  [Parameter(Mandatory=$true)]$FilePath
 )
 if ( ! (test-path $FilePath)) { write-Colored "Red" "" "Unavailable path : $FilePath" ; return }
 Import-CSV -Encoding UTF8 -Delimiter ";" $FilePath | ForEach-Object {
  if (! $_.Service) {return}
  Write-Colored $defaultblue "Testing " (Align $_.Service 30) -nonewline
  Write-Colored $defaultblue " | " (Align $_.IP 15) -nonewline
  Write-Colored $defaultblue " | Port " (Align $_.Port 5) -nonewline
  Write-Colored $defaultblue " | " "" -nonewline
  if (Test-Port $_.IP $_.Port) {write-colored "DarkGreen" "" "Access OK"} else {write-colored "Red" "" "No Access"}
 }
}
Function Test-Account {
 Param (
  $AdUser=$env:USERNAME
 )
 # Check if account is in AD and if account is enabled
 if ( ! (Assert-IsCommandAvailable Get-ADUser) ) {return}
 if ( $(try { get-aduser $AdUser } catch {}) ) {if ( (get-aduser $AdUser).Enabled ) {return $true} else {return $false}} else {return $false}
}
Function Test-Group {
 Param (
  $Group
 )
 #Must not indicate the domain
 if ( ! (Assert-IsCommandAvailable Get-ADGroup) ) {return}
 try {Get-ADGroup $Group | Out-Null ; return $true}
 catch {return $false}
}
Function Test-AccountPassword {
 Param (
  [Parameter(Mandatory=$true)]$User,
  [SecureString]$Password,
  [switch]$printerror,
  [switch]$printcredentials
 )
 # Example : test-accountpassword DOMAIN\username password $false $true
 # WARNING : if the password contains "$" then it cannot be passed directly in the command line except if protected by `

 while (! $Password) {$Password=read-host -AsSecureString "Password"}

 #When passed through command line the password is not cypted
 if ($Password.GetType().Name -ne "SecureString") {$Password=ConvertTo-SecureString -string "$Password" -AsPlainText -force}

 try {
  # $Credential = Get-Credential -Credential "${User}"
  $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User,$Password

  #This function prints the exact credentatials used for testing
  if ($printcredentials) {
   Write-StarLine "-"
   Write-Colored $defaultblue "Domain : " $Credential.GetNetworkCredential().Domain -nonewline
   Write-Colored $defaultblue " | UserName : " $Credential.GetNetworkCredential().UserName -nonewline
   Write-Colored $defaultblue " | Password : " $Credential.GetNetworkCredential().Password
   Write-StarLine "-"
  }

  Start-Process -FilePath cmd.exe /c -Credential $Credential
 } catch {
  if ($printerror) {write-colored "red" "" $error[0] } ; return $false
 }

 return $true
}
Function Test-AccountPasswordList {
 Param (
  [Parameter(Mandatory=$true)]$FilePath
 )
 if ( ! (test-path $FilePath)) { write-Colored "Red" "" "Unavailable path : $FilePath" ; return }
 Import-CSV $FilePath | ForEach-Object {
 if (! $_.Login) {return}
 $user=$_.Domain + "\" + $_.Login
 Write-Colored $defaultblue "Testing " $user -nonewline
 Write-Colored $defaultblue " with Password : " $_.Password -nonewline
 Write-Colored $defaultblue " -> " "" -nonewline
 if ( ! (Test-Account $_.Login)) {Write-Colored "Red" "" "Account does not exist" ; return}
 if (Test-AccountPassword $user $_.Password) {write-colored "DarkGreen" "" "OK"} else {write-colored "Red" "" "KO"}
 }
}
Function Test-URL {
 Param (
  [Parameter(Mandatory=$true)]$URL,
  [PSCredential]$credential,
  [Switch]$comment
 )
 # while ( ! $credential ) { $credential = get-credential }
 # try { (curl -uri $URL -credential $credential).StatusCode } catch { write-colored "Red" "" $Error[0].Exception.Message ; write-colored "Red" "-> " $Error[0] }
 if ( $comment ) {
  Write-Colored $defaultblue "Testing URL : " "$URL" -nonewline
  Write-Colored $defaultblue " with account : " $credential.username
 }
 if ( $credential ) {
  try {
   (Invoke-WebRequest -uri $URL -credential $credential).StatusCode
  } catch {
   write-colored "Red" "Return Code : " $_.Exception.Response.StatusCode.Value__ -nonewline ; write-colored "Red" " -> " $Error[0]
  }
 }
 else {
  try {
   (Invoke-WebRequest -uri $URL -credential $credential).StatusCode
  } catch {
   write-colored "Red" "Return Code : " $_.Exception.Response.StatusCode.Value__ -nonewline ; write-colored "Red" " -> " $Error[0]
  }
 }

#To pass credential
# $user="user"
# $pass="password"
# $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
# $credential = New-Object System.Management.Automation.PSCredential($user, $secpasswd)
}
Function Test-RemotePowershell {
 Param (
  $servername=$env:computername,
  [PSCredential]$Credential,
  [switch]$printmessage,
  [switch]$UseSSL
 )
 try {
  if ($UseSSL) {
   $ServerFQDN=(Resolve-DnsName $servername -QuickTimeout).Name
   if ($Credential) {
    Invoke-Command -ErrorAction Stop -computername $ServerFQDN -UseSSL -credential $Credential -ScriptBlock { }
   } else {
    Invoke-Command -ErrorAction Stop -computername $ServerFQDN -UseSSL -ScriptBlock { }
   }
  } else {
   if ($Credential) {
    Invoke-Command -ErrorAction Stop -computername $servername -credential $Credential -ScriptBlock { }
   } else {
    Invoke-Command -ErrorAction Stop -computername $servername -ScriptBlock { }
   }
  }
  if ($printmessage) {write-colored "Cyan" -ColoredText "$servername`t$true"} else {return $true}
 } catch { if ($printmessage) {write-colored "red"  -ColoredText "$servername`t$false`t$($error[0])"} else { return $false } }
}
Function Test-PSSpeed {
 Param (
  $TestCommand="Write-Host 1"
 )
 powershell -noprofile -ExecutionPolicy Bypass ( Measure-Command { powershell $TestCommand } ).TotalSeconds
}

# GetInfo
Function Get-UserInfo {
 Param (
  $user=$env:USERNAME,
  [Switch]$NoExpire
 )
 <#
 .SYNOPSIS
  Get filtered information on Active Directory User
 .EXAMPLE
  Get-UserInfo toto
  Get all user info on user Toto
 #>
 $TabSize = 20
 write-centered "Account $user"

 if ( ! (Test-Account $user)) {Write-Colored "Red" "" "Account does not exist" ; return} else {$userinformation=Get-ADUser $user -Properties * | Select-Object *}

 Write-Blank

 Write-Colored $defaultblue (Align "Name" $TabSize " = ") $userinformation.Name
 Write-Colored $defaultblue (Align "DisplayName" $TabSize " = ") $userinformation.DisplayName
 Write-Colored $defaultblue (Align "SamAccountName" $TabSize " = ") $userinformation.SamAccountName
 Write-Colored $defaultblue (Align "UserPrincipalName" $TabSize " = ") $userinformation.UserPrincipalName
 if ( $userinformation.mail ) { Write-Colored $defaultblue (Align "mail" $TabSize " = ") $userinformation.mail }
 if ( $userinformation.mailNickname ) { Write-Colored $defaultblue (Align "mailNickname" $TabSize " = ") $userinformation.mailNickname }
 if ( $userinformation.OfficePhone ) { Write-Colored $defaultblue (Align "OfficePhone" $TabSize " = ") $userinformation.OfficePhone }

 Write-Blank

 $TabSize = 40
 if ( $userinformation.Enabled ) { $color = "darkgreen" } else { $color = "red" }
 write-colored $color (Align "Account Enabled" $TabSize " = ") $userinformation.Enabled

 if ( $userinformation.CannotChangePassword -or ! $noexpire ) { $color = "darkgreen" } else { $color = "red" }
 write-colored $color (Align "User cannot change password" $TabSize " = ") $userinformation.CannotChangePassword

 if ( ! $userinformation.PasswordNotRequired ) { $color = "darkgreen" } else { $color = "red" }
 write-colored $color (Align "User must change password at next logon" $TabSize " = ") $userinformation.PasswordNotRequired

 if ( ! $userinformation.LockedOut ) { $color = "darkgreen" } else { $color = "red" }
 write-colored $color (Align "Account Locked" $TabSize " = ") $userinformation.LockedOut -nonewline
 if ( $userinformation.LastBadPasswordAttempt ) { Write-Colored $defaultblue " (Last Failed Attempt : " $userinformation.LastBadPasswordAttempt -nonewline ; ")" } else { Write-Blank }

 if ( $userinformation.PasswordNeverExpires -or ! $noexpire ) { $color = "darkgreen" } else { $color = "red" }
 write-colored $color (Align "Password Never Expires" $TabSize " = ") $userinformation.PasswordNeverExpires

 if ( ! $userinformation.PasswordExpired ) { $color = "darkgreen" } else { $color = "darkgreen" }
 write-colored $color (Align "Password Expired" $TabSize " = ") $userinformation.PasswordExpired -nonewline
 if ( $userinformation.AccountExpirationDate ) { Write-Colored $defaultblue " (Expiration date : " $userinformation.AccountExpirationDate -nonewline ; ")" } else { Write-Blank }

}
Function Get-UserGroupContent {
 Param (
  [System.Collections.ArrayList] $LocalGroup = @{}
 )
 if ( ! $LocalGroup ) {
  $LocalGroup.clear()
  $AdminGroup=Get-UserFromSID "S-1-5-32-544"
  $LocalGroup.add($AdminGroup) | out-null
 } elseif ( $LocalGroup[0] -eq "ALL" ) {
  $LocalGroup.remove("ALL") | out-null
  $Groups=(Get-CimInstance win32_group -filter "LocalAccount='True'").Name
  foreach ($Group in $Groups) { $LocalGroup.add($Group) | out-null }
}

 foreach ($Group in $LocalGroup) {
  Write-Centered $Group
  $Users=(net localgroup $Group | Where-Object {$_})
  if ($Users.count -lt 6) {write-colored "DarkGreen" "" "No user in this group"} else { $Users[4..($Users.count-2)] }
 }

}
Function Get-OSInfo {
 Param (
  [switch]$Hardware,
  [switch]$Software
 )
 $TabSize = 31

 if (! ($Hardware) -and ! ($Software)) {$Hardware=$true;$Software=$true}

 if ( $Hardware ) {
  Write-Blank
  write-centered "HARDWARE`n" "Magenta"

  #Get PC Model :
  $ComputerSystemInfo=Get-CimInstance Win32_ComputerSystem
  #Installed RAM in GB :
  $InstalledRam=(Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object {[Math]::Round(($_.sum / 1GB),2)})
  #Processor :
  $ProcInfo=Get-CimInstance win32_Processor
  $BiosInfo=Get-ciminstance win32_bios

  Write-Colored $defaultblue (Align "Hardware Info" $TabSize " : ") ($ComputerSystemInfo.manufacturer + " (Model : " + $ComputerSystemInfo.model + ")")
  Write-Colored $defaultblue (Align "Bios Info" $TabSize " : ") ("Serial Number : " + $BiosInfo.SerialNumber + " | Bios Name : " + $BiosInfo.Name)
  Write-Colored $defaultblue (Align "Installed RAM" $TabSize " : ") ($InstalledRam.tostring() + " GB")
  Write-Colored $defaultblue (Align "Physical Processor" $TabSize " : ") ($ComputerSystemInfo.NumberOfProcessors)
  Write-Colored $defaultblue (Align "Logical Processors (Total)" $TabSize " : ") ($ComputerSystemInfo.NumberOfLogicalProcessors)
  Write-Colored $defaultblue (Align "Hypervisor Present" $TabSize " : ") ($ComputerSystemInfo.HypervisorPresent)

  write-host

  $ProcInfo | foreach-object {
   Write-Colored $defaultblue (Align "$($_.SocketDesignation)-Processor" $TabSize " : ") $(($_.Name.trim() -replace '\s+',' ')," | ",$_.Description)
   Write-Colored $defaultblue (Align "$($_.SocketDesignation)-Logical Processors" $TabSize " : ") ($_.NumberOfLogicalProcessors)
   Write-Colored $defaultblue (Align "$($_.SocketDesignation)-Speed Current/Max" $TabSize " : ") ($_.CurrentClockSpeed,"Mhz /",$_.MaxClockSpeed,"Mhz")
  }
 }

 if ( $Software ) {
  Write-Blank
  write-centered "SOFTWARE`n" "Magenta"

  $os = Get-CimInstance win32_operatingsystem

  Write-Colored $defaultblue (Align "Windows Version" $TabSize " : ") (Get-WindowsVersion)
  Write-Colored $defaultblue (Align "Installation Date" $TabSize " : ") $(Format-Date ($os.InstallDate.tostring()))
  Write-Colored $defaultblue (Align "Uptime" $TabSize " : ") (Get-UptimePerso)
  Write-Colored $defaultblue (Align "TimeZone" $TabSize " : ") (([TimeZoneInfo]::Local).DisplayName)

  #NLA (If Error Message NLA will be marked as KO)
  $NLA_Config=(Get-CimInstance "Win32_TSGeneralSetting "-Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired 2> $null
  if ( $NLA_Config) {Write-colored darkgreen (Align "NLA" $TabSize " : ") "OK"} else { Write-colored red (Align "NLA" $TabSize " : ") "KO"}

  #SCCM
  if ((Get-SCCMSiteCode)) {
   if ( (test-path C:\SMSLogs\*JoinDomain*) ) {
    $installer=get-content "C:\SMSLogs\*JoinDomain*" | select-string "InstallerUserName" | get-unique | ForEach-Object { $_.Line.Split(":")[1].Trim()}
   }
   if ($installer) { Write-Colored $defaultblue " (Installed by : " "$installer" -nonewline ; write-Colored "Black" ")" } else {write-blank}
   Write-Colored $defaultblue (Align "SCCM Site Code" $TabSize " : ") Get-SCCMSiteCode
   Write-Colored $defaultblue (Align "Business Category" $TabSize " : ") (Get-BusinessCategory)
  }

  Write-Colored $defaultblue (Align "Swap" $TabSize " : ") (Get-Swap)

  #Get Proxy Settings
  # ([System.Net.WebProxy]::GetDefaultProxy()).Address

  #Bitlocker
  if (Assert-IsAdmin) {
   Try {
    Get-BitlockerVolume | Sort-Object MountPoint | ForEach-Object {
     Write-Colored $defaultblue (Align "Bitlocker $($_.MountPoint)" $TabSize " : ") ("$($_.VolumeStatus)")
    }
   } Catch {
   Write-Colored $defaultblue (Align "Bitlocker" $TabSize " : ") "Not Available"
   }
  }

  #Secure Boot
  if (Assert-IsAdmin) {
   Write-Colored $defaultblue (Align "Secure Boot" $TabSize " : ") $(Try {Confirm-SecureBootUEFI -ErrorAction Stop} catch {$False})
  }

  #SMB1 Check
  $SMB1Enabled=(Get-SmbServerConfiguration).EnableSMB1Protocol
  if ($SMB1Enabled) {$SMBColor = "Red"} else {$SMBColor = "Green"}
  Write-Colored $SMBColor (Align "SMB1 Enabled" $TabSize " : ") $SMB1Enabled

  #Credential Guard
  Try {
   $CredentialGuardInfo=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
   $VirtualizationBasedSecurityStatus=switch ($CredentialGuardInfo.VirtualizationBasedSecurityStatus)
   {
    0 {"Red","Disabled"}
    1 {"Yellow","Enabled but not Running"}
    2 {"Green","Enabled and Running"}
   }
   Write-Colored $VirtualizationBasedSecurityStatus[0] (Align "Virtualization Security" $TabSize " : ") $VirtualizationBasedSecurityStatus[1]

   if ($CredentialGuardInfo.SecurityServicesRunning[0] -eq 0) {
    Write-Colored "Red" (Align "Credential Guard" $TabSize " : ") "No Service Running"
   } else {
    if ($CredentialGuardInfo.SecurityServicesRunning -Contains('1') ){ Write-Colored "Green" (Align "Credential Guard" $TabSize " : ") "Windows Defender Credential Guard is running" }
    if ($CredentialGuardInfo.SecurityServicesRunning -Contains('2') ){ Write-Colored "Green" (Align "Credential Guard" $TabSize " : ") "HVCI is running" }
    if ($CredentialGuardInfo.SecurityServicesRunning -Contains('3') ){ Write-Colored "Green" (Align "Credential Guard" $TabSize " : ") "System Guard Secure Launch is running" }
   }
  } Catch {
   Write-Colored "Red" (Align "Credential Guard" $TabSize " : ") "Error checking status"
  }

  #Anvitirus
  $AntivirusResult=Get-AntiVirus
  If ($AntivirusResult) {
   $Count=0
   $AntivirusResult | ForEach-Object {
    $Count++
    Write-Colored $defaultblue (Align "Antivirus [$Count]" $TabSize " : ") $_.DisplayName -NoNewLine
    Write-Colored -Color $defaultblue " - " -NoNewLine
    if ($_.'Real-time Protection Status' -ne 'On') {$Color='Red'} else {$Color='Green'}
    Write-Colored $Color -ColoredText "$($_.'Real-time Protection Status') " -NoNewLine
    if ($_.'Definition Status' -ne 'Up To Date') {$Color='Red'} else {$Color='Green'}
    Write-Colored $Color -ColoredText "[$($_.'Definition Status')]"
   }
  }

 }
}
Function Get-LocalDomainInfo {
$TabSize=20
Write-Colored $defaultblue (Align "Server Hostname" $TabSize " : ") $env:computerName
Write-Colored $defaultblue (Align "Server FQDN" $TabSize " : ") ([System.Net.Dns]::GetHostByName(($env:computerName))).HostName
Write-Colored $defaultblue (Align "Server Domain" $TabSize " : ") (Get-CimInstance WIN32_ComputerSystem).Domain
Write-Colored $defaultblue (Align "User DNS Domain" $TabSize " : ") $env:USERDNSDOMAIN
Write-Colored $defaultblue (Align "User Domain" $TabSize " : ") $env:USERDOMAIN
Write-Colored $defaultblue (Align "User Domain Roaming" $TabSize " : ") $env:USERDOMAIN_ROAMINGPROFILE
Write-Colored $defaultblue (Align "Logon Server" $TabSize " : ") $env:LOGONSERVER
}
Function Get-DomainInfo {
 Param (
  [Switch]$Object
 )
 # Show FSMO Roles
 $Roles=(Get-ADDomainController -Filter * | Select-Object OperationMasterRoles | Where-Object {$_.OperationMasterRoles}).OperationMasterRoles

 $ByRole=$Roles | ForEach-Object {
  $Role=$_
  Get-ADDomainController -Filter * | Where-Object {$_.OperationMasterRoles -like "$Role"} | Select-Object @{Name="OperationMasterRoles";Expression={$Role}},Name,Domain,Forest,IPV4Address,Site,OperatingSystem, OperatingSystemServicePack
 }

 if ($Object) {
  return $ByRole
 }

 $ByRole | ForEach-Object {
 $TabSize=40
 Write-Colored -NonColoredText (Align "$($_.OperationMasterRoles) ($($_.Domain))" $TabSize " : ") -ColoredText "$($_.Name) ($($_.IPV4Address))"
 }
}
Function Get-WindowsVersion {
 Param (
  $ServerName,
  [Switch]$Quick
 )
 Try {
  if (! ($Quick)) {
   #Check Command Availibility (PS 5.1+)
   if ($ServerName) {
    $AdvCommandAvailable=invoke-command -ComputerName $ServerName -ScriptBlock {$(get-command Get-ComputerInfo -ErrorAction SilentlyContinue)}
   } else {
    $AdvCommandAvailable=$(get-command Get-ComputerInfo -ErrorAction SilentlyContinue)
   }
  }

  if ($AdvCommandAvailable ) {
   if ($ServerName) {
    $ComputerInfo=invoke-command -ComputerName $ServerName -ScriptBlock {Get-ComputerInfo -Property OsName,WindowsVersion,OsHardwareAbstractionLayer,BiosFirmwareType,OsLanguage,OsArchitecture} -ErrorAction Stop
   } else {
    $ComputerInfo=Get-ComputerInfo -Property OsName,WindowsVersion,OsHardwareAbstractionLayer,BiosFirmwareType,OsLanguage,OsArchitecture
   }

   if ($($ComputerInfo.WindowsVersion)) { $OsSpecificVersion=$ComputerInfo.WindowsVersion } else { $OsSpecificVersion="("+$ComputerInfo.OsHardwareAbstractionLayer+")" }
   if ($($ComputerInfo.BiosFirmwareType.Value)) { $BiosType=$ComputerInfo.BiosFirmwareType.Value } else { $BiosType=$ComputerInfo.BiosFirmwareType }
   $version=$ComputerInfo.OsName + " " + $OsSpecificVersion + " [" + $BiosType + "]" + "[" + $ComputerInfo.OsLanguage + "]" + "[" + $ComputerInfo.OsArchitecture + "] "

  } else {

   If (! ($ServerName) ) {
    $ReleaseID=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    if ($ReleaseID) { $Revision=" | Release $ReleaseID" } else {$Revision=""}
   } else {
    $Revision=""
   }

   If (get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $OSINFO=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue -ComputerName $ServerName
   } else {
    $OSINFO=Get-WmiObject Win32_OperatingSystem -ErrorAction Stop -ComputerName $ServerName
   }

   $OSNAME=$OSINFO.caption.trim()
   if ($OSINFO.CSDVersion) { $OSSP=" - "+$OSINFO.CSDVersion.trim() } else { $OSSP="" }
   $OSBUILD=$OSINFO.Version.trim()
   if ($OSINFO.OSArchitecture) { $OSArchitecture=$OSINFO.OSArchitecture.Trim() } else { $OSArchitecture="N/A" }
   $version="$OSNAME $OSSP ($OSBUILD$Revision | $OSArchitecture)"
  }
  return $version
 } catch {
  Return "Cannot get Windows Version ($($Error[0].ToString().Trim()))"
 }
}
Function Get-LicenseStatus {
 $result=Get-CimInstance SoftwareLicensingProduct -filter "LicenseStatus LIKE 1" | Select-Object Name, Description,
  @{Label='KeyServerDiscovered'; Expression={if (!$_.DiscoveredKeyManagementServiceMachineName) {"No Key Server Discovered"} else { $_.DiscoveredKeyManagementServiceMachineName }}},
  @{Label='KeyServer'; Expression={if (!$_.KeyManagementServiceMachine) {"No Key Server Defined"} else { $_.KeyManagementServiceMachine }}},
  @{Label='KeyServerPort'; Expression={$_.DiscoveredKeyManagementServiceMachinePort}}

 write-blank

 if (! ($result)) {Write-Colored "Red" "" "Server is not activated"} else {
  ($result | out-string).split("`r`n") | Where-Object { $_ }
  if ($result.KeyServer -eq "No Key Server Defined" -and $result.KeyServerDiscovered -eq "No Key Server Discovered") {Write-Colored "Red" "" "No KMS server found"}
  Write-Colored "darkgreen" "" "Server is Activated"
 }
 write-blank
 $LicenseKey=(Get-CimInstance -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey
 if (! $LicenseKey) {$LicenseKey="Not found"}
 Write-Colored $defaultblue "Windows License Key : " $LicenseKey
 write-blank
}
Function Get-ActivationStatus {
# Script found : https://social.technet.microsoft.com/wiki/contents/articles/5675.determine-windows-activation-status-with-powershell.aspx
[CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$DNSHostName = $Env:COMPUTERNAME
    )
    process {
        try {
            $wpa = Get-CimInstance SoftwareLicensingProduct -ComputerName $DNSHostName `
            -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" `
            -Property LicenseStatus -ErrorAction Stop
        } catch {
            $status = New-Object ComponentModel.Win32Exception ($_.Exception.ErrorCode)
            $wpa = $null
        }
        $out = New-Object psobject -Property @{
            ComputerName = $DNSHostName;
            Status = [string]::Empty;
        }
        if ($wpa) {
            :outer foreach($item in $wpa) {
                switch ($item.LicenseStatus) {
                    0 {$out.Status = "Unlicensed"}
                    1 {$out.Status = "Licensed"; break outer}
                    2 {$out.Status = "Out-Of-Box Grace Period"; break outer}
                    3 {$out.Status = "Out-Of-Tolerance Grace Period"; break outer}
                    4 {$out.Status = "Non-Genuine Grace Period"; break outer}
                    5 {$out.Status = "Notification"; break outer}
                    6 {$out.Status = "Extended Grace"; break outer}
                    default {$out.Status = "Unknown value"}
                }
            }
        } else {$out.Status = $status.Message}
        $out
    }
}
Function Get-HostContent {
 $FilePath="$env:SystemRoot\system32\drivers\etc\hosts"
 $FileContent=get-content $FilePath | select-string -Pattern '^#|^$' -NotMatch
 if ($FileContent) { $filecontent | ForEach-Object {write-host $_} } else { write-colored "darkgreen" "" "$FilePath is empty"}
}
Function Set-HostContent {
 $FilePath="$env:SystemRoot\system32\drivers\etc\hosts"
 notepad $FilePath
}
Function Get-LangSettings {
$alignsize=20
Write-Colored $defaultblue (Align "OS Language" $alignsize " : " ) $PsUICulture
#get-culture | format-list -property * => Get all Regional Properties
$RegionalInfo = get-culture
$RegionalInfoFull=$RegionalInfo.Name+" [ "+$RegionalInfo.DisplayName+" ]"
Write-Colored $defaultblue (Align "Regional Settings" $alignsize " : " ) $RegionalInfoFull

#$PsCulture => Get Only Name of Regional Settings
}
Function Get-LangForAllUser {
 if ( ! (Assert-IsAdmin) ) {Write-Colored "red" -ColoredText "You must be admin to run this command" ; return}
 New-PSDrive HKU Registry HKEY_USERS |Out-Null
 $ObjUserList=@()
 foreach( $user in $((Get-ChildItem HKU:\).PSChildName | Sort-Object)) {
  try {$DateFormat=(Get-ItemProperty -ErrorAction SilentlyContinue -Path "HKU:\$user\Control Panel\International")} catch {}
  if ($DateFormat) {
   $obj = New-Object PSObject
   if (($user -eq ".DEFAULT") -or ( !(Get-Command "Get-UserFromSID" -ErrorAction SilentlyContinue))) {$login=$user} else { $login=$(Get-UserFromSID $user) }
   $obj | Add-Member NoteProperty User $login
   $obj | Add-Member NoteProperty sCountry $DateFormat.sCountry
   $obj | Add-Member NoteProperty LocalName $DateFormat.LocaleName
   $obj | Add-Member NoteProperty sLanguage $DateFormat.sLanguage
   $obj | Add-Member NoteProperty sShortDate $DateFormat.sShortDate
   $obj | Add-Member NoteProperty sShortTime $DateFormat.sShortTime
   $obj | Add-Member NoteProperty sDecimal $DateFormat.sDecimal
   $obj | Add-Member NoteProperty sList $DateFormat.sList
   $obj | Add-Member NoteProperty sCurrency $DateFormat.sCurrency
   $obj | Add-Member NoteProperty sLongDate $DateFormat.sLongDate
   $ObjUserList += $obj
  }
 }
 $ObjUserList
}
Function Get-RolesAndFeatures {
 Param (
  $RoleOrFeature
 )
 #Only works on server OS starting with Windows 2008R2
 if ( ! (Assert-MinOSVersion 7000) ) {return}
 if ( ! (Assert-OSType) ) {Get-WindowsOptionalFeature -Online | Where-Object state -ne 'disabled' ; return}
 $ProgressPreference="SilentlyContinue"
 Import-module servermanager
 if ($RoleOrFeature -eq "Role") {$RolesAndFeatures=Get-WindowsFeature | Where-Object {$_.installed -and $_.FeatureType -eq "Role"}}
 elseif ($RoleOrFeature -eq "Feature") {$RolesAndFeatures=Get-WindowsFeature | Where-Object {$_.installed -and $_.FeatureType -eq "Feature"}}
 else {$RolesAndFeatures=Get-WindowsFeature | Where-Object {$_.installed}}
 # Get-WindowsFeature | Where-Object Installed
 $RolesAndFeatures | ForEach-Object {
  If ($_.FeatureType -eq "Role") { Write-Colored "Magenta" ("   " *$_.Depth+"[") "R" -nonewline} else { Write-Colored $defaultblue ("   " *$_.Depth+"[") "F" -nonewline}
  write-colored -NonColoredText "] " -ColoredText ($_.DisplayName+" ("+$_.Name+")")
 }
 $ProgressPreference = "Continue";
}
Function Get-KMS {
 $KMSServerList=(nslookup -type=srv _vlmcs._tcp 2>$errormessage | Select-Object -skip 3 | select-string -notmatch -pattern "internet address =|nameserver =")
 # if ( $KMSServerList[0].line.contains("DNS request timed out") ) { write-colored "Red" "" "No kms server found" ; return}
 if ( $KMSServerList | select-string "timeout" )  { write-colored "Red" "" "DNS request timed out" ; return}
 $KMSServerList_Split = $KMSServerList -replace "_vlmcs._","__SplitHere" -split "SplitHere" -replace "\s+"," " -join "," -split "__" -replace ", ","," -replace "^,","" -notmatch '^\s*$'

 foreach($server in $KMSServerList_Split) {
  $server_line=($server | Select-string -pattern ",").line.split(',')
  $Priority=$server_line[1].TrimStart("priority =")
  $Weight=$server_line[2].TrimStart("weight =")
  $Port=$server_line[3].TrimStart("port =")
  $ServerName=$server_line[4].TrimStart("svr hostname =")

  Write-Colored $defaultblue "Server : " (Align $ServerName 20) -nonewline
  Write-Colored $defaultblue " | Port : " (Align $Port 4) -nonewline
  Write-Colored $defaultblue " | Priority : " (Align $Priority 2) -nonewline
  Write-Colored $defaultblue " | Weight : " (Align $Weight 2) -nonewline
  if ( ! (Test-Port $ServerName $Port) ) { write-colored "Red" "| Access : " "KO" } else { write-colored "DarkGreen" "| Access : " "OK" }
 }

}
Function Get-TimeZoneCIM {
 #Does not seem to be the same as the clock (must check)
 # [TimeZoneInfo]::Local
 (Get-CimInstance -Class win32_timezone).Caption
}
Function Get-InstalledHotfix {
 Param (
  $KBInstalled= @{},
  $ServerName = $env:COMPUTERNAME,
  [PSCredential]$Credential
 )
 # Example to find more than one KB : Get-InstalledHotfix ("KB3042553","KB3149090")
 $count=0 ; $globalcount=0 ; $alignsize=9
 Write-Centered "$ServerName"
 Write-StarLine "-" ([console]::foregroundcolor)
 try {
 if ($Credential) {
  $AllHotFix=Get-Hotfix -ComputerName $ServerName -credential $Credential
 } else {
  $AllHotFix=Get-Hotfix -ComputerName $ServerName
 }

 } catch {write-colored "red" "" $error[0]}

 $AllHotFix | Sort-Object HotfixID | Where-Object {
  $globalcount++
  #Color specified hotfixes
  if ($KBInstalled -contains $_.HotfixID) {$color="red"} else { $color=$defaultblue }
  #Last occurence global
  if ($globalcount -eq $AllHotFix.count -or ! $AllHotFix.count) {
   #If last occurence is the first of a line
   # if ($count -ne 0 ) {write-colored -NonColoredText " | " -nonewline}
   write-colored $color " | " (Align $_.HotfixID $alignsize) -nonewline
   write-colored $color " |"
   Write-StarLine "-" ([console]::foregroundcolor)
  }
  #First occurence per line
  elseif ($count -eq 0 ) { write-colored $color " | " (Align $_.HotfixID $alignsize) -nonewline ; $count++}
  #Last occurence per line
  elseif ($count -eq 7 ) { write-colored $color " | " (Align $_.HotfixID $alignsize) -nonewline ;  write-colored $color " |" ; $count=0}
  #All other occurence
  else { write-colored $color " | " (Align $_.HotfixID $alignsize) -nonewline ; $count++}
  }
 write-Centered "Number of installed hotfixes :  $globalcount"
 Write-StarLine "*"

 # $cred=get-Credential
 # (Get-ADAllServerInSameOU $ExampleServerName).Name | ForEach-Object {Get-InstalledHotfix -KBInstalled "" -ServerName $_ -Credential $cred }
}
Function Get-AdditionnalFeatures {
 # Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -like "*.Net Framework*" -and $_.InstallDate}
 Get-CimInstance Win32_Product| Select-Object Name, Vendor, InstallDate | Sort-Object Vendor,Name
}
Function Get-NetFrameworkVersion {
#More info here : https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
Get-ItemProperty -name Version,Release -EA 0 | Where-Object { $_.PSChildName -match '^(?![SW])\p{L}'} |
Select-Object @{Name="Type";Expression={$_.PSChildName}}, Version, Release, @{
  name="Product"
  expression={
   switch -regex ($_.Release) {
    "378389" { [Version]"4.5" }
    "378675|378758" { [Version]"4.5.1" }
    "379893" { [Version]"4.5.2" }
    "393295|393297" { [Version]"4.6" }
    "394254|394271" { [Version]"4.6.1" }
    "394802|394806" { [Version]"4.6.2" }
    "460798|460805" { [Version]"4.7" }
    "461308|461310" { [Version]"4.7.1" }
    "461808|461814" { [Version]"4.7.2" }
    "528040|528049" { [Version]"4.8" }
    Default { [Version]"Undocumented version (> 4.7.2), please update script" }
   }
  }
 }
}

# IIS
Function Update-IISPoolIdentity {
 Param (
  $IISDomainAccountCurrent,
  [pscredential]$NewCredential
 )
 Import-Module WebAdministration

 Get-ChildItem IIS:\AppPools | Where-Object { $_.processModel.userName -eq $IISDomainAccountCurrent } | ForEach-Object {
  $Pool=$_.Name

  write-host "Checking `"$Pool`""
  write-host "Current Login : $($_.processModel.userName) | Current Password : $($_.processModel.password)"

  write-host "Clearing user and password"
  clear-ItemProperty "IIS:\AppPools\$Pool" -Name processModel.userName
  clear-ItemProperty "IIS:\AppPools\$Pool" -Name processModel.password

  $ClearedProperties=Get-ItemProperty "IIS:\AppPools\$Pool"
  write-host "Cleared login : $($ClearedProperties.processModel.userName) | Current Password : $($ClearedProperties.processModel.password)"

  write-host "Setting new user and password"
  # Set-ItemProperty "IIS:\AppPools\$Pool" -name processModel -value @{userName=$IISDomainAccountNew;password=$IISDomainPasswordNew;identitytype=3}
  Set-ItemProperty "IIS:\AppPools\$Pool" -name processModel.userName -value $NewCredential.UserName
  Set-ItemProperty "IIS:\AppPools\$Pool" -name processModel.password -value $NewCredential.GetNetworkCredential().password

  write-host "New Login / Password"
  $NewProperties=Get-ItemProperty "IIS:\AppPools\$Pool"
  write-host "Current Login : $($NewProperties.processModel.userName) | Current Password : $($NewProperties.processModel.password)"

  write-host "Start pool $Pool"
  Start-WebAppPool -Name $Pool
 }
}
Function Get-IISVersion {
 [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:SystemRoot\system32\inetsrv\InetMgr.exe").ProductVersion
}
Function Get-IISSite {
 #Import module does not work remotely
 try { Import-Module WebAdministration -ErrorAction Stop } catch {write-host -foregroundcolor "Red" $Error[0] ; return}
 $ServerName=$Env:COMPUTERNAME

 $BindingList=@();
 Get-ChildItem "IIS:\Sites\" | ForEach-Object {
  $S_SiteName=$_.Name
  $S_LogFolder=(Get-ItemProperty "IIS:\Sites\$S_SiteName" -Name Logfile).Directory
  $S_ID=$_.ID;
  $S_state=$_.state;
  $S_physicalPath=$_.physicalPath;
  $_.Bindings.Collection | ForEach-Object {
   $BindingList+=New-Object PSObject -Property @{
    ServerName=$ServerName;
    Name=$S_SiteName;
    ID=$S_ID;
    State=$S_state;
    PhysicalPath=$S_LogFolder;
    LogPath=$S_physicalPath;
    BindingProtocol=$_.protocol;
    Binding=$_.bindingInformation;
    BindingSSLFlag=$_.sslFlags;
   }
  }
 }
 $BindingList
}

# EventLog
Function Get-EventLogInfo {
 Param (
  $LogType,
  $ErrorCount=2,
  $NumberOfDays,
  $ServerName=$env:COMPUTERNAME
 )
 if ( ! (Assert-IsCommandAvailable Get-EventLog) ) {return}
 try {
  $EventLogList=(Get-EventLog -ComputerName $ServerName -list).log
 } catch {Write-Colored "Red" -ColoredText $Error[0] ; return}
 while (! ($EventLogList -contains $LogType) ) {$LogType=read-host "Please choose one of the following Log : $([system.String]::Join(", ", $EventLogList)) "}

 if (! $NumberOfDays) {
  $LastBootLabel="since last reboot"
  $LastBootTime=(Get-CimInstance -ClassName win32_operatingsystem -ComputerName $ServerName).lastbootuptime
 } else {
  #Get the date from X days !
  $LastBootLabel="in the past $NumberOfDays days"
  $LastBootTime=(Get-Date).Adddays(-$NumberOfDays)
 }

 Write-Centered -Color 'Magenta' "[Checking Event from event log $LogType $LastBootLabel ($LastBootTime)]"
 Write-Blank

 try {
  $AllEvents=(Get-EventLog -ComputerName $ServerName $LogType -after $LastBootTime | Where-Object {$_.entrytype -eq "Error" -or $_.entrytype -eq "Warning" -or $_.entrytype -eq "Critical"}) 2>$null
 } catch {
  Write-Colored "Red" -ColoredText $Error[0].Exception.Message
 }

 $Events=($AllEvents | Select-Object @{Label='SourceID'; Expression={ $_.Source +" (Event:"+$_.EventID +")" }},Message | Group-Object Message | Where-Object {$_.count -gt $ErrorCount})
 if ($Events.count -eq 0 ) {write-Colored "darkgreen" -ColoredText "No recurring (more than $ErrorCount) Errors/Warnings/Criticals message in log $LogType $LastBootLabel ($LastBootTime)";return}
 $Events | ForEach-Object {
  if ($_.group.count -gt 1) {$Plural="s"} else {$Plural=""}
  write-colored -Color Cyan -ColoredText "$($_.group[0].SourceID) | $($_.group.count) Occurence$Plural since $LastBootLabel ($LastBootTime)"
  $_.group[0].Message.trim()
  Write-Blank
 }
}
Function Get-EventLogNPSSecurity {

 #List all NPS Logons

 $ID=$(6272,6273)

 Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-Security-Auditing';ID=$ID} |  Select-Object RecordID,
  @{Label='DateTime';Expression={get-date -uformat '%Y-%m-%d %T' $_.TimeCreated -ErrorAction SilentlyContinue}},
  # @{Label='Machine';Expression={($_.MachineName -Split ('\.'))[0]}},
  @{Label='U_AccountName';Expression={$_.Properties[1].value}},
  @{Label='U_FQAN';Expression={$_.Properties[3].value}},
  #@{Label='M_AccountName';Expression={$_.Properties[5].value}},
  #@{Label='M_FQAN';Expression={$_.Properties[6].value}},
  @{Label='M_CallingID';Expression={$_.Properties[8].value}},
  @{Label='M_CalledID';Expression={$_.Properties[7].value}},
  @{Label='NAS_ID';Expression={$_.Properties[11].value}},
  @{Label='NAS_IP';Expression={$_.Properties[9].value}}
  #@{Label='RAD_Client_Name';Expression={$_.Properties[14].value}},
  #@{Label='RAD_Client_IP';Expression={$_.Properties[15].value}}

}
Function Get-EventLogNPSSystem () {

 #List all NPS Logons

$XML = @'
 <QueryList>
  <Query Id="0" Path="System">
   <Select Path="System">*[System[Provider[@Name='RemoteAccess']]]</Select>
  </Query>
 </QueryList>
'@

# Status Message
 $Status_List=@()
 # 20249 : The user $($_.properties.Value[1]) has connected and failed to authenticate on port $($_.properties.Value[2]). The line has been disconnected.
 $Status_List+=New-Object PSObject -Property @{Name='20249';Status='Connected | Failed Authentication'}
 # 20250 : The user $($_.properties.Value[2]) has connected and has been successfully authenticated on port $($_.properties.Value[3]).
 $Status_List+=New-Object PSObject -Property @{Name='20250';Status='Connected and Authenticated'}
 # 20253 : The user $($_.properties.Value[2]) connected to port $($_.properties.Value[3]) has been disconnected because no network protocols were successfully negotiated.
 $Status_List+=New-Object PSObject -Property @{Name='20253';Status='Disconnected | Failed Negociation'}
 # 20255 : The following error occurred in the Point to Point Protocol module on port: $($_.properties.Value[1]), UserName: $($_.properties.Value[2]). $($_.properties.Value[3]) |ErrorMessage|
 $Status_List+=New-Object PSObject -Property @{Name='20255';Status='Error'}
 # 20271 : The user $($_.properties.Value[1]) connected from $($_.properties.Value[2]) |SourceIP| but failed an authentication attempt due to the following reason: $($_.properties.Value[3]) |ErrorMessage|
 $Status_List+=New-Object PSObject -Property @{Name='20271';Status='Connected | Failed Authentication | Error'}
 # 20272 (Full User Stats) : The user $($_.properties.Value[2]) connected on port $($_.properties.Value[3]) on $($_.properties.Value[4]) at $($_.properties.Value[5]) and disconnected on $($_.properties.Value[6]) at $($_.properties.Value[7]).  The user was active for $($_.properties.Value[8]) minutes $($_.properties.Value[9]) seconds.  $($_.properties.Value[10]) bytes were sent and $($_.properties.Value[11]) bytes were received. The reason for disconnecting was $($_.properties.Value[12]). The tunnel used was WAN $($_.properties.Value[13]). The quarantine state was $($_.properties.Value[14]).
 $Status_List+=New-Object PSObject -Property @{Name='20272';Status='Full Status'}
 # 20274 : The user $($_.properties.Value[2]) connected on port $($_.properties.Value[3]) has been assigned address $($_.properties.Value[4])
 $Status_List+=New-Object PSObject -Property @{Name='20274';Status='IP Assignement'}
 # 20275 : The user with ip address $($_.properties.Value[2]) has disconnected
 $Status_List+=New-Object PSObject -Property @{Name='20275';Status='Disconnected'}

#ID 20271 is the same with more information than : 20255 & 20249 so we will ignore them

Get-WinEvent -FilterXml $xml | Where-Object { ($_.ID -ne '20249') -and ($_.ID -ne '20255') } | Select-Object RecordID,
@{Label='DateTime';Expression={get-date -uformat '%Y-%m-%d %T' $_.TimeCreated -ErrorAction SilentlyContinue}},ID,
@{Label='Status';Expression={ $Value=$Status_List | Where-Object Name -eq $_.ID ; if ($Value) {$Value.Status} else {"Unknown"} }},
@{Name="UserUPN";Expression={
 $ActionListProperties1=@('20249','20271')
 $ActionListProperties2=@('20250','20253','20255','20272','20274')
 if ( $ActionListProperties1 -Contains($_.ID) ) {$_.Properties[1].value}
 elseif ( $ActionListProperties2 -Contains($_.ID) ) {$_.Properties[2].value}
 else {"N/A"}
}},
@{Name="Origin_IP";Expression={
 $ActionListProperties2=@('20271')
 if ( $ActionListProperties2 -Contains($_.ID) ) {$_.Properties[2].value}
 else {"N/A"}
}},
@{Name="VPN_IP";Expression={
 $ActionListProperties2=@('20275')
 $ActionListProperties4=@('20274')
 if ( $ActionListProperties2 -Contains($_.ID) ) {$_.Properties[2].value}
 elseif ( $ActionListProperties4 -Contains($_.ID) ) {$_.Properties[4].value}
 else {"N/A"}
}},
@{Name="ErrorMessage";Expression={
 $ActionListProperties3=@('20255','20271')
 if ( $ActionListProperties3 -Contains($_.ID) ) {$_.Properties[3].value}
 else {"N/A"}
}},
@{Name="FullMessage";Expression={$_.Message.ToString() -Replace "^RoutingDomainID- {.*}: ","" -Replace "^CoId={.*}: ",""}}
# @{Name="Info";Expression={$_.Message.ToString() -Replace "^CoId={.*}: ",""}} | Where-Object { ($_.Id -ne 20257) -and ($_.Id -ne 20249) }

}
Function Get-EventLogNPSDetailed {
 Param (
  $ServerName=$Env:COMPUTERNAME,
  $StartTime=$(Get-Date).addDays(-31),
  $EndTime=$(Get-Date)
 )
 Get-WinEvent -ComputerName $ServerName -FilterHashtable @{LogName='System';ID='20272';StartTime=$StartTime;EndTime=$EndTime} | Select-Object `
  @{Name="UPN";Expression={$_.Properties[2].value}},
  @{Name="UserName";Expression={(Get-ADUserFromUPN $_.Properties[2].value).Name}},
  @{Name="DateConnection";Expression={Convert-DateSpecific $("$($_.Properties[4].value) $($_.Properties[5].value)")}},
  @{Name="DateDisconnection";Expression={Convert-DateSpecific $("$($_.Properties[6].value) $($_.Properties[7].value)")}},
  @{Name="Duration";Expression={ [timespan]::fromseconds($([int]$_.Properties[8].value*60)+$([int]$_.Properties[9].value)) }} ,
  @{Name="DataSent";Expression={$([int]$_.Properties[10].value)}},
  @{Name="DataReceived";Expression={$([int]$_.Properties[11].value)}},
  @{Name="DisconnectReason";Expression={$_.Properties[12].value}}
}
Function Get-EventLogSecurityAuthentication {
 # EventID 4624 info : https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624

 # To Check NTLM: Get-EventLogSecurityAuthentication | ? {$_.LogonProcessName -like "*NtLm*"} | ft


$ErrorActionPreference="Stop"
Try {
  Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-Security-Auditing';ID=4624} | Select-Object RecordID,
   @{Label='DateTime';Expression={get-date -uformat '%Y-%m-%d %T' $_.TimeCreated -ErrorAction SilentlyContinue}},
   @{Label='Machine';Expression={($_.MachineName -Split ('\.'))[0]}},
   @{Label='User';Expression={$_.UserID}},
   @{Label='SubjectUser';Expression={"$($_.Properties[2].value)\$($_.Properties[1].value)"}},
   @{Label='TargetUser';Expression={"$($_.Properties[6].value)\$($_.Properties[5].value)"}},
   @{Label='LogonType';Expression={
    switch ($_.Properties[8].value) {
     2  {'Interactive'}
     3  {'Network'}
     4  {'Batch'}
     5  {'Service'}
     7  {'Unlock'}
     8  {'NetworkCleartext'}
     9  {'NewCredentials'}
     10 {'RemoteInteractive'}
     11 {'CachedInteractive'}
    }
    }},
   @{Label='LogonProcessName';Expression={$_.Properties[9].value}},
   @{Label='AuthPackage';Expression={$_.Properties[10].value}},
   @{Label='MachineName';Expression={$_.Properties[11].value}},
   @{Label='IpAddress';Expression={$_.Properties[18].value}},
   @{Label='IpPort';Expression={$_.Properties[19].value}},
   @{Label='LogonProcess';Expression={$_.Properties[17].value}},
   @{Label='ElevatedToken';Expression={
    switch ($_.Properties[26].value) {
     '%%1842' {$True}
     '%%1843' {$False}
   }
   }}
 } Catch {
  write-Host -ForegroundColor "red" $Error[0]
 }
}
Function Get-EventLogSecurityDCAccountLocked {
 Param (
  $DCServer=$((Get-ADDomain).InfrastructureMaster)
 )
 Try {
 Get-WinEvent -ComputerName $DCServer -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop | Select-Object -Property TimeCreated,
  @{Label='UserName';Expression={$_.Properties[0].Value}},
  @{Label='ClientName';Expression={$_.Properties[1].Value}}
 } catch {
  write-host -ForegroundColor "Red" $Error[0]
 }
}

# Network
Function Get-EthernetConf {
 Param (
  [Switch]$NoFilter,
  [Switch]$ShowDisconnected
 )
 $alignsize=30
 $fontcolor="Cyan"
 $ErrorActionPreference="Stop"
 try {
  #List only Ethernet Card with a detected IP and MAC Address
  # $NetworkInfo=Get-CimInstance Win32_NetworkAdapterConfiguration -property * | where-object {$_.IPAddress -and $_.MACAddress }
  #List only Ethernet Card with a detected IP only (with VPN, no MAC appear)
  $NetworkInfo=Get-CimInstance Win32_NetworkAdapter -property * | where-object MACAddress | Sort-Object NetConnectionStatus

  $NetworkInfo | foreach-object {
   if ( (! $NoFilter) -and (! $_.NetConnectionStatus ) ) { Return }
   if ((($_.NetConnectionStatus -eq "0") -or ($_.NetConnectionStatus -eq "7")) -and (! $ShowDisconnected)) {Return}

  Write-StarLine "-" ; write-centered $_.MACAddress "Magenta" ; Write-StarLine "-"
   write-colored $fontcolor (Align "Interface Name " $alignsize " : ") $_.ProductName
   write-colored $fontcolor (Align "Interface Alias " $alignsize " : ") $_.NetConnectionID
   write-colored $fontcolor (Align "Interface Index " $alignsize " : ") $_.InterfaceIndex
   $ConnectionStatus=switch ($_.NetConnectionStatus) {
    0 {"Disconnected";"Red"}
    1 {"Connecting";"DarkYellow"}
    2 {"Connected";"Green"}
    3 {"Disconnecting";"DarkYellow"}
    4 {"Hardware not present";"Red"}
    5 {"Hardware disabled";"Red"}
    6 {"Hardware malfunction";"Red"}
    7 {"Media disconnected";"Red"}
    8 {"Authenticating";"DarkYellow"}
    9 {"Authentication succeeded";"Yellow"}
    10 {"Authentication failed";"Red"}
    11 {"Invalid address";"Red"}
    12 {"Credentials required";"Red"}
   }
   if ($ConnectionStatus) {
    $ConnectionStatusColor=$ConnectionStatus[1]
    write-colored $ConnectionStatusColor (Align "Interface Status " $alignsize " : ") $ConnectionStatus[0]
   } else {
   }

   write-colored $fontcolor (Align "Interface Last Reset " $alignsize " : ") $_.TimeOfLastReset
   if ( (Assert-IsCommandAvailable Get-NetAdapter -NoError) ) {
    $NetworkInfoHard=Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
    If (! $NetworkInfoHard) {Write-Blank ; Return}
    Write-Colored $fontcolor (Align "LinkSpeed " $alignsize " : ") $NetworkInfoHard."LinkSpeed" -NoNewLine
    if (! $NetworkInfoHard.FullDuplex) {
      if ($ConnectionStatus[0] -ne "Connected") {
        Write-Colored "Gray" -ColoredText " (Not connected)"
       } else {
       Write-Colored "Red" -ColoredText " (NOT FULL DUPLEX)"
       }
    }else {
     Write-Colored "Green" -ColoredText " (Full Duplex)"
    }
    write-colored $fontcolor (Align "Driver " $alignsize " : ")  -nonewline
    Write-Colored $fontcolor "Provider " $NetworkInfoHard.DriverProvider -nonewline
    Write-Colored $fontcolor " | Version " $NetworkInfoHard.DriverVersion -nonewline
    Write-Colored $fontcolor " | Date " $NetworkInfoHard.DriverDate
  }
  if ($ConnectionStatus[0] -ne "Connected") { Return }

  $NetworkConfig=Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object InterfaceIndex -eq $_.InterfaceIndex

  if ($NetworkConfig.IPAddress.count -eq 0) { Return }

  write-Blank
  $count=0 ; while ($count -lt $NetworkConfig.IPAddress.count) {
   if (([IpAddress]$NetworkConfig.IPAddress[$count]).AddressFamily -eq "InterNetworkV6") { $type="IPv6" } else { $type="IPv4" }
   write-colored $fontcolor (Align "IP Address($count) - $type" $alignsize " : ") (Align $NetworkConfig.IPAddress[$count] 40) -nonewline
   write-colored $fontcolor (Align "Mask($count)" 8 ": ") $NetworkConfig.IPSubnet[$count]
   $count++
  }

  if ($NetworkConfig.DefaultIPGateway) {
   write-blank
   write-colored $fontcolor (Align "Gateway - IPv4" $alignsize " : ") $NetworkConfig.DefaultIPGateway[0]
   if ($NetworkConfig.DefaultIPGateway.length -gt 1) {
    $count=1
    write-colored $fontcolor (Align "Gateway - IPv6" $alignsize " : ") $NetworkConfig.DefaultIPGateway[$count]
    $count++
   }
  }

  write-blank

  $count=0 ; $NetworkConfig.DNSServerSearchOrder | Where-Object { write-colored $fontcolor (Align "DNS Servers ($count)" $alignsize " : ") $_ ; $count++ }

  if ($NetworkConfig.WINSPrimaryServer) {write-blank; write-colored $fontcolor (Align "WINS Server (0)" $alignsize " : ") ($NetworkConfig.WINSPrimaryServer)}
  if ($NetworkConfig.WINSSecondaryServer) {write-colored $fontcolor (Align "WINS Server (1)" $alignsize " : ") ($NetworkConfig.WINSSecondaryServer)}

  write-Blank
  if (! $NetworkConfig.DHCPServer) { $DHCP_Server="N/A" } else { $DHCP_Server=$NetworkConfig.DHCPServer }
  write-colored $fontcolor (Align "DHCP Server" $alignsize " : ") $DHCP_Server -nonewline
  write-colored $fontcolor " (Enabled: " $NetworkConfig.DHCPEnabled -nonewline
  write-colored -NonColoredText ")`n"

  write-colored $fontcolor(Align "DNS Domain" $alignsize " : ") $NetworkConfig.DNSDomain

  $count=0 ; $NetworkConfig.DNSDomainSuffixSearchOrder | Where-Object { write-colored $fontcolor (Align "DNS Suffix Search Order ($count)" $alignsize " : ") $_ ; write-blank ; $count++ }

  # Format-PrintLineByLine $_.DNSDomainSuffixSearchOrder $fontcolor

  write-colored $fontcolor (Align "IP Metric " $alignsize " : ") $NetworkConfig.IPConnectionMetric

  write-blank

  if ( ! $NetworkConfig.FullDNSRegistrationEnabled) { $color="red" } else { $color="darkgreen" }
  write-colored $color (Align "DNS Auto Register" $alignsize " : ") $NetworkConfig.FullDNSRegistrationEnabled -NoNewLine
  if ( $NetworkConfig.DomainDNSRegistrationEnabled) { $color="red" } else { $color="darkgreen" }
  write-colored $color " (Uses Suffix : " $NetworkConfig.DomainDNSRegistrationEnabled -NoNewLine
  write-colored $color ")"

  if ($NetworkConfig.WINSEnableLMHostsLookup) { $color="red" } else { $color="darkgreen" }
  write-colored $color (Align "WINS Search for LMHosts" $alignsize " : ") $NetworkConfig.WINSEnableLMHostsLookup -nonewline
  if ($NetworkConfig.DNSEnabledForWINSResolution) { $color="red" } else { $color="darkgreen" }
  write-colored $color " (WINS DNS Resolution : " $NetworkConfig.DNSEnabledForWINSResolution -nonewline
  write-colored $color ")"

  if ($NetworkConfig.TcpipNetbiosOptions -ne 2) { $color="red" } else { $color="darkgreen" }
  $NetBiosValue = switch ($NetworkConfig.TcpipNetbiosOptions) {
   "0"  {"Enabled via DHCP"; break}
   "1"   {"Enabled"; break}
   "2"   {"Disabled"; break}
  }
  write-colored $color (Align "NETBIOS" $alignsize " : ") $NetBiosValue

 }
 } Catch {
  Write-Colored -Color "Red" -ColoredText $Error[0]
 }
}
Function Get-IP {
 Param (
  [Switch]$ShowDisconnected,
  [Switch]$ShowDriverInfo
 )
 $alignsize=30
 $fontcolor="Cyan"
 $ErrorActionPreference="Stop"

 $InterfaceList=[System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object Name -ne 'Loopback Pseudo-Interface 1' | ForEach-Object {
  if (($_.OperationalStatus -eq "Down") -and ! ($ShowDisconnected)) {Return}
  $IpProperties=$_.GetIPProperties()
  $IpStatistics=$_.GetIPStatistics()
  $IpMetricInfo=$(Try { Get-NetIPInterface -InterfaceAlias $_.Name -AddressFamily IPv4 } Catch {})
  New-Object PSObject -Property @{
   MAC=$_.GetPhysicalAddress()
   Name=$_.Name
   Index=$IpMetricInfo.ifIndex
   Metric=$IpMetricInfo.InterfaceMetric
   Description=$_.Description
   NetworkInterfaceType=$_.NetworkInterfaceType
   IP=$IpProperties.UnicastAddresses | Where-Object PrefixOrigin -ne WellKnown | Select-Object Address,IPv4Mask,PrefixLength,PrefixOrigin,SuffixOrigin
   InterfaceSpeed=$(if ($_.Speed -gt 0) {"$([Math]::round($_.Speed/1000/1000,1)) Mbps"})
   OperationalStatus=$_.OperationalStatus
   DNSSuffix=$IpProperties.DnsSuffix
   DNS=$IpProperties.DnsAddresses.IPAddressToString
   Gateway=$IpProperties.GatewayAddresses.Address.IPAddressToString
   DHCP=$IpProperties.DhcpServerAddresses.IPAddressToString
   WINS=$IpProperties.WinsServersAddresses.IPAddressToString
   Sent=Format-FileSize ($IpStatistics.BytesSent)
   Received=Format-FileSize ($IpStatistics.BytesReceived)
  }
 }

 $InterfaceList | Sort-Object OperationalStatus,Metric | ForEach-Object {
  Write-StarLine -character "-"
  if ($_.Mac.ToString().Trim() -ne "") {Write-Centered -Color 'Magenta' $_.Mac} else {Write-Centered -Color 'Magenta' $_.Name}
  Write-StarLine -character "-"
  write-colored $fontcolor (Align "Interface Name " $alignsize " : ") $_.Name
  write-colored $fontcolor (Align "Interface Description " $alignsize " : ") $_.Description
  write-colored $fontcolor (Align "Interface Type " $alignsize " : ") $_.NetworkInterfaceType
  write-colored $fontcolor (Align "Interface Metric " $alignsize " : ") $_.Metric
  write-colored $fontcolor (Align "Interface Index " $alignsize " : ") $_.Index
  if ($ShowDriverInfo) {
   Try {
    $AdapterInfo=Get-NetAdapter -InterfaceIndex $_.Index -ErrorAction Stop | Select-Object DriverProvider,DriverVersionString,NdisVersion,DriverDescription,DriverDate
    write-colored $fontcolor (Align "Driver Description " $alignsize " : ") $AdapterInfo.DriverDescription
    write-colored $fontcolor (Align "Driver Info " $alignsize " : ") $($AdapterInfo.DriverProvider,"[",$AdapterInfo.DriverVersionString,"]","(",$AdapterInfo.DriverDate,")")
    write-colored $fontcolor (Align "Driver Ndis Version " $alignsize " : ") $AdapterInfo.NdisVersion
   } Catch {}
  }
  if ($_.OperationalStatus -eq "Up") {$StatusColor = "Green"} elseif ($_.OperationalStatus -eq "Down") {$StatusColor = "Red"} else {$StatusColor = "DarkYellow"}
  write-colored $StatusColor (Align "Operational Status " $alignsize " : ") $_.OperationalStatus
  if ($_.InterfaceSpeed) { write-colored $fontcolor (Align "InterfaceSpeed " $alignsize " : ") $_.InterfaceSpeed }
  if ($_.DNSSuffix) {write-colored $fontcolor (Align "DNSSuffix " $alignsize " : ") $_.DNSSuffix}
  if ($_.IP) {
   If (Assert-IsCommandAvailable Get-NetConnectionProfile) {
    try {
     $ConnectionProfile=Get-NetConnectionProfile -InterfaceIndex $_.Index -ErrorAction Stop
     # Network Category
     if ($ConnectionProfile.NetworkCategory -eq 'Public') {$StatusColor = "Red"} else { $StatusColor="Green" }
     write-colored $StatusColor (Align "Network Category " $alignsize " : ") $ConnectionProfile.NetworkCategory
     # Internet Connectivity (IPv4)
     if ($ConnectionProfile.IPv4Connectivity -ne 'Internet') {$StatusColor = "Red"} else { $StatusColor="Green" }
     write-colored $StatusColor (Align "Internet Access (IPv4)" $alignsize " : ") $ConnectionProfile.IPv4Connectivity
     # Internet Connectivity (IPv6)
     if ($ConnectionProfile.IPv6Connectivity -ne 'Internet') {$StatusColor = "Red"} else { $StatusColor="Green" }
     write-colored $StatusColor (Align "Internet Access (IPv6)" $alignsize " : ") $ConnectionProfile.IPv6Connectivity
    } Catch {}
   }
   $count=0
   $countIPv6=0
   $_.IP | Sort-Object PrefixLength | ForEach-Object {
    if ($_.PrefixLength -le "32") {
     $IPType = "IPv4"
     if ($count -eq 0) {
      write-colored $fontcolor (Align "IP" $alignsize " : ") "$($_.Address) | $($_.IPv4Mask) ($($_.PrefixLength)) | Source : $($_.PrefixOrigin)"
     }
     else {
      write-colored $fontcolor (Align "IP ($count)" $alignsize " : ") "$($_.Address) | $($_.IPv4Mask) ($($_.PrefixLength)) | Source : $($_.PrefixOrigin)"
     }
     $count++
    }
    if (($_.PrefixLength -gt "32")) {
     $IPType = "IPv6"
     if ($countIPv6 -eq 0) {
      write-colored $fontcolor (Align "IPv6" $alignsize " : ") "$($_.Address) ($($_.PrefixLength)) | Source : $($_.PrefixOrigin)"
     }
     else {
      write-colored $fontcolor (Align "IPv6 ($countIPv6)" $alignsize " : ") "$($_.Address) ($($_.PrefixLength)) | Source : $($_.PrefixOrigin)"
     }
     $countIPv6++
    }
   }
  }
  if ($_.DNS) {
   write-colored $fontcolor -NonColoredText (Align "DNS" $alignsize " : ") -NoNewLine
   $count=0
   $_.DNS | ForEach-Object {
    if ($count -eq 0) {write-colored -Color $fontcolor -ColoredText $_ -NoNewLine} else {write-colored -Color $fontcolor -ColoredText " | $($_)" -NoNewLine}
    $count++
   }
   Write-Host
  }
  if ($_.WINS) {
   $count=0
   $_.DNS | ForEach-Object {
    $count++
    write-colored $fontcolor (Align "WINS ($count)" $alignsize " : ") $_
   }
  }
  if ($_.Gateway) {
   $_.Gateway | ForEach-Object {
    $IPTypeCheck = ([IPAddress]$_).AddressFamily
    $IPType = if ($IPTypeCheck -eq "InterNetworkV6") {"IPv6"} elseif ($IPTypeCheck -eq "InterNetwork") {"IPv4"}
    write-colored $fontcolor -NonColoredText (Align "Gateway $IPType" $alignsize " : ") -ColoredText $_
   }
  }
  if ($_.DHCP) {write-colored $fontcolor (Align "DHCP " $alignsize " : ") $_.DHCP}
  if ($_.Sent) {write-colored $fontcolor (Align "Sent | Received " $alignsize " : ") "$($_.Sent) | $($_.Received)"}
 }
}
Function Get-NetIP {
 Param (
  $Server,
  [Switch]$Verbose
 )
 #To test multiple server : $("","toto","server-01","server-02") | ForEach-Object {"[$($_)]" ; Get-NetIP $_ ; write-host}
 $ErrorActionPreference="Stop"
 Try {
  $CommandLine="(Invoke-WebRequest 'https://ifconfig.me/ip' -ErrorAction Stop -TimeoutSec 1 -UseBasicParsing).Content.Trim()"
  if ($server) {
   $PsRemoteResult=$(Try {Test-WSMAN $Server -ErrorAction Stop | Out-Null; $true} catch {$false})
   if ($PsRemoteResult) {
    Invoke-Command -ComputerName $Server -ArgumentList $CommandLine -ErrorAction Stop -ScriptBlock {
     #Curl is not available before version 3
     if ($PSVersionTable.PSVersion.Major -lt "3") { throw "Cannot Check (PS version < 3)" }
     #$Using: does not work well when remoting to PC
     Invoke-Expression $args[0] -ErrorAction Stop
    }
   } else {
    throw "$Server is not accessible"
   }
  } else {
   invoke-expression $CommandLine -ErrorAction Stop
  }
 } Catch {
  if ($Verbose) { write-Host -ForegroundColor "Red" "No Internet Connection ($($Error[0]))" }
 }
}
Function Get-Bandwidth {
 Param (
  $DurationInMinutes="0.5"
 )
 $startTime = get-date
 $endTime = $startTime.addMinutes($durationinminutes)
 $timeSpan = new-timespan $startTime $endTime

 $count = 0 ; $totalBandwidth = 0

 while ($timeSpan -gt 0) {
  # Get an object for the network interfaces, excluding any that are currently disabled.
  $colInterfaces = Get-CimInstance -class Win32_PerfFormattedData_Tcpip_NetworkInterface |Select-Object BytesTotalPersec, CurrentBandwidth,PacketsPersec|Where-Object {$_.PacketsPersec -gt 0}
   foreach ($interface in $colInterfaces) {
    Write-Colored $defaultblue "`rCurrent bandwith: " (Align ((Format-FileSize $interface.BytesTotalPersec)+"/s") 25) -nonewline
    $totalBandwidth = $totalBandwidth + $interface.BytesTotalPersec ; $count++
   }
   Start-Sleep -milliseconds 150
   # recalculate the remaining time
   $timeSpan = new-timespan $(Get-Date) $endTime
}

 $averageBandwidth = $totalBandwidth / $count
 # $value = "{0:N2}" -f $averageBandwidth
 $value = ((Format-FileSize $averageBandwidth)+"/s")
 Write-Colored $defaultblue "Average Bandwidth after $durationinminutes minutes: " $value

}
Function Get-DNSResponseTime {
 Param (
  $DNSServer=(Get-DnsClientServerAddress | Where-Object {($_.AddressFamily -eq "2") -and ($_.ServerAddresses)})[0].ServerAddresses[0],
  $DurationInMinutes="0.5",
  $SleepDurationInMs='150',
  $Request
 )

 $startTime = get-date
 $endTime = $startTime.addMinutes($durationinminutes)
 $timeSpan = new-timespan $startTime $endTime

 if (! $Request) { $Request=$DNSServer }

 $count = 0 ; $TotalResult = 0 ; $AverageResult = 0 ; $MinResult = 10000 ; $MaxResult = 0

 try {
  $DNSServerFQDN=(Resolve-DnsName $DNSServer -ErrorAction Stop -QuickTimeout).NameHost
 Write-Colored $defaultblue -ColoredText "Testing response time using DNS Server $DNSServer ($DNSServerFQDN) during $DurationInMinutes minutes (destination : $Request) (Pause time : $SleepDurationInMs`ms)"
 } catch {
  write-host -foregroundcolor "Red" $Error[0]
  Return
 }

 while ($timeSpan -gt 0) {
 try {
  $Result=(Measure-Command {Resolve-DnsName $Request -NoHostsFile -DnsOnly -Server $DNSServer -ErrorAction Stop -QuickTimeout}).TotalMilliseconds
 } catch {
  write-host -foregroundcolor "Red" $Error[0]
  Return
 }

 Progress "Current response time: " $Result
 $TotalResult=$TotalResult+$Result
 if ($Result -lt $MinResult) {$MinResult = $Result}
 if ($Result -gt $MaxResult) {$MaxResult = $Result}
 $count++
 Start-Sleep -milliseconds $SleepDurationInMs
 $timeSpan = new-timespan $(Get-Date) $endTime
 }
 ProgressClear
 write-Blank
 $AverageResult=$TotalResult / $count
 Write-Colored $defaultblue "Average response time after $durationinminutes minutes: " "$AverageResult ms" -NoNewLine
 Write-Colored $defaultblue " (Min : " $MinResult -NoNewLine
 Write-Colored $defaultblue " - Max : " $MaxResult -NoNewLine
 Write-Colored $defaultblue -NonColoredText ")"
}
Function Get-NetworkStatistics {
 # Based on https://gist.github.com/cainejunkazama/6244413#file-get-networkstatistics

 # Example : Get-NetworkStatistics -IISFilter | group ProcessCMD | Sort-Object Count -desc | Select-Object Count,Name | Format-Table -AutoSize *

  [OutputType('System.Management.Automation.PSObject')]
  [CmdletBinding(DefaultParameterSetName='name')]

  param(
   [Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName='port')]
   [System.String]$Port='*',

   [Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName='name')]
   [System.String]$ProcessName='*',

   [Parameter(Position=0,ValueFromPipeline=$true,ParameterSetName='address')]
   [System.String]$Address='*',

   [Parameter()]
   [ValidateSet('*','tcp','udp')]
   [System.String]$Protocol='*',

   [Parameter()]
   [ValidateSet('*','Closed','CloseWait','Closing','DeleteTcb','Established','FinWait1','FinWait2','LastAck','Listen','SynReceived','SynSent','TimeWait','Unknown')]
   [System.String]$State='*',

   [Parameter()]
   [switch]$IISFilter=$false
  )

  begin {
   $properties = 'Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','State','ProcessName','ProcessPath','ProcessCMD','PID'
  }

  process {
  # netstat -qano | Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object {
  netstat -ano | Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object {

  $item = $_.line.split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)

  if($item[1] -notmatch '^\[::') {
   if (($la -eq $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') { $localAddress = $la.IPAddressToString ; $localPort = $item[1].split('\]:')[-1]
   } else { $localAddress = $item[1].split(':')[0] ; $localPort = $item[1].split(':')[-1] }

   if (($ra -eq $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') { $remoteAddress = $ra.IPAddressToString ; $remotePort = $item[2].split('\]:')[-1]
   } else { $remoteAddress = $item[2].split(':')[0] ; $remotePort = $item[2].split(':')[-1] }

   $procId = $item[-1]
   $ProcInfo= (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue)
   $procName = $ProcInfo.Name
   $procPath = $ProcInfo.Path

   # Write-host -nonewline "`r                                                                            "
   # write-host -nonewline "`rChecking current process : $procId ($procName)"

   if ($IISFilter) {
    if ($procPath -eq 'C:\Windows\SysWOW64\inetsrv\w3wp.exe') {$procCMD=(Get-CimInstance Win32_Process -Filter "ProcessId='$procId'").commandline} else {$procCMD="Not IIS"}
   } else {
    $procCMD=(Get-CimInstance Win32_Process -Filter "ProcessId='$procId'").commandline
    if (! $procCMD) {$procCMD=$procName}
   }

   $proto = $item[0]
   $status = if($item[0] -eq 'tcp') {$item[3]} else {$null}


   $pso = New-Object -TypeName PSObject -Property @{
    PID = $procId
    ProcessName = $procName
    ProcessPath = $procPath
    ProcessCMD = $procCMD
    Protocol = $proto
    LocalAddress = $localAddress
    LocalPort = $localPort
    RemoteAddress =$remoteAddress
    RemotePort = $remotePort
    State = $status
   } | Select-Object -Property $properties

   if($PSCmdlet.ParameterSetName -eq 'port') { if($pso.RemotePort -like $Port -or $pso.LocalPort -like $Port) { if($pso.Protocol -like $Protocol -and $pso.State -like $State) { $pso } } }
   if($PSCmdlet.ParameterSetName -eq 'address') { if($pso.RemoteAddress -like $Address -or $pso.LocalAddress -like $Address) { if($pso.Protocol -like $Protocol -and $pso.State -like $State) { $pso } } }
   if($PSCmdlet.ParameterSetName -eq 'name') { if($pso.ProcessName -like $ProcessName) { if($pso.Protocol -like $Protocol -and $pso.State -like $State) { $pso } } }
   }
  }
  Write-host -nonewline "`r                                                                            "
 }


 <#

 .SYNOPSIS
  Displays the current TCP/IP connections.

 .DESCRIPTION
  Displays active TCP connections and includes the process ID (PID) and Name for each connection.
  If the port is not yet established, the port number is shown as an asterisk (*).

 .PARAMETER ProcessName
  Gets connections by the name of the process. The default value is '*'.

 .PARAMETER Port
  The port number of the local computer or remote computer. The default value is '*'.

 .PARAMETER Address
  Gets connections by the IP address of the connection, local or remote. Wildcard is supported. The default value is '*'.

 .PARAMETER Protocol
  The name of the protocol (TCP or UDP). The default value is '*' (all)

 .PARAMETER State
  Indicates the state of a TCP connection. The possible states are as follows:

  Closed  - The TCP connection is closed.
  CloseWait    - The local endpoint of the TCP connection is waiting for a connection termination request from the local user.
  Closing - The local endpoint of the TCP connection is waiting for an acknowledgement of the connection termination request sent previously.
  DeleteTcb    - The transmission control buffer (TCB) for the TCP connection is being deleted.
  Established   - The TCP handshake is complete. The connection has been established and data can be sent.
  FinWait1 - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint or for an acknowledgement of the connection termination request sent previously.
  FinWait2 - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint.
  LastAck - The local endpoint of the TCP connection is waiting for the final acknowledgement of the connection termination request sent previously.
  Listen  - The local endpoint of the TCP connection is listening for a connection request from any remote endpoint.
  SynReceived   - The local endpoint of the TCP connection has sent and received a connection request and is waiting for an acknowledgment.
  SynSent - The local endpoint of the TCP connection has sent the remote endpoint a segment header with the synchronize (SYN) control bit set and is waiting for a matching connection request.
  TimeWait - The local endpoint of the TCP connection is waiting for enough time to pass to ensure that the remote endpoint received the acknowledgement of its connection termination request.
  Unknown - The TCP connection state is unknown.

  Values are based on the TcpState Enumeration:
  http://msdn.microsoft.com/en-us/library/system.net.networkinformation.tcpstate%28VS.85%29.aspx

 .EXAMPLE
  Get-NetworkStatistics

 .EXAMPLE
  Get-NetworkStatistics iexplore

 .EXAMPLE
  Get-NetworkStatistics -ProcessName md* -Protocol tcp

 .EXAMPLE
  Get-NetworkStatistics -Address 192* -State LISTENING

 .EXAMPLE
  Get-NetworkStatistics -State LISTENING -Protocol tcp

 .OUTPUTS
  System.Management.Automation.PSObject

 .NOTES
  Author: Shay Levy
  Blog : http://PowerShay.com
 #>
 }
Function Get-NetStat {
 Param (
   $PathFilter="*"
  )
  Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,
   @{name="ProcessInfo";expression={Get-Process -PID $_.OwningProcess | `
    Select-Object ID,ProcessName,Path}} | `
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,
     @{name="PID";expression={$_.ProcessInfo.ID}},
     @{name="ProcessName";expression={$_.ProcessInfo.ProcessName}},
     @{name="ProcessPath";expression={$_.ProcessInfo.Path}} | Where-Object {$_.ProcessPath -like $PathFilter}
}
Function Get-EstablishedConnections {
 Param (
  $PathFilter="*"
 )
 Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,
 @{name="ProcessInfo";expression={Get-Process -PID $_.OwningProcess | `
 Select-Object ID,ProcessName,Path}} | `
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,
   @{name="PID";expression={$_.ProcessInfo.ID}},
   @{name="ProcessName";expression={$_.ProcessInfo.ProcessName}},
   @{name="ProcessPath";expression={$_.ProcessInfo.Path}} | Where-Object {$_.ProcessPath -like $PathFilter}
}
Function Get-PortInfo {
 Param (
  $Port
 )
 if (! $Port) {Write-Host -ForegroundColor Red "Port is required" ; return}
 Try {
  Get-Process -Id (Get-NetTCPConnection -LocalPort $Port -ErrorAction Stop).OwningProcess | Select-Object Name,ID,Path,CommandLine,SessionId,StartTime
 } Catch {
  Write-Host -ForegroundColor Green "Port not in use" ; return
 }
}
Function Open-Port {
 Param (
  $Port = 80,
  $IPSource = 'any'
 )
 #Found hre https://gallery.technet.microsoft.com/scriptcenter/Listen-Port-Powershell-8deb99e4
 $endpoint = new-object System.Net.IPEndPoint ([system.net.ipaddress]::$IPSource, $port)
 $listener = new-object System.Net.Sockets.TcpListener $endpoint
 $listener.server.ReceiveTimeout = 3000
 $listener.start()
 try {
  Write-Host "Listening on port $port, press CTRL+C to cancel"
  While ($true){
   if (!$listener.Pending()) {
    Start-Sleep -Seconds 1;
    continue;
   }
   $client = $listener.AcceptTcpClient()
   $client.client.RemoteEndPoint | Add-Member -NotePropertyName DateTime -NotePropertyValue (get-date) -PassThru
   $client.close()
   }
  }
 catch {
  Write-Error $_
 }
 finally{
  $listener.stop()
  Write-host "Listener Closed Safely"
 }
}

# Registry check
Function Get-RegAllUserProfiles {
 Param (
  $ServerToTest=$env:computername
 )
 try {
  $UserAndSid=invoke-command -ErrorAction Stop -ComputerName $ServerToTest -ScriptBlock {
   $ProfileListPath='hklm:software/microsoft/windows nt/currentversion/profilelist'
   Get-ItemProperty $ProfileListPath\* | Select-Object PSChildName,ProfileImagePath,@{Name="UserADName";Expression={$SID=$_.PSChildName;([wmi]"Win32_SID.SID='$SID'").AccountName}}
  }
 } catch {write-host -foregroundcolor "Red" $Error[0] ; return}
 return $UserAndSid
}
Function Get-RegAllUserRegKey {
 Param (
  $RegKey,
  $ServerToTest=$env:computername
 )
 if (!$RegKey) {write-host -foregroundcolor "Red" "Regkey is mandatory" ; return}
 # $RegKey must start after the HKU/ID/*, for example : 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'

 try {
  if ($ServerToTest) {
   $UserAndSid=Get-RegAllUserProfiles $ServerToTest
   $AllUserResult=invoke-command -ErrorAction Stop -ArgumentList $RegKey -ComputerName $ServerToTest -ScriptBlock {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    $RegKey=$args[0]
    Get-ItemProperty -Path "HKU:\*\$RegKey"
   }
  } else {
   $UserAndSid=Get-RegAllUserProfiles
   New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
   $AllUserResult=Get-ItemProperty -Path "HKU:\*\$RegKey"
  }
 } catch {
  write-host -foregroundcolor "Red" $Error[0] ; return
 }

 $AllUserResult=$AllUserResult | Select-Object -property *,
  @{Name="RegPath";Expression={$_.PSPath -replace ("Microsoft.PowerShell.Core\\Registry::HKEY_USERS","HKU:")}},
  @{Name="UserSID";Expression={[regex]::matches($_.PSParentPath,'(?<=HKEY_USERS\\).+?(?=\\Software)').value}} -ExcludeProperty PSPath,
  PSParentPath,PSChildName,PSDrive,PSProvider,PSComputerName,RunspaceId | Select-Object *,
   @{Name="UserName";Expression={$SID=$_.UserSID;($UserAndSid | Where-Object {$_.PSChildName -eq $SID}).UserADName}}

 Return $AllUserResult
}
Function Set-RegAllUserRegKey {
 Param (
  [Parameter(Mandatory=$true)]$RegKey,
  $RegName,
  $RegValue,
  $ServerToTest
 )

 # $RegKey must start after the HKU/ID/*, for example : 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'

 try {
  if ($ServerToTest) {
   $AllUserResult=invoke-command -ErrorAction Stop -ArgumentList $RegKey,$RegName,$RegValue -ComputerName $ServerToTest -ScriptBlock {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    $RegKey=$args[0];$RegName=$args[1];$RegValue=$args[2]
    Set-ItemProperty -Path "HKU:\*\$RegKey" -Name $RegName -Value $RegValue
   }
  } else {
   $AllUserResult=invoke-command -ErrorAction Stop -ArgumentList $RegKey,$RegName,$RegValue -ScriptBlock {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    $RegKey=$args[0];$RegName=$args[1];$RegValue=$args[2]
    Set-ItemProperty -Path "HKU:\*\$RegKey" -Name $RegName -Value $RegValue
   }
  }
 } catch {write-host -foregroundcolor "Red" $Error[0] ; return}

 Return $AllUserResult
}
Function Get-AllUserStartup {
 Param (
  $ServerToTest=$env:computername
 )
 Get-RegAllUserRegKey -RegKey 'Software\Microsoft\Windows\CurrentVersion\Run' -ServerToTest $ServerToTest
}
Function Get-AllUsersProxy {
 Param (
  $ServerToTest=$env:computername
 )
 Get-RegAllUserRegKey -RegKey 'Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ServerToTest $ServerToTest |`
  Select-Object @{Name="UserName";Expression={if ($_.UserName) {$_.UserName} else {$_.UserSID}}},* -ExcludeProperty `
   ZonesSecurityUpgrade,IE5_UA_Backup_Flag,RegPath,UserName,UserSID,LockDatabase,WarnonZoneCrossing,NoNetAutodial,EnableAutodial,MigrateProxy,CertificateRevocation,DisableCachingOfSSLPages,PrivacyAdvanced,SecureProtocols
}
Function Set-RegKey {
 Param (
  [Parameter(Mandatory=$true)]$RegKey,
  [Parameter(Mandatory=$true)]$Name,
  [Parameter(Mandatory=$true)]$Value,
  [Parameter(Mandatory=$true)]$Type
 )
 Set-ItemProperty -path $RegKey -Name $Name -value $Value -Type $Type
}

# Services, Tasks, GPO
Function Get-ServicesSpecific {
 Param (
  $servername=$env:COMPUTERNAME
 )
 try {
  if ($servername -eq $env:COMPUTERNAME) {
   $result=Get-CimInstance Win32_Service -ErrorAction Stop
  } else {
   $result=Get-CimInstance Win32_Service -ErrorAction Stop -ComputerName $servername
  }
   $result=$result | Where-Object {
   (($_.startmode -eq 'Auto') -or ($_.state -eq 'Running')) -and
   $_.PathName -notlike '*C:\WINDOWS\System32\*' -and
   $_.PathName -notlike '*C:\WINDOWS\SysWow64\*' -and
   $_.PathName -notlike '*C:\WINDOWS\servicing\*' -and
   $_.PathName -notlike '*C:\WINDOWS\Microsoft.Net\*' }
 } catch {write-colored "red" -coloredtext $error[0] ; return}
 if (! ($result)) {
  Write-Colored "darkgreen" -coloredtext "No service found"
 } else {
  $result | ForEach-Object { Format-TypeServices $._ $servername -formattable }
 }
}
Function Get-ServicesFiltered {
 Param (
  [Switch]$Start,
  [Switch]$Stop,
  $Services=@('Null')
 )

 #For VmWare : $Services=@('Vmware')
 #For SQL : $Services=@('MSSQL','SQLAgent')

 $ServicesList=Get-CimInstance Win32_Service
 $Result=$Services | ForEach-Object {
  $ServiceName=$_
  $ServicesList | Where-Object {$_.DisplayName -like "*$ServiceName*"}
 }

 if ( ! $result) {Write-colored "Red" -ColoredText "$Services Services Not Found" ; return}

 #Print Service List
 if ((! $Start) -and (! $Stop)) {
  $result | ForEach-Object {Format-TypeServices $._}
 }

 if ($Stop) {
  if ( ! (Assert-IsAdmin) ) {Write-Colored "red" -ColoredText "You must be admin to run this command" ; return}
  $result | ForEach-Object {Write-Colored $defaultblue "Stopping : " $_.displayname ; Stop-Service -force $_.name }
 }
 if ($Start) {
  if ( ! (Assert-IsAdmin) ) { Write-Colored "red" -ColoredText "You must be admin to run this command" ; return }
  $result | ForEach-Object { Write-Colored $defaultblue "Starting : " $_.displayname ; Start-Service $_.name }
 }

}
Function Get-PlannedTasks {
 Get-ScheduledTask | Where-Object state -NE 'Disabled' | Get-ScheduledTaskInfo | Where-Object NextRunTime | Sort-Object NextRunTime
}
Function Get-TasksSpecific {
 Param (
  $Server=$($env:computername),
  [switch]$csv
 )
 # Starting with windows 8.1 / Windows 2012 R2 we can use : Get-ScheduledTask
 # To remove tasks : Unregister-ScheduledTask

 # PROBLEM : Does not find tasks in subfolders

 if ($PSVERSIONTABLE.PSVersion.major -lt 3 ) {write-host -foregroundcolor "red" "$($env:computername) : Function does not work with powershell lower than 3" ; return}
 if ( $PsUICulture -ne "en-US" ) { write-host -foregroundcolor "red"  "$($env:computername) : This function does not work on non english based OS" ; return }

 $TaskQueryResult=schtasks /s $Server /query /v /fo csv | ConvertFrom-Csv | Where-Object {
       $_."Author" -notmatch "Microsoft Corporation|Microsoft|N/A" `
  -and $_."Author" -notlike "$`(@%SystemRoot%\*" `
  -and $_."HostName" -notmatch "HostName" `
  -and $_."Scheduled Task State" -notmatch "Disabled" `
  -and $_."Task To Run" -notmatch "COM handler" `
  -and $_."Schedule Type" -notmatch "On demand only" `
  } | select-object "Run As User","Author","TaskName","Last Run Time","Scheduled Task State","Task To Run","Comment","Last Result"

 if ( ! $TaskQueryResult ) {Write-colored "darkgreen" "" "No tasks using specific account and no non Microsoft tasks found" ; return}

 if ($csv) {
  $TaskQueryResult | ForEach-Object {
   $taskname=$_.TaskName
   $author=$_."Author"
   $runasuser=$_.'Run As User'
   $lastruntime=$_.'Last Run Time'
   $tasktorun=$_.'Task To Run'
   $comment=$_.Comment
   $lastresult=$_."Last Result"
   write-output "$server,$taskname,$author,$runasuser,$lastruntime,$lastresult,$tasktorun,$comment"
  }
 } else {
  $TaskQueryResult | ForEach-Object {
   Write-colored "Magenta" "" ($_.TaskName,"(Run as :",$_."Run As User",")")
   Write-Colored $defaultblue "Status : " $_."Scheduled Task State" -nonewline
   Write-Colored $defaultblue " - Last Run : " $_."Last Run Time"
   Write-Colored $defaultblue "CommandLine : " $_."Task To Run"
   write-blank
  }
 }
}
Function Get-TasksLogs {
  Param (
   $StartTime=(Get-Date).addDays(-1),
   $EndTime=$(Get-Date),
   [Switch]$NoFilter,
   [Switch]$ExportLog,
   $LogPath="C:\Temp\TasksLogsExport_$(get-date -uformat '%Y-%m-%d').csv"
  )

  #Event To ID:
  #100 	Task Started
  #101 	Task Start Failed
  #102 	Task completed
  #103 	Action start failed
  #106 	Task registered
  #107 	Task triggered on scheduler
  #108 	Task triggered on event
  #110 	Task triggered by user
  #111 	Task terminated
  #118 	Task triggered by computer startup
  #119 	Task triggered on logon
  #129 	Created Task Process
  #135 	Launch condition not met, machine not idle
  #140 	Task registration updated
  #141 	Task registration deleted
  #142 	Task disabled
  #200 	Action started
  #201 	Action completed
  #202 	Action Failed
  #203 	Action failed to start
  #301 	Task engine properly shut down
  #310 	Task Engine started
  #311 	Task Engine failed to start
  #314 	Task Engine idle
  #317 	Task Engine started
  #318 	Task engine properly shut down
  #319 	Task Engine received message to start task
  #322 	Launch request ignored, instance already running
  #329 	Task stopping due to timeout reached
  #332 	Launch condition not met, user not logged-on
  #400 	Service started
  #402  Service is shutting down
  #411 	Service signaled time change
  #700 	Compatibility module started

  # Get-ScheduledTasksLogs -StartTime $(Get-Date "2020-04-04 22:00") -EndTime $(Get-Date "2020-04-05 21:30") -ExportLog

  # Print properties once for each type detected
  # $AllEvents | Group-Object TaskDisplayName | ForEach-Object { ($AllEvents | Where-Object TaskDisplayName -eq $_.Name)[0] } | ForEach-Object { $count=0 ; $_.TaskDisplayName ; $_.Message ; $_.Properties | ForEach-Object { write-host "$count : $($_.Value)" ; $count++ } ; Write-StarLine }

  $ErrorActionPreference='Stop'

  if ( ! (Assert-IsAdmin) ) {Write-Colored "red" -ColoredText "You must be admin to run this command" ; return}

  try {
  write-host -ForegroundColor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Checking Scheduled Tasks between $StartTime and $EndTime"
  if ($NoFilter) {
   $AllEvents=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';StartTime=$StartTime;EndTime=$EndTime} | `
   Where-Object {($_.Task -ne '314')}
  } else {
   $AllEvents=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';StartTime=$StartTime;EndTime=$EndTime;ID=100,101,102,111,329}
  }

 } catch {
  write-colored "red" -ColoredText $error[0] ; return
 }

  write-host -ForegroundColor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Filtering results"
  $FilteredEvents=$AllEvents | Select-Object TimeCreated,RecordId,TaskDisplayName,Task,MachineName,UserId,`
   @{Label='TaskPath';Expression={
     $ActionListIgnored=@('402','311','301','318','310','317')
     $ActionListProperties1=@('319')
     if ( $ActionListProperties1 -Contains($_.Task) ) {$_.Properties[1].value}
     elseif ( $ActionListIgnored -Contains($_.Task) ) {"N/A"}
     else { $_.Properties[0].value }
    }},
   @{Label='UserName';Expression={
     $ActionListProperties0=@('301','310','317','318','319')
     $ActionListProperties1=@('100','101','102','119','140','332')
     $ActionListProperties2=@('103','110')
     if ($ActionListProperties0 -Contains($_.Task)) {$_.Properties[0].value}
     elseif ($ActionListProperties1 -Contains($_.Task)) {$_.Properties[1].value}
     elseif ($ActionListProperties2 -Contains($_.Task)) {$_.Properties[2].value}
     else {'N/A'}
    }},
   @{Label='TaskAction';Expression={
     $ActionListProperties1=@('129','200')
     $ActionListProperties2=@('201','202','203')
     if ($ActionListProperties1 -Contains($_.Task)) {$_.Properties[1].value}
     elseif ($ActionListProperties2 -Contains($_.Task)) {$_.Properties[2].value}
     else {'N/A'}
    }},message

  if ($ExportLog) {
   write-host -ForegroundColor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Exporting results to : $LogPath"
   #CreateFolder If it does not exist
   $LogFolder=Split-Path -Path $LogPath -Parent
   New-Item -Type Directory -Path $LogFolder -Force
   $FilteredEvents | Export-csv $LogPath -Delimiter ";" -NoTypeInformation
  }

  write-host -ForegroundColor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Finished"
  return $FilteredEvents
 }
Function Get-GPOALL {
 Param (
  $ServerToCheck=$env:COMPUTERNAME,
  $UserToCheck,
  $TempPath="$env:temp\tmp_gporeport.xml"
 )
 # New cmdlet
 # if(!$(Get-Module -List grouppolicy)) {write-host -foregroundcolor "Red" "Module GroupPolicy Unavailable" ; return} else {import-module grouppolicy}
 # Get-GPResultantSetOfPolicy -ReportType xml -path $tempPath -Computer $ServerToCheck -user $UserToCheck -ErrorAction Stop | out-Null

 # If admin check user and computer otherwise check only user
 try {
  if ( Assert-IsAdmin ) {
   if (! $UserToCheck) {
    gpresult /x $tempPath /s $ServerToCheck /SCOPE Computer /f
   } else {
    gpresult /x $tempPath /s $ServerToCheck /USER $UserToCheck /f
   }
  } else {
   if (! $UserToCheck ) {$UserToCheck = $env:USERNAME}
   gpresult /x $tempPath /s $ServerToCheck /scope User /USER $UserToCheck /f
  }
 } catch {write-colored "red" -ColoredText $error[0] ; return}

 #Convert XML  to PS Object
 [xml]$xml = try {
  get-content $tempPath -ErrorAction Stop
 } catch {
  write-colored "red" -ColoredText $error[0] ; return
 }

 #Computer
 $ComputerResult=$xml.DocumentElement.ComputerResults.GPO | Where-Object {
  # ($_.IsValid -eq $true) -and ($_.Enabled -eq $true) -and ($_.FilterAllowed -eq $true) -and ($_.AccessDenied -eq $False)
  ($_.IsValid -eq $true) -and ($_.Enabled -eq $true)
 } | Select-Object @{LABEL="Computer";EXPRESSION={$ServerToCheck}},
            @{LABEL="User";EXPRESSION={"N/A"}},
            @{LABEL="Type";EXPRESSION={"Computer"}},
            @{LABEL="LinkOrder";EXPRESSION={$_.link.linkorder}},
            @{LABEL="Denied";EXPRESSION={$_.AccessDenied}},
            Name,
            @{LABEL="LinkLocation";EXPRESSION={$_.link.SOMPath}},SecurityFilter | Sort-Object { [int]$_.linkorder }

 #User
 $UserResult=$xml.DocumentElement.UserResults.GPO | Where-Object {
  # ($_.IsValid -eq $true) -and ($_.Enabled -eq $true) -and ($_.FilterAllowed -eq $true) -and ($_.AccessDenied -eq $False)
  ($_.IsValid -eq $true) -and ($_.Enabled -eq $true)
 } | Select-Object @{LABEL="Computer";EXPRESSION={$ServerToCheck}},
            @{LABEL="User";EXPRESSION={$UserToCheck}},
            @{LABEL="Type";EXPRESSION={"User"}},
            @{LABEL="LinkOrder";EXPRESSION={$_.link.linkorder}},
            @{LABEL="Denied";EXPRESSION={$_.AccessDenied}},
            Name,
            @{LABEL="LinkLocation";EXPRESSION={$_.link.SOMPath}},SecurityFilter | Sort-Object { [int]$_.linkorder }

 $AllEnabled=$ComputerResult+$UserResult | Where-Object Denied -eq false
 $AllDisabled=$ComputerResult+$UserResult | Where-Object Denied -eq True
 return $($AllEnabled+$AllDisabled)
}

# SQL
Function Get-SQLInfo {
 Param (
  $TITLE,
  $SQLREQUEST
 )
 if (!$SQLREQUEST) {Write-Colored "red" -ColoredText "Provide SQL request";return}
 if ( ! (Assert-IsCommandAvailable sqlcmd) ) {return}
 write-starline "-"
 write-centered $TITLE
 write-starline "-"
 write-colored "DarkGreen" -ColoredText $SQLREQUEST
 write-blank
 ($SQLRESPONSE = sqlcmd -W -Q $SQLREQUEST) | Select-Object -index (2..$($SQLRESPONSE.count -3))
 write-blank
}
Function Remove-SQLUser {
 Param (
  $USER
 )
 if ( ! (Assert-IsCommandAvailable sqlcmd) ) {return}
 $SQLREQUEST="DROP LOGIN [$USER]"
 write-colored "DarkGreen" "" $SQLREQUEST
 sqlcmd -W -Q $SQLREQUEST
}
Function Enable-KerberosAccess {
 Param (
  [Parameter(Mandatory=$true)][String]$UserName,
  [Parameter(Mandatory=$true)][String]$ServerName,
  [String]$Domain=$env:USERDNSDOMAIN
 )
 $ErrorActionPreference='Stop'
 Try {
  #Generate FQDN with standard format
  $ServerFQDN=$ServerName.ToUpper()+"."+$Domain.ToLower()

  #Add Service Principal Name (SPN) to Server
  Set-ADComputer -Identity $ServerName -ServicePrincipalNames @{Add="MSSQLSvc/$ServerFQDN"}

  #Enable Trusted Delegation on User
  # Set-ADAccountControl -Identity $UserName -TrustedForDelegation $True

  #Add delegation to user for specific service
  Set-ADUser -Identity $UserName -Add @{'msDS-AllowedToDelegateTo'=@("MSSQLSvc/$ServerFQDN")}
 } Catch {
  write-Host -ForeGroundColor "Red" $error[0]
 }
}
Function Get-SQLOpenedConnections {
 Param (
  $ServerName
 )
 if ( !(Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
  Write-Host -ForegroundColor "red" "sqlcmd is not in the path)"
  Return
 }
 Try {
  Invoke-Command -ComputerName $ServerName -ErrorAction Stop -ScriptBlock {(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances} | ForEach-Object {
   $Instance = $_
   $SQLCMDEXTRACT = sqlcmd -S $ServerName\$_ -W  -Q "SELECT connect_time,session_id,local_net_address,local_tcp_port,client_net_address,client_tcp_port,auth_scheme,protocol_type,net_transport FROM sys.dm_exec_connections where protocol_type <> 'Database Mirroring' and client_net_address <> '<local machine>' Order by connect_time ;" -s ";"
   $SQLCMDEXTRACT[0..($SQLCMDEXTRACT.count -3)] | ConvertFrom-Csv -Delimiter ";" | Where-Object session_id -notlike "*--*" | Select-Object `
    @{name="Server";expression={$ServerName}},@{name="Instance";expression={$Instance}},
    @{name="DateTime";expression={$_.connect_time}},@{name="SessionID";expression={$_.session_id}},
    @{name="LocalIP";expression={$_.local_net_address}},@{name="LocalPort";expression={$_.local_tcp_port}},
    @{name="RemoteIP";expression={$_.client_net_address}},@{name="RemotePort";expression={$_.client_tcp_port}},
    @{name="Authentication";expression={$_.auth_scheme}},@{name="Transport";expression={$_.net_transport}}
  }
 } Catch {
  write-Host -ForegroundColor "Red" $error[0]
 }
}

# File Info
Function Get-FileInfoFull {
 Param (
  [Parameter(Mandatory=$true)]$path
 )
 if ( ! (test-path $path)) { write-Colored "Red" "" "Unavailable path : $path" ; return }
 Get-ItemProperty -Path $path | Format-list -Property *
}
Function Get-FileInfo {
 Param (
  [Parameter(Mandatory=$true)]$path
 )
 if (!$path) { write-Colored "Red" "" "Please provide a path" ; return }
 if ( ! (test-path $path)) { write-Colored "Red" "" "Unavailable path : $path" ; return }
 (Get-ItemProperty -Path $path).versioninfo
}

# SWAP Management
Function Get-SWAP {
 if ( ! (Assert-MinPSVersion 3 -CurrentFunction $($MyInvocation.MyCommand)) ) {return}
 #Works only with one swapfile defined
 $PageFileInfo=Get-CimInstance -ClassName Win32_PageFileSetting

 if (! $PageFileInfo) {
  Return "PageFile set as Auto"
 }

 $PageFileInfo | foreach-object {
  $PageFileName=$_.Name
  if (! $PageFileName) {$PageFileName="Automatic Configuration"}
  $PageFileInitSize=$_.InitialSize
  if (! $PageFileInitSize) {$PageFileInitSize="Auto"}
  $PageFileMaxSize=$_.MaximumSize
  if ( ! $PageFileMaxSize) {$PageFileMaxSize="Auto"}
  Return "$PageFileName ($PageFileInitSize/$PageFileMaxSize)"
 }

}
Function Set-SWAP {
 Param (
  [int]$MinSize,
  [int]$MaxSize,
  [switch]$Auto
 )
 if ( ! (Assert-MinPSVersion 3 -CurrentFunction $($MyInvocation.MyCommand)) ) {return}
 if ( ! (Assert-IsAdmin) ) {Write-Colored "red" -ColoredText "You must be admin to run this command" ; return}

 if ($Auto) {
  $AutomaticValue=$True
  $MessageValue="Automatic Configuration"
 } else {
  $AutomaticValue=$False
  $MessageValue="Manual Configuration"
 }
 Write-host -ForegroundColor $defaultblue $MessageValue

 #Set Automatic Value
 if (Get-Command Get-CimInstance) {
  $computersys = Get-CimInstance Win32_ComputerSystem
  $computersys.AutomaticManagedPagefile = $AutomaticValue
  Set-CimInstance -CimInstance $computersys
 } else {
  $computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
  $computersys.AutomaticManagedPagefile = $AutomaticValue
  $computersys.Put() | out-null
 }

 if ( ! $Auto ) {
  if (Get-Command Get-CimInstance) {
   $physicalmemMB = [int]((Get-CimInstance -Class Win32_ComputerSystem).TotalPhysicalMemory/1mb)
   $pagefile = Get-CimInstance -Query "Select * From Win32_PageFileSetting"
  } else {
   $physicalmemMB = [int]((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1mb)
   $pagefile = Get-WmiObject -Query "Select * From Win32_PageFileSetting"
  }
  if (! $MinSize ) { $MinSize=$physicalmemMB }
  if (! $MaxSize ) { $MaxSize=$physicalmemMB }

  #Common Configuration
  $pagefile.InitialSize = $MinSize
  $pagefile.MaximumSize = $MaxSize

  if (Get-Command Get-CimInstance) {
   Set-CimInstance -CimInstance $pagefile
  } else {
   $pagefile.Put() | out-null
  }
 }

 #Print Configuration
 Get-SWAP
}

# AD Management
Function Get-ADOUFromServer {
 Param (
  $ServerName=$env:COMPUTERNAME
 )
 $DistinguishedName=(get-adcomputer $Servername -properties DistinguishedName).DistinguishedName.split(",")
 ($DistinguishedName[1..($DistinguishedName.Length -1)] -join ",")
}
Function Get-ADOUFromUser {
 Param (
  $User=$env:USERNAME
 )
 $DistinguishedName=(get-aduser $User -properties DistinguishedName).DistinguishedName.split(",")
 ($DistinguishedName[1..($DistinguishedName.Length -1)] -join ",")
}
Function Get-ADGroupContent {
 Param (
  [Parameter(Mandatory=$true)]$ADGroup
 )
 write-centered "$ADGroup Members"
 (Get-ADGroupMember $ADGroup) | ForEach-Object {
  $Name=(Align $_.SamAccountName 10)
  write-colored -NonColoredText ($Name,"(",$_.Name,")")
 }
 Write-Blank
 write-centered "$ADGroup Member of"
 #Add check if empty
 $GroupMemberOf=(Get-ADGroup $ADGroup -Properties *).memberof
 if ( $GroupMemberOf) {($GroupMemberOf.split(',') | select-string "CN=").line.substring(3) | Sort-Object } else {write-colored -Color "Green" -Color "**This group is not member of any group**" ""}
}
Function Get-ADMembersWithMails {
 Param (
  $OU=(Get-ADDomain).DistinguishedName,
  $Filter="*"
 )
 Get-adgroup -SearchBase $OU -Filter {Name -like $Filter} | ForEach-Object {
  try { (Get-ADGroupMember -ErrorAction Stop $_.Name) | ForEach-Object {
   $mail=(get-aduser $_.SamAccountName -properties mail).mail
   $allmails=$allmails+$mail+";" }
   write-host -nonewline "$mail;"
  } catch {}
 }
 clear-host
 $allmails
 # Get-ADMembersWithMails | Out-File "C:\Temp\ADUsersMails.csv"
}
Function Get-ADUserMemberOf {
 Param (
  $ADUser=$env:USERNAME
 )
 if ( ! (Test-Account $ADUser)) {
  Write-host -foregroundcolor "Red" "Account $ADUser does not exist"
 } else {
  $Groups=(Get-ADUser $ADUser -properties memberof).memberof | Sort-Object
  $Groups | ForEach-Object {
   if ( ! (Test-Group $_)) {
    Write-host -foregroundcolor "Red" "Group $_ does not exist"
   } else {
    $Group=(Get-ADGroup -properties CanonicalName $_)
    [pscustomobject]@{
     Name=$Group.SamAccountName;
     DisplayName=$Group.Name;
     GroupCategory=$Group.GroupCategory;
     GroupScope=$Group.GroupScope;
     OU=$Group.CanonicalName | ForEach-Object {(($_ -split('/'))| Select-Object -skiplast 1) -join '/'}
    }
   }
  }
 }
}
Function Get-ADServerMemberOf {
 Param (
  $ServerName=$($env:computername)
 )
 if ( ! (Assert-IsCommandAvailable "Get-ADComputer") ) { return }
 try { $GROUPLIST=(Get-ADComputer $ServerName -Properties memberof).memberof }
 catch {Write-Colored "red" "" "Server $ServerName does not exist" ; return}
 if ( $GROUPLIST ) { ($GROUPLIST.split(',') | select-string "CN=").line.substring(3) | Sort-Object } else { Write-Colored "red" "" "Server $ServerName is not in any group" }
}
Function Get-ADSubnetsOld {
 Param (
  [Parameter(Mandatory=$true)]$AD_site_name
 )
 if ( ! (Assert-IsCommandAvailable "Get-ADRootDSE") ) {return}
 $configNCDN = (Get-ADRootDSE).ConfigurationNamingContext
 $siteContainerDN = ("CN=Sites," + $configNCDN)
 $siteDN = "CN=" + $AD_site_name + "," + $siteContainerDN
 $siteObj = try {Get-ADObject -Identity $siteDN -properties "siteObjectBL", "description", "location"} catch {write-colored "red" "" $error[0]}
 $(foreach ($subnetDN in $siteObj.siteObjectBL) { (Get-ADObject -Identity $subnetDN -properties "siteObject", "description", "location").Name }) | Sort-Object
}
Function Get-ADSubnets {
 Get-ADReplicationSubnet -Filter * | Select-Object @{name="SiteShortName";expression={(($_.Site -split ",")[0] -Split "CN=")[1]}},Name | Sort-Object SiteShortName
}
Function Get-ADUserLastLogon {
 Param (
  [string]$user=$env:USERNAME
 )
 $DomainControllers=Get-ADDomainController -Filter {Name -like "*"}
 $lastlogonInit=0
 $lastLogonTimestampInit=0
 foreach($DomainController in $DomainControllers){
  $ServerName=$DomainController.HostName
  $userinfo=(Get-ADUser $user -properties *)
  $lastlogon=$userinfo.lastLogon
  $lastLogonTimestamp=$userinfo.lastLogonTimestamp
  if($lastlogon -gt $lastlogonInit){ $lastlogondc=$ServerName ; $lastlogonInit=$lastlogon }
  if($lastLogonTimestamp -gt $lastLogonTimestampInit){ $lastLogonTimestamdc=$ServerName ; $lastLogonTimestampInit=$lastLogonTimestamp }
 }
 $ll = [DateTime]::FromFileTime($lastlogonInit)
 $llts = [DateTime]::FromFileTime($lastLogonTimestampInit)
 if ( ! $lastlogondc -and ! $lastLogonTimestamdc ) { Write-Host "$user : No trace of any logon"} else { Write-Host "$user : Last Logon $ll on $lastlogondc | Last Logon time stamp : $llts on $lastLogonTimestamdc" }
}
Function Get-ADUnusedComputers {
 Param (
  $domain=$env:USERDNSDOMAIN,
  $DaysInactive=91
 )
 $time = (Get-Date).AddDays(-($DaysInactive))
 $UnusedComputerList=Get-ADComputer -Filter {LastLogonTimeStamp -lt $time} -Properties LastLogonTimeStamp,OperatingSystem,OperatingSystemServicePack,CanonicalName,Description `
  | sort-object LastLogonTimeStamp `
  | Group-Object OperatingSystem,OperatingSystemServicePack

 $Count=0 ; $EnabledCount=0
 $ComputerObj=@()
 $UnusedComputerList | ForEach-Object {
  if ( ! $_.Name ) { $GroupName="None" } else { $GroupName=$_.Name }
  $_.Group | ForEach-Object {
   $Count++
   if ($_.Enabled) {$EnabledCount++}
   $LastLogon=[DateTime]::FromFileTime($_.lastLogonTimestamp)
   $Name=$_.Name
   $ComputerObj+=[pscustomobject]@{Group=$GroupName;Name=$Name;LastLogon=$LastLogon;Enabled=$_.Enabled;Description=$_.Description}
   write-host -NoNewline "`r$Name"
  }
 }

 write-host "`r                              "
 Write-StarLine "-"
 write-centered "$Count server unused since $time"
 $UnusedComputerList | Sort-Object Count,Name | ForEach-Object {if (! $_.Name) {$Name="N/A"} else {$Name=$_.Name} ; write-host "($($_.Count)) $Name"}
 Write-StarLine "-"

 return $ComputerObj
}
Function Get-ADUsersMailsWithNoExchangeAccount {
 # Return All AD Account with a mail with no corresponding account in Exchange
 Get-ADUsersMails | ForEach-Object { if ( ! (Assert-IsInExchange $_.SamAccountName) ) { Format-ADUserExtract $_ } }
 # Get-ADUsersMailsWithNoExchangeAccount | Export-Csv "C:\Temp\ADUsersMailsWithNoExchangeAccount.csv" -encoding "unicode" -notypeinformation
}
Function Get-ADUserLastLogonInOU {
 Param (
  $OU=$(Get-ADOUFromUser)
 )
 (Get-ADUser -SearchBase $OU -Filter { Name -like "*" } ) | ForEach-Object { Get-ADUserLastLogon $_.SamAccountName }
}
Function Get-ADUsersUPN {
 Param (
  $OU=$(Get-ADOUFromUser)
 )
 (Get-ADUser -properties Name,SamAccountName,proxyAddresses,UserPrincipalName,AccountExpirationDate,CanonicalName,EmailAddress,Description -SearchBase $OU -Filter {( ObjectClass -like "user") -and (Enabled -eq "True")} ) |
 Select-Object Name,SamAccountName,UserPrincipalName,AccountExpirationDate,CanonicalName,Description,EmailAddress,@{name="ProxyAddresses";expression={$_.proxyaddresses -replace "SMTP:","" -join ","}}
 # Get-ADUsersUPN | Export-Csv "C:\Temp\AllUsers.csv" -encoding "unicode" -notypeinformation
}
Function Get-ADComputersAll {
 Param (
  $OU=$(Get-ADOUFromServer)
 )
 Get-ADComputer -SearchBase $OU -filter {Enabled -eq "True"} | Select-Object Name
}
Function Get-ADAllServerInSameOU {
 Param (
  $ServerName=$env:COMPUTERNAME
 )
 Get-ADComputer -SearchBase ( Get-ADOUFromServer $Servername ) -filter 'OperatingSystem -like "*Windows*"'
}
Function Update-ADUPNSuffix {
 Param (
  [Parameter(Mandatory=$true)]$OldUPNSuffix,
  [Parameter(Mandatory=$true)]$NewUPNSuffix
 )
 Get-ADUser -Filter { Name -like "*" } -properties UserPrincipalName,Created,Modified | Select-Object Name,SamAccountName,UserPrincipalName,Created,Modified |
 Where-Object {$_.UserPrincipalName -like "*@$OldUPNSuffix"} | ForEach-Object {
  $OldUPN=$_.UserPrincipalName
  $OldSamAccount=($OldUPN -split("@"))[0]
  $NewUPN="$OldSamAccount`@$NewUPNSuffix"
  #Could use one liner but notepad ++ does not understand the syntax : "$(($OldUPN -split("@"))[0])`@$NewUPNSuffix"

  write-host "UPN Before : $OldUPN | After: $NewUPN"
  write-host "Set-ADUser $($_.SamAccountName) -UserPrincipalName $NewUPN"

  if ( $(read-host "Continue with the action (Y/N)") -eq "N" ) {write-host "Skipped" ; return}

  try {Set-ADUser $($_.SamAccountName) -UserPrincipalName $NewUPN ; write-host "Done"} catch {write-host -foregroundcolor "red" $error[0]}
 }
 write-host "Finished updating"
}
Function Get-ADSecurityDomain {
 Param (
  $ADLocation="AD:$((Get-ADDomain).DistinguishedName)",
  $UserFilter
 )
 # $UserFilter="$Env:USERNAME"
 # Get-ADSecurityDomain | Where-Object {! $_.IsInherited}
 Import-Module ActiveDirectory
 $schemaIDGUID=Get-SchemaGUIDDefinition
 if ($UserFilter) {
  (get-acl $ADLocation).access | Where-Object { $_.IdentityReference -eq $UserFilter } | Select-Object IdentityReference,IsInherited,AccessControlType,ActiveDirectoryRights,
   @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'-'} Else {$schemaIDGUID.Item($_.objectType)}}}
 } else {
  (get-acl $ADLocation).access | Select-Object IdentityReference,IsInherited,AccessControlType,ActiveDirectoryRights,
   @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'-'} Else {$schemaIDGUID.Item($_.objectType)}}}
 }
}
Function Get-ADSecurityGroup {
 Param (
  [Parameter(Mandatory=$true)]$Group
 )
 # Use Get-ADSecurityDomain instead
 #check self access only
 Import-Module ActiveDirectory
 $schemaIDGUID=Get-SchemaGUIDDefinition
 try {
  (Get-acl $("AD:"+((get-adgroup $Group).DistinguishedName))).Access | Where-Object {! $_.IsInherited} | Select-Object IdentityReference,
   @{name="ADRights";expression={
    if ($_.ActiveDirectoryRights -eq 'ExtendedRight') { $schemaIDGUID.Item($_.ObjectType) }
    else {$_.ActiveDirectoryRights}
   }},ObjectType,
   @{name="Type";expression={$_.AccessControlType}}
 } catch {write-colored "red" "Error during check ($($error[0]))"}
}
Function Get-ADSecurityUser {
 Param (
  [Parameter(Mandatory=$true)]$User
 )
 # Use Get-ADSecurityDomain instead
 #check self access only
 #On specific OU
  # Get-Acl -Path "AD:\DC=contoso,DC=com" |  Select-Object -ExpandProperty Access | Where-Object {! $_.IsInherited} | Where-Object {$_.IdentityReference -eq "CONTOSO\UserSamAccountName"}
 Import-Module ActiveDirectory
 try {
  (get-acl $("AD:"+((get-aduser $User).DistinguishedName))).Access | Where-Object {! $_.IsInherited} | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType,ObjectType
 } catch {write-colored "red" "Error during check ($($error[0]))"}
}
Function Get-ADComputerInVLAN {
 Param (
  [Parameter(Mandatory=$true)]$VLAN # Format example "192.168.1.*"
 )
 $ObjUserList=@()
 Get-ADComputer -Filter * -Properties ipv4Address | Where-Object {$_.ipv4Address -like $VLAN} | ForEach-Object {
  Progress "Checking : " $_.Name
  $obj = New-Object PSObject
  $obj | Add-Member NoteProperty Name $_.Name
  if ($_.ipv4Address) {$ip=$_.ipv4Address} else {$ip="-"}
  $obj | Add-Member NoteProperty IP $ip
  $ObjUserList += $obj
 }
 $ObjUserList | Sort-Object {[version]$_.IP}
}
Function Get-ADSendAsPermission {
 Param (
  $DisplayName
 )
 # Does not work with Connect-Exchange. This will always work but is really slow

 $ErrorActionPreference=Stop

 #When using Exchange Module
 if ( ! (Assert-IsCommandAvailable Get-RecipientPermission -NoError) ) {
  $Result=Get-ADPermission -identity $DisplayName | Where-Object {($_.ExtendedRights -like "*Send-As*") -and ($_.IsInherited -eq $false)}
  if ($Result) {return $Result.User} else {return "-"}
 }

 #When using O365
 $PermissionList=Get-RecipientPermission $DisplayName -AccessRights SendAs
 $Permissions=@()
 $PermissionList | ForEach-Object {
  if ($_.Trustee -eq "NT AUTHORITY\SELF") {$Permissions+="SELF"}
  else {
   $Trustee=$_.Trustee
   if ($Trustee.contains("/")) {
    #With Exchange command we get the canonical name
    $name=($Trustee -split "/")[-1]
    $Perm=Get-ADObject -Filter "Name -eq '$Name'"
   } elseif ($Trustee.contains("@")) {
    #with Office 365 we get the UPN
    $name=(get-aduser -filter {UserPrincipalName -eq $Trustee}).Name
    $Perm=Get-ADObject -Filter "Name -eq '$Name'"
   } else {
    $name=(get-aduser -filter {Name -eq '$Trustee'}).Name
   }
   if (! $Perm) {return}

   $Perm | ForEach-Object {
    if ($_.ObjectClass -eq 'Group') {
     $Permissions+=((Get-ADGroupMember $_.Name -Recursive).Name)
    } else {$Permissions+=$_.Name}
   }
  }
 }
 $Permissions | ForEach-Object {
  $User=$_
  #Remove blank values
  if (! $User) {return}
  if ($User -eq "SELF") {write-output "$user"} else {
   try {
    $useradinfo=get-aduser -filter {DisplayName -eq $User}
    if ($useradinfo.Enabled) {$UPN=$useradinfo.UserPrincipalName}
   } catch {$UPN=""}
   if (! $UPN) {write-output "$user"} else { write-output $UPN }}
 } | Sort-Object -uniq
}
Function Get-ADSendAsAndFullControlPermission {
 Param (
  [Parameter(Mandatory=$true)]$AccountName
 )
 # Work only with Exchange Module
 # Should Use Get-RecipientPermission instead
 Import-Module ActiveDirectory
 $SendAs=@()
 $FullControl=@()
 Get-ADPermission $AccountName | Where-Object {
  (! $_.IsInherited) -and ($_.User -inotlike "S-1-5-32-548") -and ($_.User -inotlike "NT AUTHORITY\SYSTEM") -and (($_.ExtendedRights -like "*Send-As*") -or ($_.AccessRights -eq "GenericAll"))
 } | Select-Object user,extendedrights,accessrights | ForEach-Object {
   if ($_.extendedrights -like "*Send-As*") {$SendAs=$SendAs+$_.User}
   elseif ($_.AccessRights -eq "GenericAll") {$FullControl=$FullControl+$_.User}
  }
 $SendAs=$SendAs -join ","
 if ($FullControl) {$FullControl=",FULLCONTROL : $($FullControl -join ",")"}
 return "$SendAs$FullControl"
}
Function Get-ADUpnFromMail {
 Param (
  $MailList=@()
 )
 ($MailList | ForEach-Object {$name=$_ ; get-aduser -filter {Mail -eq $name}}).UserPrincipalName
}
Function Get-ADVersion {
 Get-ADObject (Get-ADRootDSE).schemaNamingContext -Property objectVersion
}
Function Update-AccountPassword {
 Param (
  [Parameter(Mandatory=$true)]$OU,
  $Date = (Get-Date).AddDays(-120),
  $OutFile="UserList_$(get-date -uformat '%Y-%m-%d').csv"
 )
 # Usage example : Update-AccountPassword -OU @("OU=ouName1,DC=dcname,DC=com","OU=ouName2,DC=dcname,DC=com")
 $OU | ForEach-Object {
  write-host
  write-Colored -color 'Cyan' -ColoredText $_
  $UserList=Get-ADUser -Filter {PasswordLastSet -LT $Date} -Properties PasswordLastSet -SearchBase $_ -SearchScope OneLevel
  $UserListAll=Get-ADUser -Filter * -Properties PasswordLastSet -SearchBase $_ -SearchScope OneLevel
  write-Colored -color 'Magenta' -ColoredText "Current passwords to update $($UserList.count)/$($UserListAll.count)"
  $UserList | ForEach-Object {
   Progress "Forcing password update for user : " $_.SamAccountName
   $t_lastset=try {get-date -ErrorAction Stop -uformat '%Y-%m-%d-%T' $_.PasswordLastSet} catch {"Not Found"}
   write-output "$(get-date -uformat '%Y-%m-%d-%T')`t$($_.SamAccountName)`t$t_lastset`t$($_.Name)" | out-file -append $OutFile
   Set-aduser $_.SamAccountName -ChangePasswordAtLogon $true -PasswordNeverExpires $false
  }
 }
}
Function Get-ADCertificateStatus {
param(
 $ComputerList=$(Get-ADOUFromServer),
 $CommonName,
 $CALocation=(Get-CaLocationString),
 [ValidateSet("Machine","CodeSigning","EFS","WebServer","DomainController","User","CrossCA","AOVPNUserAuthentication")]$CertType='machine'
 )
 Try {

  $CertList=Get-IssuedCertificate -CAlocation $CALocation

  if ($CertType -eq 'AOVPNUserAuthentication') {
   $CertOID=Get-CertificateTemplateOID $CertType
   $CertListFiltered=$CertList | Where-Object {$_.'Certificate Template' -eq $CertOID}
  } else {
   $CertListFiltered=$CertList | Where-Object {$_.'Certificate Template' -eq $CertType}
  }

  if ($CertType -eq 'machine') {
   $FullComputerList=Get-AdComputer -SearchBase $ComputerList -Filter {Enabled -eq "True"} -Properties LastLogonDate,Description,DNSHostName,created,OperatingSystem,LastLogonDate,CanonicalName
   if ($CommonName) {
    $FullComputerList=$FullComputerList | Where-Object { $_.Name -like "*$CommonName*"}
   }
   $FullComputerList | Select-Object `
    Name,SamAccountName,DNSHostName,Description,Created,LastLogonDate,OperatingSystem,@{name="OU";expression={$_.CanonicalName -replace '/[^/]+$'}} | Select-Object *,`
     @{name="Cert";expression={$tmp=$_.DNSHostName;($CertListFiltered | Where-Object {$_.'Issued Common Name' -eq $tmp})[-1]}} | Select-Object -exclude cert *,`
      @{name="CertCN";expression={if (! $_.Cert) {'NotFound'} else {$_.Cert.'Issued Request ID'}}},`
      @{name="CertMSG";expression={if ($_.Cert) {$_.Cert.'Request Disposition Message'}}},`
      @{name="CertCreateDate";expression={if ($_.Cert) {$_.Cert.'Certificate Effective Date'}}},`
      @{name="CertExpirationDate";expression={if ($_.Cert) {$_.Cert.'Certificate Expiration Date'}}}
  } else {
   if ($CommonName) {
    $CertListFiltered=$CertListFiltered | Where-Object {$_.'Issued Common Name' -like "*$CommonName*"}
   }
   $CertListFiltered | Select-Object 'Certificate Template','Issued Common Name','Requester Name','Issued Request ID','Certificate Effective Date',`
    'Certificate Expiration Date',@{name="Message";expression={$_.'Request Disposition Message' -replace "`t","" -replace "`n",""}}`
    | Sort-Object 'Issued Request ID'
   }
 } Catch {
   write-host -ForegroundColor "Red" $Error[0]
 }
}
Function AreComputersInOUInGroup {
 Param (
  $OU=$(Get-ADOUFromServer),
  [Parameter(Mandatory=$true)]$GROUP,
  [switch]$ExportFile
 )
 $G_List=@()
 get-adcomputer -SearchBase $OU -filter * -Properties CanonicalName | Sort-Object Name | ForEach-Object {
  $G_List+=[pscustomobject]@{
   Name=$_.Name
   SamAccountName=$_.SamAccountName
   IsInGroup=$(Assert-IsComputerInGroup $_.SamAccountName $GROUP)
   OU=$(($_.CanonicalName -split('/')| Select-Object -skiplast 1) -join '/')}
 }
 if ($ExportFile) {
  $G_List | Export-Csv -Path "$GROUP.csv" -NoClobber -Encoding UTF8 -Delimiter ";" -NoTypeInformation
 }
 return $G_List
}
Function AreUsersInOUInGroup {
 Param (
  $OU=$(Get-ADOUFromUser),
  [Parameter(Mandatory=$true)]$GROUP,
  [switch]$ExportFile)
 $G_List=@()
 get-aduser -SearchBase $OU -filter * -Properties CanonicalName | Sort-Object Name | ForEach-Object {
  $G_List+=[pscustomobject]@{
   Name=$_.Name
   SamAccountName=$_.SamAccountName
   IsInGroup=$(Assert-IsUserInGroup $_.SamAccountName $GROUP)
   OU=$(($_.CanonicalName -split('/')| Select-Object -skiplast 1) -join '/')}
 }
 if ($ExportFile) {
  $G_List | Export-Csv -Path "$GROUP.csv" -NoClobber -Encoding UTF8 -Delimiter ";" -NoTypeInformation
 }
 return $G_List
}
Function Get-ADUserFromUPN {
 Param (
  $UPN
 )
 Get-ADUser -Filter {UserPrincipalName -eq $UPN}
}
Function Get-ADUserFromName {
 Param (
  $DisplayName
 )
 Get-ADUser -Filter {Name -eq $DisplayName}
}
Function Set-BusinessCategory {
 Param (
  [Parameter(Mandatory=$true)]$BC #BusinessCategory
 )
 if ( ! (Assert-IsCommandAvailable "Get-ADComputer" -NoError) ) { return "N/A" }
 $ServerPath=(Get-ADComputer $($env:computername)).DistinguishedName
 Set-ItemProperty "AD:\$ServerPath" -Name "BusinessCategory" -Value $BC
}
Function Get-BusinessCategory {
 if ( ! (Assert-IsCommandAvailable "Get-ADComputer" -NoError) ) { return "N/A" }
 $ServerName=$($env:computername)
 try {
  $ServerPath=(Get-ADComputer $ServerName).DistinguishedName
 } catch {return "Error checking value"}
 $ServerBusinessCategory=(Get-ItemProperty "AD:\$ServerPath" -Name "BusinessCategory").BusinessCategory
 if (! $ServerBusinessCategory) {$ServerBusinessCategory="N/A"}
 return $ServerBusinessCategory
}
Function Get-SchemaGUIDDefinition {
 #Set global to use in other scripts
 # $global:schemaIDGUID = @{}
 $schemaIDGUID = @{}
 $ErrorActionPreference = 'SilentlyContinue'
 Get-ADObject -erroraction 'SilentlyContinue' -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
 Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID | ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}
 $ErrorActionPreference = 'Continue'
 return $schemaIDGUID
}
Function Get-ValueFromGUID {
 Param (
  [Parameter(Mandatory=$true)]$Guid
 )
 $GuidList=Get-SchemaGUIDDefinition
 $GuidResult=$GuidList.GetEnumerator() | Where-Object { ($_.Name | Where-Object {$_ -eq $Guid} ) }
 if ($GuidResult.Value) { $returnvalue=$GuidResult.Value } else {$returnvalue="GUID Not Found"}
 return $returnvalue
}
Function Get-ADUserGUID {
 Param (
  [Parameter(Mandatory=$true)]$user
 )
 Try {
 ([GUID]((Get-ADUser $user -property mS-DS-ConsistencyGuid)."mS-DS-ConsistencyGuid")).GUID
 } Catch {
  write-host -ForegroundColor 'Red' "User $User does not have a GUID"
 }
}

# Bitlocker
Function Get-BitlockerRemote {
 Param (
  $ServerName=$env:COMPUTERNAME
 )
 Invoke-Command -ComputerName $ServerName -ScriptBlock {(Get-BitLockerVolume).KeyProtector | Where-Object KeyProtectorType -eq RecoveryPassword} | Select-Object KeyProtectorId,RecoveryPassword
}
Function Get-BitLockerKeyInAD {
 Param (
  $ServerName=$env:COMPUTERNAME
 )
 Try {
  Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase (Get-ADComputer $ServerName).DistinguishedName -Properties CanonicalName,msFVE-RecoveryPassword,Created `
   | Select-Object @{Name="Name";Expression={$ServerName}},@{Name="ID";Expression={$_.CanonicalName -replace '.*{', '' -replace "}",""}},msFVE-RecoveryPassword,Created
 } Catch {
  write-host -foregroundcolor "red" $Error[0]
 }
}
Function Set-BitlockerKeyInAD {
 $NumericalID=((get-BitLockerVolume).KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}).KeyProtectorId
 if (! $NumericalID) {
  write-host -foregroundcolor "red" "No Key Found - Check Encryption Status"
  Return
 }
 manage-bde -protectors -adbackup c: -id $NumericalID
}
Function Get-BitlockerKeyFromID {
 Param (
  $ID
 )
 if (!$ID) {write-host -foregroundcolor "Red" "ID is mandatory" ; Return}
 Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $((Get-ADDomain).DistinguishedName) `
  -Properties CanonicalName, msFVE-RecoveryPassword, Created `
   | Select-Object @{Name="Name";Expression={($_.CanonicalName -split "/")[-2]}},`
            @{Name="ID";Expression={$_.CanonicalName -replace '.*{', '' -replace "}",""}},`
            msFVE-RecoveryPassword,Created `
   | Where-Object {$_.ID -like "*$ID*"}
}

# Exchange/O365
#Exchange Connexion
Function LoadExchangeModule () {
 if ( ! (Assert-IsCommandAvailable Get-Mailbox -NoError) ) { try {add-pssnapin -ErrorAction stop Microsoft.Exchange.Management.PowerShell.E2010} catch {write-colored "red" "" "Cannot load Exchange Module" ; return $false} }
 Title -PostMsg " | ExchangeModule Loaded"
 return $true
}
Function UnloadExchangeModule () {
 try {Remove-PSSnapin -ErrorAction stop Microsoft.Exchange.Management.PowerShell.E2010} catch {write-colored "red" "" "Cannot load Exchange Module"}
 Title
}
Function Connect-Exchange () {
 [Parameter(Mandatory=$true)]$ExchangeServerName,
 $SessionName = "Exchange-Local"
 try {
  $URL = "http://$ExchangeServerName/PowerShell/"
  $SessionNumber = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $URL -Authentication Kerberos -AllowRedirection -Name $SessionName -ErrorAction Stop
  Import-PSSession $SessionNumber -AllowClobber -DisableNameChecking | Out-Null
  Title -PostMsg " | Exchange Connected"
 } catch {
  write-host -foregroundcolor "Red" $Error[0]
 }
}
Function Disconnect-Exchange () {
 #Disconnect all Exchange Local PS Sessions
 Get-PSSession -ErrorAction Ignore -Name "Exchange-Local" | Remove-PSSession

 $ModuleSource=get-command -ErrorAction Ignore get-mailbox
 if ($ModuleSource) { Remove-Module -ErrorAction Ignore -Name $($ModuleSource.Source) }
 Title
}
# O365 Connexion
Function Connect-MSOL {
Param (
 $user,
 [securestring]$Password
)
 while (! $user) {$user=read-host "Enter O365 UserName"}
 while (! $Password) {$Password=read-host -AsSecureString "Enter O365 Password of account `"$user`" "}

 $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User,$Password
 try {
  Connect-MsolService -ErrorAction Stop -Credential $Credential
 } catch {
  write-colored "Red" "" $error[0]
 }
}
Function Connect-O365Old {
 Param (
  $user=$((get-aduser $env:username -ErrorAction SilentlyContinue).UserPrincipalName), # Format must be UPN of O365 User
  [securestring]$Password,
  [switch]$NoProxy=$false
 )

 #Get User Variables
 while (! $Password) {$Password=read-host -AsSecureString "Enter O365 Password of account `"$user`" "}

 #Get Session Variables
 $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User,$Password
 $URL = "https://ps.outlook.com/powershell"
 $SessionName = "O365-Proxy"

 if ($NoProxy) {
  $proxysettings = New-PSSessionOption
 } else {
  # $proxysettings = New-PSSessionOption -ProxyAccessType IEConfig
  $proxysettings = New-PSSessionOption -ProxyAccessType AutoDetect
 }

 #Open Session
 try {
  $SessionNumber = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $URL -Credential $Credentials -Authentication Basic -AllowRedirection -SessionOption $proxysettings -Name $SessionName -WarningAction Ignore -ErrorAction Stop
 } catch {
  $ConnectionErrorMessage = $Error[0]
  if ( $ConnectionErrorMessage.Exception.ErrorCode -eq 12180) {
   # If 'The Proxy Auto-configuration URL was not found' try again with direct connection
   $SessionNumber = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $URL -Credential $Credentials -Authentication Basic -AllowRedirection -SessionOption $(New-PSSessionOption) -Name $SessionName -WarningAction Ignore -ErrorAction Stop
  } else {
   write-host -foregroundcolor "red" "Error during connection : $ConnectionErrorMessage ($($ConnectionErrorMessage.Exception.Message))"
   return
  }
 }

 #Import command in Shell
 import-module (Import-PSSession $SessionNumber -AllowClobber -DisableNameChecking -ErrorAction Stop) -Global | Out-Null
 Title -PostMsg " | O365 Connected"
}
Function Connect-O365 {
 Param (
  $user,
  [securestring]$Password,
  [switch]$NoProxy=$false
 )
 #Get UPN of current user if not set
 if ((! $User) -and (Get-Command get-aduser -ErrorAction SilentlyContinue)) {
  $user=$((get-aduser $env:username -ErrorAction SilentlyContinue).UserPrincipalName)
 }
 if (! $User) {write-host -ForegroundColor "Red" "UserName is mandatory" ; return}
 if ($NoProxy) {
  $proxysettings = New-PSSessionOption
 } else {
  $proxysettings = New-PSSessionOption -ProxyAccessType AutoDetect
 }
 if(!$(Get-InstalledModule -Name 'ExchangeOnlineManagement')) { import-module 'ExchangeOnlineManagement' }
 Connect-IPPSSession -UserPrincipalName $user -PSSessionOption $proxysettings -ConnectionUri "https://ps.protection.outlook.com/powershell-liveid/"
}
Function Disconnect-O365 {
 #Disconnect all O365 PS Sessions
 Get-PSSession -ErrorAction Ignore -Name "O365-Proxy" | Remove-PSSession

 $ModuleSource=get-command -ErrorAction Ignore get-mailbox
 if ($ModuleSource) { Remove-Module -ErrorAction Ignore -Name $($ModuleSource.Source) }
 Title
}
# SendMail
Function Send-MailO365 {
 Param (
  [PSCredential]$Credential=(get-credential),
  [Parameter(Mandatory=$true)]$eTo,
  [Parameter(Mandatory=$true)]$eFrom,
  [Parameter(Mandatory=$true)]$eSubject,
  [Parameter(Mandatory=$true)]$eBody
 )
 try {
  Send-MailMessage -SmtpServer 'smtp.office365.com' -port 587 -UseSsl -BodyAsHtml -Priority High -Encoding UTF8 -credential $Credential -To $eTo -From $eFrom -Subject $eSubject -Body $eBody -ErrorAction Stop
  } catch {
   write-host -foregroundcolor "red" "Error while sending mail ($($error[0]))"
  }
}
# Get Info/Filter
Function Get-ExchangeVersion {
 if ( ! (Assert-IsCommandAvailable EXSetup) ) {return}
 $ExchangeFileVersion=Get-Command EXSetup | Where-Object {$_.FileVersionInfo}
 $ExchangeFileVersion | Where-Object {
 Write-Colored $defaultblue "" $($_.ProductName,$_.Comments,"(",$_.ProductVersion,")")
 }
}
Function Get-ExchangeMailboxSize {
 Param (
  [Parameter(Mandatory=$true)]$DisplayName,
  [switch]$NoError
 )
 # if ( ! (LoadExchangeModule) ) {return}
 if ( ! (Assert-IsCommandAvailable Get-MailboxStatistics) ) {return}
 try {
  $MailboxStats=Get-MailboxStatistics -ErrorAction stop $DisplayName | Select-Object DisplayName,TotalItemSize,ItemCount,ServerName
  $mailboxinfo = New-Object PSObject
  $mailboxinfo | Add-Member NoteProperty Size $(($MailboxStats.TotalItemSize -replace (",","") -replace (" bytes","")).Split('()')[1])
  $mailboxinfo | Add-Member NoteProperty Count $MailboxStats.ItemCount
  $mailboxinfo | Add-Member NoteProperty ServerName $MailboxStats.ServerName
  return $mailboxinfo
 } catch {
  if ($NoError) {return}
  write-colored "Red" "" "Error with account $DisplayName ($($error[0]))"
 }
}
Function Get-MailboxPermissionFiltered {
 Param (
  [Parameter(Mandatory=$true)]$Mailbox,
  [Parameter(Mandatory=$true)]$PermissionType
 )
# Works for SharedMailbox also
 $ErrorActionPreference="Stop"

 #Check Command Availability
 if ( ! (Assert-IsCommandAvailable Get-Mailbox) ) {return}

 #Check mandatory params
 if (! $Mailbox) {write-colored "Red" -ColoredText "A Mailbox Name is mandatory";return}

 #Get Mailbox SendAs permission
 try { $MailboxPermissionSendAs = Get-RecipientPermission $Mailbox -ErrorAction "Stop" } catch {if ($verbose) {write-colored "red" -ColoredText $error[0]}}
 # Ignore Deny and Self
 if ($MailboxPermissionSendAs) {
  $MailboxPermissionSendAs = $MailboxPermissionSendAs | Where-Object {! (( $_.IsInherited ) -or ( $_.Deny ) -or ($_.Trustee -like "*nt authority\self*"))}
 }

 #Get Mailbox Full Access permission
 try { $MailboxPermissionFullAccess = Get-MailboxPermission $Mailbox -ErrorAction "Stop" } catch {if ($verbose) {write-colored "red" -ColoredText $error[0]}}
 # Ignore Deny and Self
 if ($MailboxPermissionFullAccess) {
  $MailboxPermissionFullAccess = $MailboxPermissionFullAccess | Where-Object {! (( $_.IsInherited ) -or ( $_.Deny ) -or ($_.User -like "*nt authority\self*"))}
 }

 If ((! $PermissionType) -or ($PermissionType -eq "SendAs") ) {
 $MailboxPermissionSendAs | Select-Object @{name="MailBox";expression={$_.Identity}},
  @{name="ID";expression={$_.Trustee}},
  @{name="Rights";expression={"SendAs"}},
  @{name="DetailObject";expression={Get-Mailbox $_.Trustee -ErrorAction SilentlyContinue |`
   Select-Object UserPrincipalName,Identity,CustomAttribute2,DisplayName,WindowsEmailAddress}} |`
   Select-Object Mailbox,ID,Rights,
    @{name="DisplayName";expression={$($_.DetailObject.DisplayName)}},
    @{name="Mail";expression={$($_.DetailObject.WindowsEmailAddress)}},
    @{name="OrganisationID";expression={$($_.DetailObject.CustomAttribute2)}}
 }
 If ((! $PermissionType) -or ($PermissionType -eq "FullAccess") ) {
 $MailboxPermissionFullAccess | Select-Object @{name="MailBox";expression={$_.Identity}},
  @{name="ID";expression={$_.User}},
  @{name="Rights";expression={"FullAccess"}},
  @{name="DetailObject";expression={Get-Mailbox $_.User -ErrorAction SilentlyContinue |`
   Select-Object UserPrincipalName,Identity,CustomAttribute2,DisplayName,WindowsEmailAddress}} |`
   Select-Object Mailbox,ID,Rights,
    @{name="DisplayName";expression={$($_.DetailObject.DisplayName)}},
    @{name="Mail";expression={$($_.DetailObject.WindowsEmailAddress)}},
    @{name="OrganisationID";expression={$($_.DetailObject.CustomAttribute2)}}
 }
}
Function Get-MemberFilter {
 Param (
  $Members,
  $Type
 )
 ($Members | Where-Object {$_.RecipientType -eq $Type}).name -join ","
}
Function Get-O365MemberOf {
 Param (
  [Parameter(Mandatory=$true)]$Mail
 )
 $UserDN=Get-User $mail | Select-Object -ExpandProperty DistinguishedName
(Get-Recipient -Filter "Members -eq '$UserDN'" ) | Select-Object Alias,DisplayName,PrimarySmtpAddress,RecipientType | Sort-Object DisplayName
}
Function Get-O365Licences {
 Param (
  $path="C:\Temp\LicensesExport-$(get-date -uformat %Y-%m-%d).csv",
  $UPNFilter="*" # Can filter with only one domain name for example : *@microsoft.com
 )
 Connect-MSOL
 Get-MsolAccountSku
 Get-MsolUser -all | Where-Object {$_.UserPrincipalName -like $UPNFilter} | Select-Object @{name="LocalUserID";expression={Progress "Checking : $($_.DisplayName)";$_.DisplayName}},
  UserPrincipalName,Department,Country,Office,PreferredLanguage, @{name="Lic";expression={($_.Licenses).AccountSkuId -join ","}} `
  | Export-Csv $path -NoTypeInformation -Delimiter ";" -Encoding UTF8
 return $path
}
# Checks
Function Assert-O365DistributionList {
 Param (
  $DLMail,
  [switch]$NoError
 )
 # if ( ! (Assert-IsCommandAvailable Get-MsolGroup) ) {return}
 if ( ! (Assert-IsCommandAvailable Get-DistributionGroup) ) {return}
 $result=$false
 try {
  # $result=Get-MsolGroup -erroraction stop -SearchString $DLMail
  $result=Get-DistributionGroup -erroraction stop $DLMail
 } catch {
  if (! $NoError) {write-colored "Red" "" "Error while searching for $DLMail ($($error[0]))"}
 }
 if ($result) {$result="$($result.GroupType) | $($result.DisplayName) | $($result.PrimarySmtpAddress)"} else {$result=$false}
 return $result
}
Function Assert-O365User {
 Param (
  [Parameter(Mandatory=$true)]$ANumber,
  [switch]$CheckInAD,
  [switch]$ShowMessage
 )
 if ( ! (Assert-IsCommandAvailable get-mailbox) ) {return}

 #Check In AD Allows to get UPN from AD
 # work with mail if UPN contains the good value
 # Usage : Assert-O365User toto@microsoft.com -CheckInAD -ShowMessage

 $result=$false

 if ($CheckInAD) {
  $UserPrincipalName=(get-aduser -filter {mail -eq $ANumber}).UserPrincipalName
  if (! $UserPrincipalName) {
   if ($ShowMessage) {write-host "$ANumber | $False | Non existing in AD"}
   return $false
  }
 }

 if ($UserPrincipalName) { $SearchValue=$UserPrincipalName} else {$SearchValue=$ANumber}

 try {
  $result=get-mailbox $SearchValue  -erroraction stop
 } catch {
  if ($ShowMessage) {write-colored "Red" "" "Error while searching Office 365 for $SearchValue ($($error[0]))"}
 }
 if ($result) {
  if ($ShowMessage) {
   write-host "$SearchValue | $($result.IsMailboxEnabled) | $($result.DisplayName) | $($result.ID) | $($result.WindowsLiveID) | $($result.PrimarySmtpAddress) | $($result.WhenMailboxCreated) | $($result.WhenMailboxCreated)"
  }
  return $($result.IsMailboxEnabled)
 } else {
  if ($ShowMessage) {write-host "$SearchValue | $False | Non Existing in Office 365 | "}
  return $false
 }
}
Function Assert-IsSelf {
 Param (
  $ValueToCheck,
  $MembersMails
 )
 #If Self is present in the Array, add members to Array
 $TMP=@() ; $TMP+=$ValueToCheck
 if ($TMP.contains("SELF")) { $TMP+=$(Get-ADUpnFromMail $($_.DistributionGroupMemberMailAddress -split ",")) }
 $TMP -join ','
}
Function Assert-O365Account {
 Param (
  $LoginName
 )
 #Check Account info :
 try {
  $accountinfo=get-aduser $loginname -properties UserPrincipalName,mail,proxyAddresses,targetAddress,legacyExchangeDN
 } catch {write-colored "Red" "$(get-date -uformat '%Y-%m-%d-%T') | Fatal Error | $loginname | " "Error during account check ($($error[0]))" $logfile ; return}

 Write-StarLine "-"
 #Backup Info
 write-colored "blue" "$(get-date -uformat '%Y-%m-%d-%T') | Normal | $loginname | Account check" "" $logfile
 write-colored "blue" "target address : " "$($accountinfo.targetAddress)" $logfile
 write-colored "blue" "LegacyExchangeDN address : " "$($accountinfo.legacyExchangeDN)" $logfile
 write-colored "blue" "Proxy Addresses : " "$($accountinfo.proxyAddresses) " $logfile
 Write-StarLine "-"

 return $accountinfo
}
# Create Lists
Function Get-ExchangeResources {
 Param (
  $OutputFile="C:\Temp\ExchangeResources.csv",
  $user=$((get-aduser $env:USERNAME).UserPrincipalName)
 )
 while (! $Password) {$Password=read-host -AsSecureString "Enter O365 Password of account `"$user`" "}

 Disconnect-O365
 Connect-Exchange

 #Get Exchange Information
 $NonMigrated=get-mailbox | Where-Object {$_.IsMailboxEnabled -and $_.IsResource} | Select-Object SamAccountName,DisplayName,PrimarySmtpAddress,
  @{name="EmailAddresses";expression={$_.EmailAddresses -replace "SMTP:","" -join ","}},Office,
  @{name="GrantSendOnBehalfTo";expression={$_.GrantSendOnBehalfTo.Name -join ","}},UserPrincipalName,OrganizationalUnit

 Disconnect-Exchange
 Write-host
 Connect-O365 $user $password

 #Get O365 Information
 $Migrated=Get-Mailbox -RecipientTypeDetails RoomMailbox -ResultSize:Unlimited -filter {DisplayName -like "DAS FR*" } | Select-Object SamAccountName,DisplayName,PrimarySmtpAddress,
  @{name="EmailAddresses";expression={$_.EmailAddresses -replace "SMTP:","" -join ","}},Office,
  @{name="GrantSendOnBehalfTo";expression={$_.GrantSendOnBehalfTo.Name -join ","}},UserPrincipalName,OrganizationalUnit

 Disconnect-O365

 #Fusion Migrated and Non MigratedResourcesMailbox
 $AllUserList=$NonMigrated+$Migrated

 $AllUserList | Export-Csv $OutputFile -encoding "unicode" -notypeinformation -Delimiter ";"

 return $OutputFile
}
# Misc Functions
Function New-PSTBackup {
 Param (
  $userlist=@(""),
  $Path=""
 )
 $userlist | ForEach-Object {
  $user=$_
  $BackupPath="$path$user.pst"
  try {
   if (test-path $BackupPath) {write-colored "Blue" "$(get-date -uformat '%Y-%m-%d-%T') | Warning | $User | " "Backup already exists : $BackupPath" $logfile; return}
   New-MailboxExportRequest -ErrorAction stop -name $user -Mailbox $user -FilePath $BackupPath
  } catch {
   write-colored "Red" "$(get-date -uformat '%Y-%m-%d-%T') | Fatal Error | $User | " "Error during the backup of $user ($($error[0]))" $logfile ; return
  }
 }
}
Function SamToMail {
 Param (
  $Sam
 )
 try {
  $UserInfo=get-aduser -filter {SamAccountName -eq $Sam} -properties mail
 } catch {write-host -foregroundcolor "Red" $Error[0]}
 $UserInfo.Name
 $UserInfo.Mail
}
Function CreateMailContactFromSam {
 Param (
  $Sam
 )
 Connect-Exchange
 if ( !(Get-Command "New-MailContact" -ErrorAction SilentlyContinue)) {write-host -foregroundcolor "Red" "Could not create mail contact for `"$Sam`"" ; return}
 $Result=SamToMail $Sam
 New-MailContact -Name $Result[0] -ExternalEmailAddress $Result[1]
 Disconnect-Exchange
}
Function Remove-O365UserFromDG {
 Param (
  $Mail
 )
 while (! $Mail) {$Mail=read-host "Enter mail :"}

 # Search for UPN from mail
 $UPN=$((get-aduser -Filter {Mail -eq $Mail}).UserPrincipalName)

 # check if one and only one answer is received
 if ($UPN.count -ne 1) {write-host -foregroundcolor "red" "Error while searching for user" ; return}

 # Get Distribution List Member
 $DistributionGroupList=Get-O365MemberOf $UPN | Where-Object {$_.RecipientType -like "MailUniversalDistributionGroup"}

 # Remove user from Distribution List
 $DistributionGroupList | ForEach-Object {
  New-item -ItemType Directory C:\Temp\ -Force | Out-Null
  write-host "Removing User $Mail from Distribution Group $($_.DisplayName)"
  Remove-DistributionGroupMember -Identity $_.DisplayName -Member $UPN
  write-output "Removed user $UPN from Distribution Group $($_.DisplayName)" >> "C:\Temp\O365-DG-Removal.log"
 }
}

# Windows Update
Function Get-WindowsUpdateConfig {
 Param (
  [Switch]$DisableWUServer,
  [Switch]$EnableWUServer
 )
 $MsUpdateReg = "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
 # Machine
 if ($EnableWUServer) {
  Set-ItemProperty "$MsUpdateReg\AU" -Name 'UseWUServer' -Value 1
 }
 if ($DisableWUServer) {
  Set-ItemProperty "$MsUpdateReg\AU" -Name 'UseWUServer' -Value 0
 }

 $WINDOWSUPDATE = Get-ItemProperty $MsUpdateReg 2> $null
 $WINDOWSUPDATE_WU_AU = Get-ItemProperty "$MsUpdateReg\AU" 2> $null

 if ( $WINDOWSUPDATE_WU_AU.UseWUServer -eq 1 ) {
  $COLOR="darkgreen";$WINDOWSUPDATE_WU_AU_UseWUServer_Status="Yes"
 } else {
  $COLOR="red";$WINDOWSUPDATE_WU_AU_UseWUServer_Status="No"
 }
 write-host -foregroundcolor $Color "Use WU Server  :" $WINDOWSUPDATE_WU_AU_UseWUServer_Status
 write-host "WUServer       : $($WINDOWSUPDATE.WUServer)"
 write-host "WUStatusServer : $($WINDOWSUPDATE.WUStatusServer)"
 write-host "Target Group   :" $WINDOWSUPDATE.TargetGroup
 # User
 $WINDOWSUPDATE=Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" 2> $null
 if ( $WINDOWSUPDATE.DisableWindowsUpdateAccess ) {
  $Color="red" ; $WINDOWSUPDATESTATUS="Disabled"
 } else {
  $Color="darkgreen" ; $WINDOWSUPDATESTATUS="Enabled"
 }
 write-host -foregroundcolor $Color "CurrentUser WU : $WINDOWSUPDATESTATUS ($env:username)"
}
Function Get-WindowsUpdate {
 $AutoUpdates = New-Object -ComObject "Microsoft.Update.AutoUpdate"
 $AutoUpdates.DetectNow()
 $AutoUpdates.Results
}
Function Restart-WindowsUpdate {
 Param (
  [Switch]$Start
 )
 # Restart Windows Update Service on client
 $ServiceList=("wuauserv","cryptSvc","bits","msiserver")
 if ($Start) {$startorstop="Start-Service" ; $RequiredStatus="Running"} else {$startorstop="Stop-Service -Force" ; $RequiredStatus="Stopped"}
 $ServiceList | ForEach-Object {
  $ServiceStatus=get-service $_
  $Count=0
  while (($ServiceStatus.Status -ne $RequiredStatus) -and ($count -le "10") ) {
   try {
    Write-Host -ForegroundColor Magenta "Waiting for service $($_) to be in status $RequiredStatus"
    Invoke-Expression "$startorstop $_"
    Start-Sleep -s 1
    $ServiceStatus=get-service $_
    $Count++
    if ($count -gt 10) {Throw {"Error Stopping service after 10 Tries"}}
   } catch {
    write-host -foregroundcolor "Red" "Error while starting or stopping $_"
   }
  }
  write-host "$($ServiceStatus.DisplayName) ( $($ServiceStatus.Name) ) : $($ServiceStatus.Status)"
 }
}
Function Reset-WindowsUpdate {
 $regkey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\"
 try {
  remove-ItemProperty $regkey "SusClientID" -ErrorAction SilentlyContinue
  remove-ItemProperty $regkey "SusClientIdValidation" -ErrorAction SilentlyContinue
  Restart-WindowsUpdate
  remove-item "C:\Windows\SoftwareDistribution" -recurse -ErrorAction Stop
  remove-item "C:\Windows\System32\catroot2" -recurse -ErrorAction Stop
  Restart-WindowsUpdate -Start
 } catch {
  write-host -foregroundcolor "Red" $error[0]
 }
 Get-WindowsUpdate
}
Function Get-WU {

 Param (
  $ServerName=$Env:ComputerName,
  $ScriptLog="C:\Temp\$($MyInvocation.MyCommand).Log",
  [switch]$Install,
  [switch]$IgnoreWsus,
  $UpdateID
 )

 $ErrorActionPreference="Stop"

 Function LocalUpdate ([Switch]$Install,$ScriptLog) {
  $ErrorActionPreference="Stop"

  New-Item -Type Directory $(Split-Path $ScriptLog) -Force | Out-Null

  if ($Install) { $Action='Install' } else {$Action='GetUpdate'}
  $ServerName=$Env:ComputerName

  Function Format-FileSize ($Size,$Format="0:0.00") {
   If ($size -gt 1TB) {[string]::Format("{$Format} TB", $size / 1TB)}
   ElseIf ($size -gt 1GB) {[string]::Format("{$Format} GB", $size / 1GB)}
   ElseIf ($size -gt 1MB) {[string]::Format("{$Format} MB", $size / 1MB)}
   ElseIf ($size -gt 1KB) {[string]::Format("{$Format} kB", $size / 1KB)}
   ElseIf ($size -gt 0) {[string]::Format("{$Format} B", $size)}
   Else {""}
  }
  Function Get-NetIP ($Server,[Switch]$Verbose) {
 #To test multiple server : $("","toto","Server-01","Server-02") | ForEach-Object {"[$($_)]" ; Get-NetIP $_ ; write-host}
 $ErrorActionPreference="Stop"
 Try {
  $CommandLine="(Invoke-WebRequest 'https://ifconfig.me/ip' -ErrorAction Stop -TimeoutSec 1 -UseBasicParsing).Content.Trim()"
  if ($server) {
   $PsRemoteResult=$(Try {Test-WSMAN $Server -ErrorAction Stop | Out-Null; $true} catch {$false})
   if ($PsRemoteResult) {
    Invoke-Command -ComputerName $Server -ArgumentList $CommandLine -ErrorAction Stop -ScriptBlock {
     #Curl is not available before version 3
     if ($PSVersionTable.PSVersion.Major -lt "3") { throw "Cannot Check (PS version < 3)" }
     #$Using: does not work well when remoting to PC
     Invoke-Expression $args[0] -ErrorAction Stop
    }
   } else {
    throw "$Server is not accessible"
   }
  } else {
   invoke-expression $CommandLine -ErrorAction Stop
  }
 } Catch {
  if ($Verbose) { write-Host -ForegroundColor "Red" "No Internet Connection ($($Error[0]))" }
 }
}
  Function Write-Colored ($Color=$defaultblue,$NonColoredText,$ColoredText,[switch]$NoNewLine=$false,[Switch]$PrintDate,$filepath) {
   If (! $Color) {$Color = "Cyan"}
   if ($PrintDate) { $Date="$(get-date -uformat '%Y-%m-%d %T') " } else { $Date= "" }
   write-host -nonewline "$Date$NonColoredText"
   if ($NoNewLine) {write-host -nonewline -foregroundcolor $Color $ColoredText} else {write-host -foregroundcolor $Color $ColoredText}
   if ($filepath) { write-output "$Date$NonColoredText $ColoredText" | out-file -append $filepath }
  }

  Try {
   Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Starting Process"

   Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Creating API Object"
   $UpdateSession = New-Object -ComObject "Microsoft.Update.Session"

   Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Disabling Proxy Search"
   if ( $UpdateSession.WebProxy ) { $UpdateSession.WebProxy.BypassProxyOnLocal=$true ; $UpdateSession.WebProxy.AutoDetect=$false }

   #Choose Criteria (Default all non installed) -> Could filter by type : $Criteria = "IsInstalled=0 and Type='Software'"
   $Criteria = "IsInstalled=0"

  If ($UpdateID) {$Criteria = $Criteria + " and UpdateID=`'$UpdateID`'"}
   Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Choosing default Criteria : " -NoNewLine
   Write-Colored -filepath $ScriptLog  -Color 'Magenta' -ColoredText $Criteria

   Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Checking Internet Access : " -NoNewLine
   $UpdateSearcherObject=$UpdateSession.CreateUpdateSearcher()
   if (! $(Get-NetIP)) {
    $UpdateSearcherObject.Online=$false
    Write-Colored -filepath $ScriptLog -Color 'Red' -ColoredText "No Internet Access"
   } else {
    Write-Colored -filepath $ScriptLog -Color 'Green' -ColoredText "Internet Access found"
   }

   Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Launch Search with user Locale : " -NoNewLine
   Write-Colored -filepath $ScriptLog  -Color 'Magenta' -ColoredText $UpdateSession.UserLocale
   $Updates = $UpdateSearcherObject.Search($Criteria).updates

   if (! ($Updates.Count -eq 0)) {
    if ($Updates.Count -gt 1) {$plural="s"}
    Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "$($Updates.Count) update$plural found"

    $ReturnResult=$Updates | Select-Object @{name="ServerName";expression={$ServerName}}, Title, MsrcSeverity, RebootRequired,
     @{name="MinDlSize";expression={Format-FileSize $_.MinDownloadSize}},
     @{name="MaxDlSize";expression={Format-FileSize $_.MaxDownloadSize}}, SupportUrl, Description ,
     @{name="KB";expression={$_.KBArticleIDs | ForEach-Object { "KB$($_)" }}},
     @{name="UpdateID";expression={$_.Identity.UpdateID}}

    #Print result to Screen
    $ReturnResult
    #Print result to file
    $ReturnResult | Out-String >> $ScriptLog
	   if ($Install) {
     Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Downloading $($Updates.Count) update$plural"
     #Download updates
     $ReturnInfo=""
     $Downloader = $UpdateSession.CreateUpdateDownloader()
     $Downloader.Updates = $Updates
     $ReturnInfo=$Downloader.Download()
     Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Downloading result : $($ReturnInfo.ResultCode) ($($ReturnInfo.HResult))"

     Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Installing $($Updates.Count) update$plural"
     #Install updates
     $ReturnInfo=""
     $Installer = $UpdateSession.CreateUpdateInstaller()
     $Installer.Updates = $Updates
     $ReturnInfo=$Installer.Install()

     Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action in progress | " -ColoredText "Installing result : $($ReturnInfo.ResultCode) ($($ReturnInfo.HResult))"

     Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action Finished    | " -ColoredText "Installed $($Updates.Count) update$plural"

     if ($InstallerStatus.RebootRequired) {
      Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action Finished    | " -ColoredText "Reboot required"
     }
	   }
   } else {
    Write-Colored -filepath $ScriptLog -Color 'Green' -PrintDate -NonColoredText "| $ServerName | $Action Finished    | " -ColoredText "Nothing to do"
    $ReturnResult=New-Object PSObject -Property @{ServerName=$ServerName;Title="";MsrcSeverity="";RebootRequired="";MinDlSize="";MaxDlSize="";SupportUrl="";Description="No Update Required"}
   }
 } Catch {
  Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName | $Action Finished    | " -ColoredText "ERROR : $($Error[0])"
  $ReturnResult=New-Object PSObject -Property @{ServerName=$ServerName;Title="";MsrcSeverity="";RebootRequired="";MinDlSize="";MaxDlSize="";SupportUrl="";Description="ERROR : $($Error[0])"}
 }
 # return $ReturnResult
}

 if ($Install -and ($PSSenderInfo -or ( $ServerName -ne $($Env:ComputerName) ) ) ) {
  write-Host -ForegroundColor "Red" "Install is not available remotely - A scheduled task must be used"
  return
 }

 if ($ServerName -ne $($Env:ComputerName)) {
  try {
   if ($IgnoreWsus) {
    Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName |  ------ DEBUG ------  | " -ColoredText "Disabling WSUS"
    Invoke-command -ComputerName $ServerName -ScriptBlock { Set-ItemProperty "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name 'UseWUServer' -Value 0 }
   }
   Invoke-command -ComputerName $ServerName -ScriptBlock ${function:LocalUpdate}
  } catch {
   New-Object PSObject -Property @{ServerName=$ServerName;Title="";MsrcSeverity="";RebootRequired="";MinDlSize="";MaxDlSize="";SupportUrl="";Description="ERROR : $($Error[0])"}
  }
 } else {
  if ($IgnoreWsus) {
   Write-Colored -filepath $ScriptLog -PrintDate -NonColoredText "| $ServerName |  ------ DEBUG ------  | " -ColoredText "Disabling WSUS"
   Set-ItemProperty "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name 'UseWUServer' -Value 0
  }
  if ($Install) {
   LocalUpdate -Install -ScriptLog $ScriptLog
  } else {
   LocalUpdate -ScriptLog $ScriptLog
  }
 }
}
Function Disable-WSUS {
 Set-ItemProperty "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name 'UseWUServer' -Value 0
}
Function Enable-WSUS {
 Set-ItemProperty "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name 'UseWUServer' -Value 1
}

# WSUS
Function Install-WSUS {
 Param (
  $DataFolder="E:\WSUS"
 )
 # Install Feature
 Install-WindowsFeature -Name UpdateServices -IncludeManagementTools | Out-Null

 # Create Folder
 $WSUSDataLocation=$DataFolder
 New-Item -Path $WSUSDataLocation -ItemType Directory -Force | Out-Null

 # WSUS Post Install (Must be run from the server)
 Start-Process -NoNewWindow "C:\Program Files\Update Services\Tools\wsusutil.exe" -ArgumentList "postinstall","CONTENT_DIR=$WSUSDataLocation"
}
Function Remove-WSUSSuperseeded {
 Param (
  $WsusServerInfo=$(Get-WSUSServer),
  [Boolean]$useSecureConnection = $False,
  [Int32]$portNum = $portNumber
 )
 # Load .NET assembly
 [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
 $wsus=$WsusServerInfo
 # Connect to WSUS Server
 $updateServerInfo = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer($wsus.Name,$wsus.useSecureConnection,$wsus.PortNumber)
 $updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
 $UpdateList=$updateServerInfo.GetUpdates($updatescope )

 $count = 0
 foreach ($Update in $UpdateList ) {
  if (($Update.IsSuperseded) -and ! ($Update.IsDeclined)) {
   write-host "Decline Update : $($Update.Title)"
   $Update.Decline()
   $count=$count + 1
  }
 }
 write-host Total Declined Updates: $count
}
Function Set-WSUSConfig {
 Param (
  $ProxyInfo
 )
 $wsus=Get-WSUSServer

 #Connect to WSUS server configuration
 $wsusConfig = $wsus.GetConfiguration()

 # Set to download updates from Microsoft Updates
 Set-WsusServerSynchronization -SyncFromMU | Out-Null

 # Set Update Languages to English and save configuration settings
 $wsusConfig.AllUpdateLanguagesEnabled = $false
 $wsusConfig.SetEnabledUpdateLanguages("en")

 #If Proxy is required
 if ($ProxyInfo) {
  $wsusConfig.ProxyName=$ProxyInfo[0]
  $wsusConfig.ProxyServerPort=$ProxyInfo[1]
  $wsusConfig.UseProxy=$true
 }

 $wsusConfig.Save()

 #Get WSUS Subscription
 $subscription = $wsus.GetSubscription()
 $subscription.StartSynchronizationForCategoryOnly()

 # Perform initial synchronization to get latest categories
 While ($subscription.GetSynchronizationStatus() -ne 'NotProcessing') {
  Write-Host "`r$(get-date -uformat '%Y-%m-%d %T') Subscription Sync In Progress - Please Wait" -NoNewline
  Start-Sleep -Seconds 1
 }

 #Disable Products
 Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Office" } | Set-WsusProduct -Disable
 Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Windows" } | Set-WsusProduct -Disable
 Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Language Packs" } | Set-WsusProduct -Disable
 #Enable Products
 Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Windows Server 2016" } | Set-WsusProduct
 Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Windows 10 Fall Creators" } | Set-WsusProduct
 Get-WsusServer | Get-WsusProduct | Where-Object -FilterScript { $_.product.title -match "Windows 10 Creators" } | Set-WsusProduct

 #Configure the Classifications
 Get-WsusClassification | Where-Object {
  # When using IN cannot load profile on 2003
  # $_.Classification.Title -in ( 'Critical Updates', 'Definition Updates', 'Feature Packs', 'Security Updates', 'Service Packs', 'Update Rollups', 'Updates') } | Set-WsusClassification
  ( 'Critical Updates', 'Definition Updates', 'Feature Packs', 'Security Updates', 'Service Packs', 'Update Rollups', 'Updates') -contains $_.Classification.Title } | Set-WsusClassification

 #Configure Synchronizations
 $subscription.SynchronizeAutomatically=$true

 #Set synchronization scheduled for midnight each night
 $subscription.SynchronizeAutomaticallyTimeOfDay= (New-TimeSpan -Hours 0)
 $subscription.NumberOfSynchronizationsPerDay=1
 $subscription.Save()

 #Launch Sync
 $subscription.StartSynchronization()

 #Monitor Progress of Synchronisation
 Start-Sleep -Seconds 15 # Wait for sync to start before monitoring
 while ($subscription.GetSynchronizationProgress().ProcessedItems -ne $subscription.GetSynchronizationProgress().TotalItems) {
  $ProgressPercentage=[System.Math]::Round($subscription.GetSynchronizationProgress().ProcessedItems * 100/($subscription.GetSynchronizationProgress().TotalItems),2)
  Write-Host "`r$(get-date -uformat '%Y-%m-%d %T') Sync In Progress - $ProgressPercentage %    " -NoNewline
  Start-Sleep -Seconds 1
 }

 write-host
 write-host "Done"
}
Function Get-WSUSUpdatesStatus {
 Param (
  $ServerOU=$(Get-ADOUFromServer),
  $Output="C:\Temp\WindowsUpdate"
 )
 $count=0
 $CurrentDate=get-date -uformat '%Y-%m-%d'
 $serverlist=(Get-ADComputer -SearchBase $ServerOU -filter *).Name
 $GlobalUpdateList=@()
 # $GlobalUpdateList="$($output)_$($CurrentDate)_UpdateList.csv"
 # write-output "ServerName;UpdateCount;Uptime;Access" | Out-File $GlobalUpdateList -Encoding UTF8
 $GlobalServerList=@()

 $StartDate=get-date -uformat "%Y-%m-%d %T"
 "$StartDate - Start of process"

 $serverlist | ForEach-Object {
  $count++
  Progress "Checking server $count/$($serverlist.count) : " $_
  $ServerInfo = New-Object PSObject
  $ServerInfo | Add-Member NoteProperty ServerName $_
  try {
   if (Test-RemotePowershell $_) {
    $serverupdatelist=get-windowsupdate -ErrorAction Stop -computername $_
    $GlobalUpdateList += $serverupdatelist
    # $serverupdatelist | Out-File -append $GlobalUpdateList -Encoding UTF8
    $ServerInfo | Add-Member NoteProperty UpdateCount $serverupdatelist.count
    $ServerInfo | Add-Member NoteProperty UpdateSize $(($serverupdatelist | Measure-Object -Sum MaxDownloadSize).Sum)
    $ServerInfo | Add-Member NoteProperty Uptime $(Get-UptimePerso $_)
    $ServerInfo | Add-Member NoteProperty Access "OK"
   } else {
    $ServerInfo | Add-Member NoteProperty UpdateCount "-"
    $ServerInfo | Add-Member NoteProperty UpdateSize "-"
    $ServerInfo | Add-Member NoteProperty Uptime "-"
    $ServerInfo | Add-Member NoteProperty Access $error[0]
   }
  } catch {
   $ServerInfo | Add-Member NoteProperty UpdateCount "-"
   $ServerInfo | Add-Member NoteProperty UpdateSize "-"
   $ServerInfo | Add-Member NoteProperty Uptime "-"
   $ServerInfo | Add-Member NoteProperty Access $error[0]
  }
  $GlobalServerList += $ServerInfo
 }
 $GlobalServerList | Export-Csv "$($output)_$($CurrentDate)_ServerList.csv" -Encoding Unicode -NoTypeInformation -Delimiter ","
 $GlobalUpdateList | Export-Csv "$($output)_$($CurrentDate)_UpdateList.csv" -Encoding Unicode -NoTypeInformation -Delimiter ","

 $EndDate=$(get-date -uformat "%Y-%m-%d %T")
 $Duration=(New-TimeSpan -Start $StartDate -End $EndDate)
 "$EndDate - Process finished in {0:g}" -f $Duration
}
Function Get-WSUSConfiguredCategories {
 Param (
  $wsusServer=$(Get-WsusServer)
 )
 $wsusSubscription = $wsusServer.GetSubscription()
 $wsusSubscription.GetUpdateCategories() | Select-Object Title
}
Function Get-WSUSConfiguredClassifications {
 Param (
  $wsusServer=$(Get-WsusServer)
 )
 $wsusSubscription = $wsusServer.GetSubscription()
 $wsusSubscription.GetUpdateClassifications() | Select-Object Title
}
Function Get-WSUSConfiguredApprovalRules {
 Param (
  $wsusServer=$(Get-WsusServer)
 )
 $ApprovalRulesList=@()
 $wsusServer.GetInstallApprovalRules() | ForEach-Object {
  $ApprovalRulesList+=[pscustomobject]@{Name=$_.Name;TargetGroups=$($_.GetComputerTargetGroups().Name -join ",");UpdateClassification=$_.GetUpdateClassifications().Title -join ","}
 }
 return $ApprovalRulesList
}
Function Connect-WSUS {
 Param (
  [Parameter(Mandatory=$true)]$WsusServer, #WSUS FQDN
  [Switch]$NoSSL,
  $Path="C:\Temp\"
 )
 if ($NoSSL) {
  $UseSSL=$false
  $PortNumber="8530"
 } else {
  $UseSSL=$true
  $PortNumber="8531"
 }

 [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

 #Create WSUS connection Object
 try {
  $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WsusServer,$UseSSL,$PortNumber)
 } catch {
  write-host -foregroundcolor "red" "$WsusServer : $($error[0])"
  return
 }

 return $wsus
}
Function Get-WSUSUpdatesFull {
 Param (
  $wsus=$(Connect-WSUS)
 )
 $updates = $wsus.GetUpdates()
 return $updates
}
Function Get-WSUSUpdatesWaitingForApproval {
 Param (
  $ServerGroup="FR-G-ORG-Servers WSUS"
 )
 Get-ADGroupMember $ServerGroup | ForEach-Object {
  $CurrentServer=$_.Name
  Invoke-Command -ComputerName $CurrentServer -ArgumentList $CurrentServer -ScriptBlock {
   $ServerName=$args[0]
   Write-host -ForegroundColor Cyan "Checking server $ServerName"
   Get-WsusUpdate -Approval Unapproved -Status Needed | Select-Object *, @{Name="Server";Expression={$ServerName}}, @{Name="Title";Expression={$_.Update.Title}}
  }
 } | Select-Object Server,Title,Classification,ComputersWithErrors,ComputersNeedingThisUpdate,RestartBehavior,`
 @{Name="Products";Expression={$_.Products -join ','}},UpdateId
}

# DNSManagement
Function CheckDNS {
Param (
 $Server=$($env:computername)
)
try { $IP=[IPAddress]$Server } catch {}

 try {

  if ($IP) {
   $Name=Resolve-DNSName -Name $IP -ErrorAction SilentlyContinue
   $Server=$Name.NameHost
   if (!$Server) {Throw "No name found for this IP"}
  }
  $Server | ForEach-Object {
   Resolve-DNSName -QuickTimeout -Name $_ -type A -ErrorAction Stop |
   Select-Object `
    @{Name="Name (Ping)";Expression={ $Ping=Test-Connection $_.Name -BufferSize 16 -Count 1 -ea 0 -quiet ; "$($_.Name) ($Ping)"}},
    @{Name="IPAddress (Ping)";Expression={ $Ping=Test-Connection $_.IPAddress -BufferSize 16 -Count 1 -ea 0 -quiet ; "$($_.IPAddress) ($Ping)"}},
    @{Name="Reverse";Expression={ (Resolve-DNSName -QuickTimeout -ErrorAction SilentlyContinue $_.IPAddress).NameHost }}
  }
 } catch {
  New-Object PSObject -Property @{"Name (Ping)"=$Server;"IPAddress (Ping)"=$Error[0];"Reverse"=$Error[0]}
 }
}
Function CheckVLAN {
 Param (
  $GatewayIP
 )
 #1) Check if IP is valid
 try {[ipaddress]$GatewayIP 2>&1>$null} catch {}
 if (!$? -or !$GatewayIP -or [regex]::matches("$GatewayIP","\.").count -ne 3) { write-colored "red" "" "You must provide a correct Gateway IP" ; return}

 #2) Show which Gateway will be used
 Write-Colored $defaultblue (Align "Checking Gateway" 20 " : ") $GatewayIP -nonewline

 #3) Test Gateway Ping response :
 if ( ! (Test-Connection -Cn $GatewayIP -BufferSize 16 -Count 1 -ea 0 -quiet) ) { write-colored "red" " - ping " "KO" } else { write-colored "green" " - ping " "OK" }

 #4) Get Reverse zone
 $IPElements=$GatewayIP.split('.')
 $Reverse=$IPElements[2]+"."+$IPElements[1]+"."+$IPElements[0]

 Write-Colored $defaultblue (Align "Reverse Zone" 20 " : ") $Reverse

 #5) Check Reverse zone
 try {
  $NameServers=(nslookup -type=NS "$Reverse.in-addr.arpa" 2>&1 | Select-string -pattern "nameserver").line | ForEach-Object {$_.split("=")[1].trim()}
  Write-Colored $defaultblue "Reverse zone defined on following DNS Servers : "
  Format-PrintLineByLine $NameServers $defaultblue
  } catch { write-colored "red" "" "Failed checking reverse zone or reverse zone not defined" }
}
Function Get-DNSAllZoneUsingAlias {
 Param (
  $DNSServerName=((Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)[0]),
  $AliasFilter="vip*"
 )
 $ZoneList=@(Get-DnsServerZone -ComputerName $DNSServerName | Where-Object { ! ($_.IsReverseLookupZone)})
 $RecordList=@()
 $ZoneList | ForEach-Object {
  $Record=Get-DnsServerResourceRecord -ZoneName $($_.ZoneName) -ComputerName $DNSServerName | Where-Object {$_.RecordData.HostNameAlias -like $AliasFilter}
  if ( $Record.Count -eq 0 ) {
   $CurrentZone="" ; $ZoneTTL=""
   return
  } else {
   $CurrentZone=$_.ZoneName
   $ZoneTTL=$(($record.TimeToLive | Get-Unique).TotalSeconds)
   $record | ForEach-Object {
    $RecordList+=New-Object PSObject -Property @{
     ZoneName=$CurrentZone;
     ZoneTTL=$ZoneTTL;
     Hostname=$_.HostName;
     RecordType=$_.RecordType;
     RecordAlias=$_.RecordData.HostNameAlias
    }
   }
  }
  $RecordList | Select-Object ZoneName,Hostname,RecordAlias,ZoneTTL,RecordType
 }
}
Function Get-DNSAllZoneInfoSOA {
 Param (
  $DNSServerName=$((Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)[0])
 )
 @(Get-DnsServerZone -ComputerName $DNSServerName | Where-Object {! ($_.IsReverseLookupZone)}) | ForEach-Object {
  $Record=Get-DnsServerResourceRecord -ZoneName $($_.ZoneName) -ComputerName $DNSServerName -RRType "SOA"
  if ( $Record.Count -eq 0 ) {return} else {write-host -nonewline -foreground "Magenta" "$($_.ZoneName)"}
  $record | ForEach-Object { write-host " : $($_.RecordData.PrimaryServer) `(Hostname : $($_.Hostname)`)"}
 }
}
Function Get-DNSAllZoneInfoNS {
 Param (
  $DNSServerName=$((Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)[0]),
  $ServerToMark=""
 )
 try {Get-DnsServerZone -ErrorAction Stop -ComputerName $DNSServerName | Where-Object {! ($_.IsReverseLookupZone)} | ForEach-Object {
  $Record=Get-DnsServerResourceRecord -ZoneName $($_.ZoneName) -ComputerName $DNSServerName -RRType "NS"
  if ( $Record.Count -eq 0 ) {return} else {write-host -foreground "Magenta" "$($_.ZoneName)"}
  $record | Group-Object -Property Hostname | ForEach-Object {
   Write-host -foregroundcolor "Green" "=> Hostname $($_.Name)"
   $_.Group.RecordData.NameServer | ForEach-Object {
    if ($_ -like $ServerToMark ) {write-host -foregroundcolor "Red" $_} else {$_}
    }
   }
  Write-host $("*" * ([console]::windowwidth - 2))
 }
 } catch {write-host -foregroundcolor "red" $error[0]}
}
Function Remove-DNSEntry {
 Param (
  $ServerName,
  $DNSServer=(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)[0],
  $CurrentZone=$env:USERDNSDOMAIN
 )
 Remove-DnsServerResourceRecord -ZoneName $CurrentZone -RRType "A" -ComputerName $DNSServer -Name $ServerName
}

# DHCP Management
Function CheckDHCPReservations { #Check DHCP Reservation of a group of machine in a Scope

 Param (
  [Parameter(Mandatory=$true)]$Scope, # IP Scope using the format : 192.168.0.0
  [Parameter(Mandatory=$true)]$DHCPServer, # DHCP Server Name
  [Parameter(Mandatory=$true)]$ADGroup # AD Group Name containing Machines
 )

 write-host "Checking Reservation"
 $ReservationList=Get-DhcpServerv4Reservation -ScopeId $Scope -ComputerName $DHCPServer | `
  Select-Object IPAddress,@{Name="MAC";Expression={$_.ClientId -replace "-",""}},Name,AddressState | `
   Sort-Object -Property { [Version]$_.IPAddress }

 write-host "Checking Computers"
 $ComputerList=Get-ADGroupMember $ADGroup | Select-Object name | Sort-Object Name | ForEach-Object {
  Progress "Checking : " -Value $_.Name
  try {
   invoke-command -ComputerName $_.Name -ErrorAction Stop -ScriptBlock {
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Select-Object Description,@{Name="MAC";Expression={$_.GetPhysicalAddress()}}
   } | Where-Object Description -eq 'vmxnet3 Ethernet Adapter'
  } catch {
   write-host -ForegroundColor "Red" "Error checking $($_.Name) $($Error[0])"
  }
 }

 $ComputerList | `
 Select-Object PSComputerName,MAC,
  @{Name="ReservationIP";Expression={($ReservationList | Where-Object MAC -eq $_.MAC).IPAddress}},
  @{Name="ReservationName";Expression={($ReservationList | Where-Object MAC -eq $_.MAC).Name}},
  @{Name="Status";Expression={($ReservationList | Where-Object MAC -eq $_.MAC).AddressState}}

}

# Disks
Function Get-PartitionInfo {
 Param (
  $ServerName,
  $MinimumFreeSpace="20",
  [Switch]$Object
 )
 #Init Global Volume List Object
 $VolumeListObj=@()

 #Get Volume info
 try {
  if ($ServerName) {
   if (Assert-IsCommandAvailable -NoError "Get-CimInstance") {
    $VolumeList=Get-CimInstance Win32_Volume -ComputerName $ServerName -ErrorAction Stop
   } else {
    $VolumeList=Get-WmiObject Win32_Volume -ComputerName $ServerName -ErrorAction Stop
   }
  } else {
   $ServerName=$Env:COMPUTERNAME
   if (Assert-IsCommandAvailable -NoError "Get-CimInstance") {
    $VolumeList=Get-CimInstance Win32_Volume -ErrorAction Stop
   } else {
    $VolumeList=Get-WmiObject Win32_Volume -ErrorAction Stop
   }
  }
 } catch {
  write-colored "Red" -ColoredText $Error[0] ; return
 }

 #Volume check loop
 $VolumeList | Sort-Object DriveLetter | ForEach-Object {

  #Check Disk Type
  if ($_.Drivetype -eq 3) {
   $textcolor = $defaultblue ; $drivetype="HDD"
  } elseif ($_.Drivetype -eq 4) {
   $textcolor = "Magenta" ; $drivetype="Network"
  } elseif ($_.Drivetype -eq 5) {
   $textcolor = "Magenta" ; $drivetype="CD/DVD"
  } else {
   $textcolor= "DarkGray" ; $drivetype="Other"
  }

  if ( $_.Freespace) {
   $drivefreespace=[math]::round($_.Freespace/$_.Capacity*100,0)
   $UsedSpace=($_.Capacity-$_.freespace)

   #For Total
   $SizeTotal=$SizeTotal+$_.Capacity
   $FreeTotal=$FreeTotal+$_.freespace
  } else {
   $drivefreespace=""
   $UsedSpace=""
  }

  $VolumeListObj+=New-Object PSObject -Property @{
   ServerName=$ServerName
   Name=$_.Name;
   Letter=$_.DriveLetter;
   Label=$_.Label;
   Type=$drivetype;
   ClusterSize=$_.BlockSize;
   Indexing=$_.IndexingEnabled;
   BootVolume=$_.BootVolume;
   FileSystem=$_.FileSystem;
   Swap=$_.PageFilePresent;
   TotalSize=$_.Capacity;
   UsedSpace=$UsedSpace;
   FreeSpace=$_.freespace;
   TotalSizeH=Format-FileSize $_.Capacity;
   UsedSpaceH=Format-FileSize $UsedSpace;
   FreeSpaceH=Format-FileSize $_.freespace;
   FreePercent=$drivefreespace;
  }

  if (! $Object) {
   #Add color if size is under minimum freespace
   if ([decimal]$drivefreespace -lt [decimal]$MinimumFreeSpace) { $sizecolor = "red" } else {$sizecolor = [console]::foregroundcolor}
   #Check Label
   if ( ! $_.Label ) { $volumelabel = "N/A" } else { $volumelabel=$_.Label }
   #Align Drive Letter
   if ( ! $_.DriveLetter ) { $DriveLetter = "  " } else { $DriveLetter = $_.DriveLetter}
   #Check Page File
   if ($_.PageFilePresent) { $SWAP=" *SWAP*" } else { $SWAP="" }

   #Print
   write-starline "-"
   write-colored $textcolor -ColoredText (Align ($DriveLetter+" ($drivetype $($_.FileSystem) : $volumelabel$SWAP)") 38) -nonewline
   if ($_.Freespace) {
    write-colored $sizecolor -NonColoredText " | Total $(Align $(Format-FileSize($_.Capacity)) 10) / Free $(Align $(Format-FileSize($_.freespace)) 10) " -ColoredText $(align "( $drivefreespace% )" 12) -nonewline
   }
   Write-Colored $defaultblue -ColoredText $(Format-FileSize $_.BlockSize)
  }
 }

 #Add Total :
 $VolumeListObj+=New-Object PSObject -Property @{
  ServerName=$ServerName;
  Name="-";
  Letter="-";
  Label="-";
  Type="TOTAL";
  ClusterSize="-";
  Indexing="-";
  BootVolume="-";
  FileSystem="-";
  Swap="-";
  TotalSize=$SizeTotal;
  UsedSpace=($SizeTotal-$FreeTotal);
  FreeSpace=$FreeTotal;
  TotalSizeH=Format-FileSize $SizeTotal;
  UsedSpaceH=Format-FileSize ($SizeTotal-$FreeTotal);
  FreeSpaceH=Format-FileSize $FreeTotal;
  FreePercent=[math]::round($FreeTotal/$SizeTotal*100,0);
 }
 if ($Object) {
  $VolumeListObj | Select-Object ServerName,Letter,Label,Type,
   FileSystem,ClusterSize,Indexing,BootVolume,Swap,FreePercent,
   TotalSize,TotalSizeH,UsedSpace,UsedSpaceH,FreeSpace,FreeSpaceH,Name
 } else {
  write-starline "*"
  write-centered ("Total",$VolumeListObj[-1].TotalSizeH," | Free ",$VolumeListObj[-1].FreeSpaceH,"(",$VolumeListObj[-1].FreePercent,"% )") "Magenta"
  write-starline "*"
 }
}
Function Get-DriveInfo {
 if ( ! (Assert-IsCommandAvailable "Get-disk") ) {
  Get-CimInstance win32_diskdrive | Select-Object Model,Name,SerialNumber,InterfaceType,FirmwareRevision,Manufacturer
 } else {
  # get-disk | Select-Object Number,Model,PartitionStyle,HealthStatus,BusType,UniqueIdFormat,FirmwareVersion,SerialNumber,IsBoot,IsSystem,
  # Location,PhysicalSectorSize,LogicalSectorSize,NumberOfPartitions,@{Label='Size'; Expression={ if ($_.Size -gt '1') {format-FileSize $_.Size }}} | Sort-Object Number
  Get-Disk | ForEach-Object {
   $CurrentDisk=$_
   Get-Partition -DiskId $_.Path | Select-Object `
   @{Name="DiskNum"; Expression={$_.DiskNumber}},
   @{Name="PartNum"; Expression={$_.PartitionNumber}},
   # @{Name="TotalPart"; Expression={$CurrentDisk.NumberOfPartitions}},
   @{Name="Location"; Expression={$CurrentDisk.Location}},
   # @{Name="Manufacturer"; Expression={$CurrentDisk.Manufacturer}},
   @{Name="PartStyle"; Expression={$CurrentDisk.PartitionStyle}},
   @{Name="BusType"; Expression={$CurrentDisk.BusType}},
   @{Name="Letter"; Expression={$_.DriveLetter}},
   Type,
   @{Name="DiskSize"; Expression={Format-FileSize $CurrentDisk.Size}},
   @{Name="PartSize"; Expression={Format-FileSize $_.Size}},
   # @{Name="PartPercent"; Expression={($_.Size/$CurrentDisk.Size)*100}},
   @{Name="IsSystem"; Expression={$CurrentDisk.IsSystem}},
   @{Name="IsHidden"; Expression={$_.IsHidden}},
   @{Name="IsActive"; Expression={$_.IsActive}},
   @{Name="IsBoot"; Expression={$_.IsBoot}},
   @{Name="IsClustered"; Expression={$CurrentDisk.IsClustered}},
   @{Name="IsHighlyAvailable"; Expression={$CurrentDisk.IsHighlyAvailable}},
   @{Name="Model"; Expression={$CurrentDisk.Model}},
   @{Name="HealthStatus"; Expression={$CurrentDisk.HealthStatus}},
   @{Name="Status"; Expression={$CurrentDisk.OperationalStatus}},
   @{Name="PhysicalSector"; Expression={$CurrentDisk.PhysicalSectorSize}},
   @{Name="LogicalSector"; Expression={$CurrentDisk.LogicalSectorSize}},
   Offset,
   @{Name="UniqueIdFormat"; Expression={$CurrentDisk.UniqueIdFormat}},
   @{Name="UniqueID"; Expression={$CurrentDisk.UniqueID}}
  }
 }
}
Function Get-DriveRights {
 get-CimInstance win32_logicaldisk | select-object $_.DeviceID | Where-Object {$_.DriveType-eq 3 } | ForEach-Object {
  write-starline "-" ; write-centered ($_.deviceID,"(",$_.volumename,")") ; write-starline "-"
  Get-Rights( $_.deviceID+"\" )
 }
}
Function Get-Rights {

 Param (
  $path=$pwd.path,
  $highlighteduser,
  [switch]$Object
 )

 $U_Users=Get-UserFromSID 'S-1-5-32-545'
 $U_System=Get-UserFromSID 'S-1-5-18'
 $U_Administrators=Get-UserFromSID 'S-1-5-32-544'
 $U_CreatorOwner=Get-UserFromSID 'S-1-3-0'

 # while ( ! $path ) { $path = read-host "Enter path to check" }
 if ( ! ($(try {test-path $path -ErrorAction SilentlyContinue} catch {}))) {write-colored "Red" -ColoredText "Please provide a valid path. `"$path`" is not accessible" ; return}
 $objlist=@()
 get-acl $path | ForEach-Object {$_.Access} | Sort-Object | ForEach-Object {
  $obj = New-Object PSObject
  $obj | Add-Member NoteProperty ID $_.IdentityReference
  if ($_.GetType().Name -eq 'FileSystemAccessRule') { $CurrentRights=$_.FileSystemRights }
  elseif ($_.GetType().Name -eq 'RegistryAccessRule') { $CurrentRights=$_.RegistryRights }
  #Add different type of rights
  else { $CurrentRights='UNKNOWN' }
  $obj | Add-Member NoteProperty Rights $CurrentRights
  $obj | Add-Member NoteProperty Type $_.AccessControlType
  $objlist += $obj
 }

 if ($Object) {
  $objlist | ForEach-Object {
   if ($_.Type -eq "Allow") {"$($_.ID) ($($_.Rights))"} else {"$($_.ID) ($($_.Rights)) [DENIED]"}
  }
  return
 }

 $objlist | ForEach-Object {
  #$textcolor = [console]::foregroundcolor
  $textcolor = "red"
  #if ( $_.Rights -eq "FullControl" ) { $textcolor = "red" }
  #Different color for default rights
  if ( $_.ID -eq "BUILTIN\$U_Users") {if ( $_.Rights -like "ReadAndExecute*" ) {$textcolor = $defaultblue} }
  if ( $_.Rights -eq "FullControl" -and $_.ID -eq "BUILTIN\$U_Administrators" -or $_.ID -eq "NT AUTHORITY\$U_System" ) { $textcolor = "DarkGreen" }
  if ( $path -eq "C:\" ) {
   if ( $_.ID -eq "BUILTIN\$U_Users" -and ( $_.Rights -like "AppendData*" -or $_.Rights -like "CreateFiles*" ) ) {$textcolor = $defaultblue}
   if ( $_.ID -eq $U_CreatorOwner -and $_.Rights -like "268435456" ) {$textcolor = $defaultblue}
  }
  #To Highlight a specific user. Everything is black except specified user
  if ( $highlighteduser ) { if ( $_.ID -like "*"+$highlighteduser ) {$textcolor =$defaultblue} else {$textcolor = [console]::foregroundcolor} }
  if ($_.Type -eq "Allow") {
   Write-colored $textcolor "=>" ($_.ID,"(",$_.Rights,")")
  } else {
   Write-colored $textcolor "=>" ($_.ID,"(",$_.Rights,") [DENIED]")
  }
 }
}
Function Set-Rights {
 [CmdletBinding()]
 Param (
  $Path=$(Get-Location).ProviderPath,
  [Switch]$Commit,
  [Switch]$ChangeOwner,
  $SpecificOwner,
  [Switch]$PurgeNonInherited,
  [Switch]$Details,
  [ValidateSet("Ignore","Add","Remove")][string]$GlobalInheritance="Ignore",
  $User
 )

 DynamicParam {
  #Default
  $attributes = new-object System.Management.Automation.ParameterAttribute
  $attributes.Mandatory = $False
  $paramList = new-object -Type System.Management.Automation.RuntimeDefinedParameterDictionary

  ###### Rights ######
  $SetList = [System.Security.AccessControl.FileSystemRights].DeclaredFields.Name | Where-Object {! ($_ -eq "value__")}

  $ValidateSet = New-Object -Type System.Management.Automation.ValidateSetAttribute -ArgumentList $SetList
  $Collection = new-object -Type System.Collections.ObjectModel.Collection[System.Attribute]
  $Collection.Add($attributes)
  $Collection.Add($ValidateSet)

  $Param = new-object -Type System.Management.Automation.RuntimeDefinedParameter("UserRights", [string], $Collection)
  $PSBoundParameters['UserRights'] = "FullControl" #Default Value
  $paramList.Add("UserRights", $Param)

  ###### InheritanceFlags ######
  $SetList = [System.Security.AccessControl.InheritanceFlags].DeclaredFields.Name | Where-Object {! ($_ -eq "value__")}

  $ValidateSet = New-Object -Type System.Management.Automation.ValidateSetAttribute -ArgumentList $SetList
  $Collection = new-object -Type System.Collections.ObjectModel.Collection[System.Attribute]
  $Collection.Add($attributes)
  $Collection.Add($ValidateSet)

  $Param = new-object -Type System.Management.Automation.RuntimeDefinedParameter("UserInheritance", [string], $Collection)
  # Default for folders : "ContainerInherit, ObjectInherit"
  # Default for Users : "None"
  $PSBoundParameters['UserInheritance'] = "ContainerInherit, ObjectInherit" #Default Value
  $paramList.Add("UserInheritance", $Param)

  ###### PropagationFlags ######
  $SetList = [System.Security.AccessControl.PropagationFlags].DeclaredFields.Name | Where-Object {! ($_ -eq "value__")}

  $ValidateSet = New-Object -Type System.Management.Automation.ValidateSetAttribute -ArgumentList $SetList
  $Collection = new-object -Type System.Collections.ObjectModel.Collection[System.Attribute]
  $Collection.Add($attributes)
  $Collection.Add($ValidateSet)

  $Param = new-object -Type System.Management.Automation.RuntimeDefinedParameter("UserPropagationFlags", [string], $Collection)
  $PSBoundParameters['UserPropagationFlags'] = "None" #Default Value
  $paramList.Add("UserPropagationFlags", $Param)

  ###### AccessControlType ######
  $SetList = [System.Security.AccessControl.AccessControlType].DeclaredFields.Name | Where-Object {! ($_ -eq "value__")}

  $ValidateSet = New-Object -Type System.Management.Automation.ValidateSetAttribute -ArgumentList $SetList
  $Collection = new-object -Type System.Collections.ObjectModel.Collection[System.Attribute]
  $Collection.Add($attributes)
  $Collection.Add($ValidateSet)

  $Param = new-object -Type System.Management.Automation.RuntimeDefinedParameter("UserAccessControlType", [string], $Collection)
  $PSBoundParameters['UserAccessControlType'] = "Allow" #Default Value
  $paramList.Add("UserAccessControlType", $Param)

  return $paramList
 }

 End {

  $ErrorActionPreference="Stop"
  [Switch]$RequireCommit=$false

  Try {
   $CurrentFolderACL=(Get-ACL $Path)

   # Change Owner, default is builtin Admin group, or specific user can be used
   if ($ChangeOwner) {
    if ($Details) {write-host -ForegroundColor "Green" "Previous owner was $($CurrentFolderACL.Owner)"}
    if ($SpecificOwner) {
     $Group = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $SpecificOwner)
    } else {
     $Group = New-Object System.Security.Principal.NTAccount("Builtin", $(Get-UserFromSID "S-1-5-32-544"))
    }
    $CurrentFolderACL.SetOwner($Group)
    Set-ACL -Path $path -AclObject $CurrentFolderACL
    if ($Details) {write-host -ForegroundColor "Green" "Owner was changed to $($Group.Value)"}
   }

   # Get Current Rights
   # $DirectorySecurity = (Get-Item $Path).GetAccessControl('Access')
   $DirectorySecurity = (Get-ACL $Path)

   # If Purge is set remove all non inherited rights
   if ($PurgeNonInherited) {
    $RequireCommit=$true
    $DirectorySecurity.Access | ForEach-Object {$DirectorySecurity.RemoveAccessRule($_)} | Out-Null
   }

   # If User is set Add User Rights
   if ($user) {
    $RequireCommit=$true
    # If PurgeNonInherited is not set the user can only have more rights not less (Modify => FullControl OK | FullControl => Read KO)
    $Account = New-Object System.Security.Principal.NTAccount($User)
    $FileSystemRights = [System.Security.AccessControl.FileSystemRights]$PSBoundParameters['UserRights']
    $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]$PSBoundParameters['UserInheritance']
    $PropagationFlags = [System.Security.AccessControl.PropagationFlags]$PSBoundParameters['UserPropagationFlags']
    $AccessControlType =[System.Security.AccessControl.AccessControlType]$PSBoundParameters['UserAccessControlType']

    #Files cannot have ContainerInherit option. So we will change it to none if default or if set incorrectly
    if ($InheritanceFlags -eq 'ContainerInherit, ObjectInherit') {
     if ((Get-Item $Path) -is [System.IO.FileInfo]) {[System.Security.AccessControl.InheritanceFlags]$InheritanceFlags='None' }
    }

    $NewRights = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)

    $DirectorySecurity.AddAccessRule($NewRights)
   }

   # If Global Inheritance is set Add or Remove all inheritance
   if (! ($GlobalInheritance -eq 'Ignore') ) { $RequireCommit=$true }
   if ($GlobalInheritance -eq 'Add') {
    $DirectorySecurity.SetAccessRuleProtection($False,$False)
   } elseif ($GlobalInheritance -eq 'Remove') {
    $DirectorySecurity.SetAccessRuleProtection($True,$False)
   }

   # Commit Previous updates
   if ( $Commit ) {
    if ($Details) {
     Set-ACL -Path $Path -AclObject $DirectorySecurity -verbose
    } else {
     Set-ACL -Path $Path -AclObject $DirectorySecurity
    }
   } else {
    if ($RequireCommit) {
     write-host -foregroundcolor "Yellow" "***** ['commit' flag required to validate update] *****"
    }
    $DirectorySecurity | Select-Object @{name="Path";expression={$Path}},@{name="Owner";expression={$CurrentFolderACL.Owner}},AccessToString,@{name="Inheritance";expression={if ($_.AreAccessRulesProtected) {$False} else {$True}}},Access
   }

  } catch {
   write-host -foregroundcolor "Red" "Error Settings rights $Rights on folder $Path for user $User ($($Error[0]))"
  }
 }
}
# Share
Function Get-WindowsShareRights {
 Param (
  $ShareName
 )
 $ErrorActionPreference="Stop"

 #For OS 2012+
 if (get-command Get-SmbShare -ErrorAction SilentlyContinue) {
  if ($ShareName) {
   $SearchResult=Get-SmbShareAccess $_.Name
  } else {
   $SearchResult=Get-SmbShare | Get-SmbShareAccess
  }
  $SearchResult | Sort-Object Name | Select-Object Name,AccountName,AccessRight,AccessControlType
  Return
 }

 #Warning : When using method below administrative shares are ignored
 #Retrieve share information from computer
 if ($ShareName) {
  $ShareSec = Get-WmiObject -Class Win32_LogicalShareSecuritySetting | Sort-Object Name | Where-Object Name -eq $ShareName
 } else {
  $ShareSec = Get-WmiObject -Class Win32_LogicalShareSecuritySetting | Sort-Object Name
 }

 $objlist=@()

 ForEach ($Shares in $ShareSec) {
  #Try to get the security descriptor
  $SecurityDescriptor = $Shares.GetSecurityDescriptor()

  #Iterate through each descriptor
  ForEach ($DACL in $SecurityDescriptor.Descriptor.DACL) {
   #Convert the current output into something more readable
   Switch ($DACL.AccessMask) {
    2032127 {$AccessMask = "FullControl"}
    1179785 {$AccessMask = "Read"}
    1180063 {$AccessMask = "Read, Write"}
    1179817 {$AccessMask = "ReadAndExecute"}
    -1610612736 {$AccessMask = "ReadAndExecuteExtended"}
    1245631 {$AccessMask = "ReadAndExecute, Modify, Write"}
    1180095 {$AccessMask = "ReadAndExecute, Write"}
    268435456 {$AccessMask = "FullControl (Sub Only)"}
    default {$AccessMask = $DACL.AccessMask}
    }
   #Convert the current output into something more readable
   Switch ($DACL.AceType) {
    0 {$AceType = "Allow"}
    1 {$AceType = "Deny"}
    2 {$AceType = "Audit"}
   }
   #Add to existing array
   $trusteedomain=$DACL.Trustee.Domain
   if ($trusteedomain) {$trusteedomain=$trusteedomain+"\"}
   $objlist+=New-Object PSObject -Property @{Name=$Shares.Name;AccountName=$($trusteedomain+$DACL.Trustee.Name);AccessRight=$AccessMask;AccessControlType=$AceType}
  }
 }
 $objlist
}
Function Get-WindowsShareOld {
 Param (
  $ServerName
 )
 if ($ServerName) {
  $wmiresult=get-CimInstance win32_share -ComputerName $ServerName
 } else {
  $wmiresult=get-CimInstance win32_share
 }

 $wmiresult | ForEach-Object {

  if ( ! $_.Description ) {$Description="No Desc"} else {$Description=$_.Description}

  Write-Blank

  #Default admin share
  # if ( $_.Type -eq "2147483648" ) { Write-colored "darkgreen" "" ($_.Name,"(",$Description,") :",$_.Path) ; return }
  # IPC share

  if ($_.Type -eq "2147483651" ) { Write-colored "darkgreen" "" ($_.Name,"(",$Description,")") ; return }

  #Print Info
  Write-colored $defaultblue "Share Name : " ($_.Name,"(",$Description,")")

  if ($ServerName) {$dnsname=$ServerName} else {$dnsname=$env:computerName}

  $ShareFullPath="\\"+([System.Net.Dns]::GetHostByName($dnsname)).HostName+"\"+$_.Name
  Write-Colored $defaultblue "Local Path : " $_.Path
  Write-Colored $defaultblue "Remote Path : " $ShareFullPath

  #Do not try to get share info on print share
  if ( $_.Name -eq "shared_printer" -and $Description -eq "shared_printer" ) { return }

  write-colored "Black" "[NTFS Rights]"
  Get-Rights $ShareFullPath

  write-colored "Black" "[Share Rights]"
  if ($ServerName) {
   Get-WindowsShareRights -ShareName $_.Name -ServerName $ServerName
  } else {
   Get-WindowsShareRights -ShareName $_.Name
  }
 }
}
Function Get-WindowsShare {
 Param (
  $ShareName
 )
 if ($ShareName) {
  $ShareList=get-CimInstance win32_share | Where-Object Name -eq $ShareName
 } else {
  $ShareList=get-CimInstance win32_share
 }
 $FQDN="\\"+([System.Net.Dns]::GetHostByName($env:computerName)).HostName+"\"

 $FullResult=@()

 $ShareList | ForEach-Object {

  $ShareRights=Get-WindowsShareRights $_.Name | ForEach-Object {
   if ($_.AccessControlType -eq "Allow") {
    "$($_.AccountName) ($($_.AccessRight))"
   } else {
    "$($_.AccountName) ($($_.AccessRight))[DENIED]"
   }
  }

  $FullResult+=[pscustomobject]@{
   Name=$_.Name
   Description=$_.Description
   Path=$_.Path
   FullPath=$FQDN+$_.Name
   NTFSRights=if ($_.Path) {Get-Rights ( $_.Path ) -Object} else {"N/A"}
   ShareRights=$ShareRights
  }
 }
 return $FullResult
}

# CopyManagement
Function CopyWithBITS {
 Param (
  [Parameter(Mandatory=$true)]$Source,
  [Parameter(Mandatory=$true)]$Destination
 )
 # Warning : Will not work with a user that is not logged in interactive mode :
 # https://docs.microsoft.com/en-us/windows/desktop/Bits/using-windows-powershell-to-create-bits-transfer-jobs
 #Remove PS Progress Bar
 # $ProgressPreference='SilentlyContinue'

 if ( ! (test-path $Source)) {
  write-Colored "Red" -ColoredText "Unavailable source path : $Source"
  return
 }

 Try {
  $FullPath=(Resolve-Path $Source -ErrorAction Stop).ProviderPath
  write-colored "Green" -ColoredText "Using path : $FullPath"
 } catch {
  write-Colored "Red" -ColoredText "Error finding full path"
 }

 Import-Module BitsTransfer

 Get-ChildItem -Path $FullPath -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSisContainer} | ForEach-Object {
  $CurrentFolder = $_.BaseName
  $spath = $_.FullName.Replace($FullPath,'')
  $C_SRC="$FullPath$spath"
  $C_DST="$Destination$spath"
  # $C_DST="$Destination"
  # write-host "$C_SRC To $C_DST"
  Progress "Currently copying " ($C_SRC,"To",$C_DST)
  New-Item -Type Directory $C_DST -Force | Out-Null
  try {
   Start-BitsTransfer -Source $C_SRC\*.* -Destination $C_DST -ErrorAction Stop -Description "Copying $C_SRC to $C_DST" -DisplayName "Current Folder `'$CurrentFolder`'"
  } Catch {
  write-Colored "Red" -ColoredText $Error[0]
  }
 }
 ProgressClear
 Start-BitsTransfer $FullPath\*.* $Destination
}

# SCCM
Function Get-SCCMSiteCode {
 Param (
  $SCCMCODE,
  $SERVERNAME=$env:COMPUTERNAME
 )
 try {
  if ( ! $SCCMCODE ) { ($([WmiClass]"\\$SERVERNAME\ROOT\ccm:SMS_Client").getassignedsite()).sSiteCode }
  else { ($([WmiClass]"\\$SERVERNAME\ROOT\ccm:SMS_Client").SetAssignedSite($SCCMCODE)) | Out-Null}
 } catch { return $false }
}
Function Get-SCCMInfo {
 if ( ! (Get-SCCMSiteCode) ) {$color="red" ; $sitecode="N/A"} else {$color=$defaultblue ; $sitecode=(Get-SCCMSiteCode)}
 $alignsize=20
 write-colored $color (Align "SCCM Site Code" $alignsize " : ") $sitecode
 try {
  $SCCMVersion=(Get-CimInstance -ErrorAction "Stop" -Namespace root\ccm -Class SMS_Client).clientversion
  $color=$defaultblue
 } catch {
  $SCCMVersion="SCCM Client not installed"
  $color="red"
 }
 write-colored $color (Align "SCCM Client Version" $alignsize " : ") $SCCMVersion
}

# License Management
Function Set-WindowsLicense {
 Param (
  $computer = $env:computername,
  $key
 )
 if (((Get-ActivationStatus).Status -eq "Licensed")) {write-host -foregroundcolor Green "$computer is already activated" ; return}
 if (! ($key)) {write-host -foregroundcolor Red "A key is mandatory" ; return}
 if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
  $service = Get-CimInstance "SoftwareLicensingService" -computername $computer
  Invoke-CimMethod -InputObject $service -MethodName InstallProductKey -Arguments @{ProductKey=$key}
 } else {
  $service = Get-WmiObject -query "select * from SoftwareLicensingService" -computername $computer
  $service.InstallProductKey($key) | Out-Null
  $service.RefreshLicenseStatus() | Out-Null
 }
 if (((Get-ActivationStatus).Status -ne "Licensed")) {write-host -foregroundcolor Red "$computer is not activated" ; return}
}

# Kaspersky
Function Get-KasperskyStatus {
 Param (
  $KasperskyPath="${env:ProgramFiles(x86)}\Kaspersky Lab\NetworkAgent\"
 )
 if ( ! (Assert-IsAdmin) ) {Write-Colored "red" -ColoredText "You must be admin to run this command" ; return}
 if ( ! (test-path $KasperskyPath)) { write-Colored "Red" -ColoredText "Unavailable path : $KasperskyPath" ; return }

 $command=$KasperskyPath+"klnagchk.exe"
 & $command
}
Function Set-KasperskyServer {
 Param (
  [Parameter(Mandatory=$true)]$ServerIP, # Kaspersky Serveur IP
  $KasperskyPath="C:\Program Files (x86)\Kaspersky Lab\NetworkAgent\"
 )
 if ( ! (Assert-IsAdmin) ) {Write-Colored "red" -ColoredText "You must be admin to run this command" ; return}
 if ( ! (test-path $KasperskyPath)) { write-Colored "Red" -ColoredText "Unavailable path : $KasperskyPath" ; return }

 $command=$KasperskyPath+"klmover.exe"
 &$command -address $ServerIP
}
Function Set-KasperskyCert {
 Param (
  $CertLocation="C:\Temp\klserver.cer",
  $KasperskyPath="C:\Program Files (x86)\Kaspersky Lab\NetworkAgent\"
 )
 # Cert location on server %ALLUSERSPROFILE%\Application Data\KasperskyLab\adminkit\1093\cert
 if ( ! (Assert-IsAdmin) ) {Write-Colored "red" "" "You must be admin to run this command" ; return}
 if ( ! (test-path $KasperskyPath)) { write-Colored "Red" "" "Unavailable path : $KasperskyPath" ; return }

 $command=$KasperskyPath+"klmover.exe"
 &$command -cert $CertLocation
}
Function Update-KasperskyDatabase {
 param(
  $S_Name=$env:COMPUTERNAME,
  $logfile=$([environment]::GetEnvironmentVariable("temp","machine"))+'\kes_std.log',
  $avpPath="${env:ProgramFiles(x86)}\Kaspersky Lab\Kaspersky Endpoint Security *\",
  $TaskName="Workstation - Install"
 )
 Invoke-Command -ErrorAction Stop -computername $S_Name -ArgumentList $logfile,$avpPath,$TaskName -ScriptBlock {
  $logfile=$args[0]
  $avpPath=$args[1]
  $TaskName=$args[2]
  start-process -WorkingDirectory $avpPath -FilePath "$avpPath\avp.com" -ArgumentList "status" -NoNewWindow -Wait -RedirectStandardOutput $logfile
  $UpdateName=(get-content $logfile | Select-String $TaskName).Line.Trim().split()[0]
  if ($UpdateName) {
   start-process -WorkingDirectory $avpPath -FilePath "$avpPath\avp.com" -ArgumentList "start $UpdateName" -NoNewWindow -Wait -RedirectStandardOutput $logfile
   get-content $logfile
  } else {
   write-host -foregroundcolor "Red" "Error while checking for task name"
  }
 }
}
Function Connect-Kaspersky { #Connect to the API
 Param (
  $KLUser=$env:USERNAME,
  $KLDomain=$env:USERDOMAIN,
  [Parameter(Mandatory=$true)]$KLServer, #Kaspersky ServerName
  [Parameter(Mandatory=$true)]$KLServerFull #Kaspersky FQDN
 )

 $ErrorActionPreference='Stop'

 $KLUserEncoded=Convert-StringToBase64UTF8 $KLUser
 $KLPassword=$(read-host -AsSecureString "Enter $KLUser password")
 $KLPasswordEncoded=Convert-StringToBase64UTF8 $(ConvertFrom-SecureString $KLPassword -AsPlainText)
 $KLDomainEncoded=Convert-StringToBase64UTF8 $KLDomain

 #Not Used :
 $KLServerEncoded=Convert-StringToBase64UTF8 $KLServer

 $url = "https://$($KLServerFull):13299/api/v1.0/login"
 $Authentheaders = @{
 "Authorization" = "KSCBasic user=`"$KLUserEncoded`", pass=`"$KLPasswordEncoded`", domain-str=`"$KLDomainEncoded`", internal=`"0`""
 "Content-Type" = "application/json"
 "Accept-Encoding" = "gzip, deflate"
# "X-KSC-VServer" = $KLServerEncoded
 # "Content-Length" = 2
 }
 Try {
  $ReturnValue=Invoke-WebRequest -Method POST -Uri $url -SkipCertificateCheck -Header $Authentheaders -SessionVariable 'Session'
  if ($ReturnValue.StatusCode -eq '200') {return $Session} else {Return $ReturnValue.RawContent}
 } Catch {
  Write-Host -ForegroundColor Red $Error[0]
 }
}

# Protocol & Cipher
Function Get-Protocols {
 $ProtocolList = [enum]::GetNames([Net.SecurityProtocolType])
 $ProtocolList | ForEach-Object {
  $Protocol=$_
  if ($Protocol -eq 'SystemDefault') {return}
  $ProtocolFolder=switch ($Protocol) {
   Ssl2 {"SSL 2.0"}
   Ssl3 {"SSL 3.0"}
   tls {"TLS 1.0"}
   tls11 {"TLS 1.1"}
   tls12 {"TLS 1.2"}
   tls13 {"TLS 1.3"}
   default {"Unknown"}
  }
  if ($ProtocolFolder -eq "Unknown") {write-host -ForegroundColor Red "$Protocol is unknown, please check" ; return}
  $S_RegKey="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ProtocolFolder\Server"
  $C_RegKey="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ProtocolFolder\Client"
  $S_ForcedEnabled = Try {(get-ItemProperty -path $S_RegKey -Name "Enabled" -ErrorAction Stop).Enabled} catch {"Default"}
  $S_ForceDisabled = Try {(Get-ItemProperty -path $S_RegKey -Name "DisabledByDefault" -ErrorAction Stop).DisabledByDefault} catch {"Default"}
  $C_ForcedEnabled = Try {(get-ItemProperty -path $C_RegKey -Name "Enabled" -ErrorAction Stop).Enabled} catch {"Default"}
  $C_ForceDisabled = Try {(Get-ItemProperty -path $C_RegKey -Name "DisabledByDefault" -ErrorAction Stop).DisabledByDefault} catch {"Default"}
 [pscustomobject]@{Name="$Protocol";REG="$ProtocolFolder";Server_Enabled=$S_ForcedEnabled;Server_DisabledByDefault=$S_ForceDisabled;Client_Enabled=$C_ForcedEnabled;Client_DisabledByDefault=$C_ForceDisabled}
 }
}
Function Get-Cipher {
  #Starting with Windows 10 or Windows 2016 we can use Disable-TlsCipherSuite / Get-CipherSuite
  $AdvancedCmdLine=$(get-command Get-TlsCipherSuite -ErrorAction SilentlyContinue)
  if ($AdvancedCmdLine) {
   $CipherListFull=(Get-TlsCipherSuite).Name
  } else {
   $CipherListFull=(Get-ItemProperty -ErrorAction Stop -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002' -Name 'Functions').Functions
   $CipherListToReplace=$CipherListFull
  }
  #Print Cipher List
  $CipherListFull
}
Function Update-ProtocolsAndCipher {
 Param (
  $ProtocolToDisable=@("PCT 1.0","SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1"),
  $CipherToDisable=@("*RC4*","*MD5*","*3DES*"),
  [Switch]$DisableClientProtocol,
  [switch]$NoQuestion
 )
 write-host -ForegroundColor Magenta "[PROTOCOLS]"

 $ProtocolToDisable | ForEach-Object {
  $Protocol=$_
  #Server
  $RegKey="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
  try {
   New-Item -ErrorAction STOP -force $RegKey | out-null
   Set-ItemProperty -path $RegKey -Name "Enabled" -Value "0" -Type DWord
   Set-ItemProperty -path $RegKey -Name "DisabledByDefault" -Value "1" -Type DWord
   write-host -foregroundcolor "DarkGreen" "Protocol $protocol disabled (Server)"
  } catch {
   write-host -foregroundcolor "Red" "Protocol $protocol not disabled (Server) - $($Error[0])"
  }
  # (Do not disable the client part as this will remove the possibility to use it to connect to other system)
  if ($DisableClientProtocol) {
   #Client
   $RegKey="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client"
   try {
    New-Item -ErrorAction STOP -force $RegKey | out-null
    Set-ItemProperty -path $RegKey -Name "Enabled" -Value "0" -Type DWord
    Set-ItemProperty -path $RegKey -Name "DisabledByDefault" -Value "1" -Type DWord
    write-host -foregroundcolor "DarkGreen" "Protocol $protocol disabled (Client)"
   } catch {
    write-host -foregroundcolor "Red" "Protocol $protocol not disabled (Client) - $($Error[0])"
   }
  }
 }

 write-host -ForegroundColor Magenta "[CIPHERS]"

 #Init Var
 $CipherListToRemove=@()
 $CipherListToReplace=@()
 [Boolean]$Marker=$False

 #Starting with Windows 10 or Windows 2016 we can use Disable-TlsCipherSuite / Get-CipherSuite
 $AdvancedCmdLine=$(get-command Get-TlsCipherSuite -ErrorAction SilentlyContinue)

 #To test old method:
 # $AdvancedCmdLine=""

 write-host -ForegroundColor DarkGreen "Current Cipher List"
 if ($AdvancedCmdLine) {
  $CipherListFull=(Get-TlsCipherSuite).Name
 } else {
  $CipherListFull=(Get-ItemProperty -ErrorAction Stop -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002' -Name 'Functions').Functions
  $CipherListToReplace=$CipherListFull
 }
 #Print Cipher List
 $CipherListFull

 $CipherToDisable | ForEach-Object {
  $Cipher=$_
  write-host -foregroundcolor "DarkGreen" "Checking cipher `'$Cipher`' : " -NoNewline
  if ($CipherListFull | Where-Object {$_ -like "$Cipher"}) {
   write-host -foregroundcolor "DarkYellow" "Cipher will be removed"
   $Marker=$True
   if ($AdvancedCmdLine) {
    $CipherListToRemove += $CipherListFull | Where-Object {$_ -like "$Cipher"}
   } else {
    $CipherListToReplace = $CipherListToReplace -split "," | Where-Object {$_ -notlike $Cipher}
   }
  } else {
   write-host -foregroundcolor "Cyan" "Cipher not present"
  }
 }

 if (! $Marker) {
  write-host -ForegroundColor "Green" "Nothing to do"
 } else {
  if ($AdvancedCmdLine) {
   write-host -ForegroundColor "Yellow" "Following Cipher will be removed"
   $CipherListToRemove
  } else {
   write-host -ForegroundColor "Yellow" "Cipher list will be replaced by the following"
   $CipherListToReplace
  }
  #Add manual validation
  if (! $NoQuestion) {
   write-host
   # Ask for validation
   $Answer=Question "Please confirm the action" "0"
   if (! $Answer) {write-host -foregroundcolor "Yellow" "Canceled" ; return}
  }
  Try {
   if ($AdvancedCmdLine) {
    $CipherListToRemove | ForEach-Object {
     write-host -foregroundcolor "DarkGreen" "Removing cipher $($_)"
     Disable-TlsCipherSuite $_ -ErrorAction SilentlyContinue
    }
   } else {
    # Update Cipher Suite
    $CipherListToReplace=$CipherListToReplace -join(',')
    Set-ItemProperty -ErrorAction Stop -Force -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002' -name 'Functions' -value $CipherListToReplace | Out-Null
   }
  } catch {
   write-host -foregroundcolor "Red" $error[0]
  }
 }
}

# Remote
Function RunRemoteWMI {
 Param (
  $server=$($env:COMPUTERNAME),
  $processName = 'notepad'
 )
 #Run app remotely using WMI
 $Arguments=@{
  CommandLine=$processName;
  CurrentDirectory = $null;
 }
 $process = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments $Arguments -ComputerName $server
 write-host "Return value : $($process.ReturnValue) | PID : $($process.ProcessID)"
}
Function RunLocalWMI {
 Param (
  $command = "notepad.exe"
 )
 #Run app localy using WMI
 $process = [WMICLASS]"\\$($env:computername)\ROOT\CIMV2:win32_process"
 $result = $process.Create($command)
 write-host "Return value : $($result.ReturnValue)"
}
Function RunRemotePS {
 Param (
  $server=$($env:computername),
  $processName = 'notepad',
  [PSCredential]$credential
 )
 if ($credential) {
   $remoteSession = New-PSSession -ComputerName $server -credential $credential
  } else {
   $remoteSession = New-PSSession -ComputerName $server
  }
 $command = 'Start-process ' + $processName + ';'
 Invoke-Command -Session $remoteSession -ScriptBlock  ([ScriptBlock]::create($command))
}
Function Remote {
 Param (
  $ComputerName,
  $Port,
  [PSCredential]$Credential,
  [switch]$ForceNewSession=$false,
  [Switch]$CredSSP,
  [Switch]$UseSSL,
  [Switch]$IgnoreCACheck, #For SSL With Autosigned)
  $SessionTimeout="00:00:05",
  $PsVersion
 )
 try {

 # If port is not set then use default port depending on SSL or not.
 if (! $Port) { if ($UseSSL) { $Port = 5986 } else { $Port = 5985 } }

  # PsVersion : To check available PS version on remote : (Get-PSSessionConfiguration).Name
  # To register other PS Version : Enable-PSRemoting
  # To remove older PS Version : Unregister-PSSessionConfiguration PowerShell.7.0.0-rc.2
  # To install New PS Version : Install-Powershell

  #Set Defaults Options
  $SessionOption=New-PSSessionOption
  $SessionOption.MaximumConnectionRedirectionCount=1
  $SessionOption.OperationTimeout=$SessionTimeout
  $SessionOption.OpenTimeout=$SessionTimeout
  $SessionOption.CancelTimeout=$SessionTimeout

  #For SSL with self signed certificates
  if ($IgnoreCACheck) { $SessionOption.SkipCACheck=$true }

  if (! $ForceNewSession) {
   #BUG : when using -Computername does not work with non admin session (?)
   # $SessionID=$(Get-PSSession -ComputerName $ComputerName -State 'Opened' -ErrorAction SilentlyContinue | Sort-Object ID | Select-Object -Last 1)
   $SessionID=$(Get-PSSession -ErrorAction SilentlyContinue | Where-Object {($_.ComputerName -eq $ComputerName) -and ($_.State -eq "Opened")} | Sort-Object ID | Select-Object -Last 1)
   if ($SessionID) {
    write-host -foregroundcolor "Cyan" "Using existing connexion (use -ForceNewSession to force new session)"
    Enter-PSSession -ErrorAction Stop $SessionID ; return
   }
  }

  $PSSessionParams = @{
   ErrorAction = "Stop" ;
   ComputerName = $ComputerName ;
   Port = $Port ;
   SessionOption = $SessionOption ;
  }

  if ($PsVersion) {$PSSessionParams.Add("ConfigurationName",$PsVersion)}
  if ($Credential) {$PSSessionParams.Add("credential",$Credential)}
  #CredSSP Allows Second Hop (network access from remote session) but requires credential - Also requires FQDN
  if ($CredSSP) {
   if (! $Credential) {throw "Credentials are mandatory for CredSSP"}
   $PSSessionParams.Add("Authentication","CredSSP")
  }
  if ($UseSSL) {$PSSessionParams.Add("UseSSL",$True)}

  #Create Connection
  $session = New-PSSession @PSSessionParams

  Invoke-Command -ErrorAction Stop -FilePath $profile.AllUsersAllHosts -Session $session
  Enter-PSSession -ErrorAction Stop -Session $session
 } catch {
  write-host -foregroundcolor "Red" $Error[0]
 }
}
Function Send-RemoteCommand {
 Param (
  $ComputerName,
  $CommandLine,
  $SessionTimeout="00:00:05",
  $ScriptSourcePath=$profile.AllUsersAllHosts
 )
 if (! (Test-Path $ScriptSourcePath)) {
  New-Item -ItemType file $ScriptSourcePath
 }
 $ErrorActionPreference = 'Stop'
 Try {
  $SessionOption=New-PSSessionOption
  $SessionOption.MaximumConnectionRedirectionCount=1
  $SessionOption.OperationTimeout=$SessionTimeout
  $SessionOption.OpenTimeout=$SessionTimeout
  $SessionOption.CancelTimeout=$SessionTimeout

  $session = New-PSSession -ComputerName $ComputerName -SessionOption $SessionOption
  invoke-Command -FilePath $ScriptSourcePath -Session $session
  invoke-Command -Session $session -ArgumentList $CommandLine -ScriptBlock { Invoke-Expression $Args[0] }
  Remove-PSSession $session
 } Catch {
  write-host -ForegroundColor 'Red' "Error on computer $ComputerName : $($Error[0])"
 }
}

# VMware
Function Get-VMLic {
 Param (
  [Parameter(Mandatory=$true)]$vCenterServer # vCenter FQDN
 )
 $vCenterConnexion=$global:defaultviserver
 if (! $vCenterConnexion) {
  $vCenterConnexion=connect-VIServer $vCenterServer -Protocol https -WarningAction silentlyContinue
 }
 (Get-View licensemanager).licenses | Select-Object Name,LicenseKey,Total,Used,
  @{Name="Label";Expression={$_.Labels | Select-Object -expand Value}},
  @{Name="ExpirationDate";Expression={$_.Properties  | Where-Object { $_.key -eq "expirationDate" } | Select-Object -ExpandProperty Value }},
  @{Name="Features";Expression={ ($_.Properties | Where-Object { $_.key -eq "feature" } | Select-Object -ExpandProperty Value).value -join "," }}
}
Function Get-VMAutoUpdateStatus {
 Param (
  $VMName,
  [Parameter(Mandatory=$true)]$vCenterServer # vCenter FQDN
 )
 $vCenterConnexion=$global:defaultviserver
 if (! $vCenterConnexion) {
  $vCenterConnexion=connect-VIServer $vCenterServer -Protocol https -WarningAction silentlyContinue
 }
 if ($VMName) {
  Get-VM $VMName | Get-View | Select-Object Name,@{N='ToolsUpgradePolicy';E={$_.Config.Tools.ToolsUpgradePolicy } }
 } else {
  Get-VM | Get-View | Select-Object Name,@{N='ToolsUpgradePolicy';E={$_.Config.Tools.ToolsUpgradePolicy } }
 }
}
Function Set-VMToolsAutoUpdate {
 Param (
  $VMName,
  [ValidateSet('upgradeAtPowerCycle','Manual')]$Status='Manual',
  [Parameter(Mandatory=$true)]$vCenterServer # vCenter FQDN
 )
 $vCenterConnexion=$global:defaultviserver
 if (! $vCenterConnexion) {
  $vCenterConnexion=connect-VIServer $vCenterServer -Protocol https -WarningAction silentlyContinue
 }
 try {
  if (! $VMName) {throw "VM Name is required"}
  $VMConfig = Get-View -VIObject (Get-VM $VMName) -ErrorAction Stop
  $vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
  $vmConfigSpec.Tools = New-Object VMware.Vim.ToolsConfigInfo
  $vmConfigSpec.Tools.ToolsUpgradePolicy = $Status
  $VMConfig.ReconfigVM($vmConfigSpec)
 } catch {
  write-host -foregroundcolor "Red" $Error[0]
 }
}
Function Set-VMToolsSyncTime {
 Param (
  $VMName,
  [switch]$Enable=$false,
  [Parameter(Mandatory=$true)]$vCenterServer # vCenter FQDN
 )
 $vCenterConnexion=$global:defaultviserver
 if (! $vCenterConnexion) {
  $vCenterConnexion=connect-VIServer $vCenterServer -Protocol https -WarningAction silentlyContinue
 }
 try {
  if (! $VMName) {throw "VM Name is required"}
  $VMConfig = Get-View -VIObject (Get-VM $VMName) -ErrorAction Stop
  $vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
  $vmConfigSpec.Tools = New-Object VMware.Vim.ToolsConfigInfo
  $vmConfigSpec.Tools.SyncTimeWithHost = $Enable
  $VMConfig.ReconfigVM($vmConfigSpec)
 } catch {
  write-host -foregroundcolor "Red" $Error[0]
 }
}
Function Connect-vCenter {
 Param (
  [Parameter(Mandatory=$true)]$vCenterServer, # vCenter FQDN
  [Switch]$Verbose
 )
 $vCenterConnexion=$global:defaultviserver
 if (! $vCenterConnexion) {
  $vCenterConnexion=connect-VIServer $vCenterServer -Protocol https -WarningAction silentlyContinue
 }
 if ($Verbose) {Return $vCenterConnexion}
}

# Captures
Function Get-BufferContentToTxt {
 #Must clear window before function and must send the output to a file (>file.txt)
 if ($host.Name -ne "ConsoleHost"){ write-host -ForegroundColor Red "This script runs only in the console host. You cannot run this script in $($host.Name)." ; exit -1}

 # Initialize string builder.
 $textBuilder = new-object system.text.stringbuilder
 # Grab the console screen buffer contents using the Host console API
 $bufferWidth = $host.ui.rawui.BufferSize.Width
 $bufferHeight = $host.ui.rawui.CursorPosition.Y
 $rec = new-object System.Management.Automation.Host.Rectangle 0,0,($bufferWidth - 1),$bufferHeight
 $buffer = $host.ui.rawui.GetBufferContents($rec)
 # Iterate through the lines in the console buffer.
 for($i = 0; $i -lt $bufferHeight; $i++) {
  for($j = 0; $j -lt $bufferWidth; $j++) { $cell = $buffer[$i,$j] ; $null = $textBuilder.Append($cell.Character) }
  $null = $textBuilder.Append("`r`n")
 }
 return $textBuilder.ToString()
}
Function Get-ConsoleBuffer {
 # Found but heavily modified from http://blogs.msdn.com/b/powershell/archive/2009/01/11/colorized-capture-of-console-screen-in-html-and-rtf.aspx
 # Usage example : clear ; Get-CheckListWindows ; Get-ConsoleBuffer -full -preview
 #region header
 param (
  [string]$Path = "$env:temp\$($env:computername)-console-$(Get-Date -uformat '%Y%m%d').",
  [switch]$Full,
  [switch]$Preview,
  [bool]$_boolFull = $false,
  [bool]$_boolPreview = $false
 );
 #endregion
 #region html functions
 Function Set-HtmlColor ($color) {
  # The Windows PowerShell console host redefines DarkYellow and DarkMagenta colors and uses them as defaults.
 # The redefined colors do not correspond to the color names used in HTML, so they need to be mapped to digital color codes.
  if ($color -eq "DarkYellow") { "#eeedf0"; }
  elseif ($color -eq "DarkMagenta") { "#012456"; }
  else { $color; }
 }
 Function Add-HtmlSpan ($Text, $ForegroundColor = "DarkYellow", $BackgroundColor = "DarkMagenta") {
  $ForegroundColor= Set-HtmlColor $ForegroundColor;
  $BackgroundColor= Set-HtmlColor $BackgroundColor;
  $node = $script:xml.CreateElement("span");
  $node.SetAttribute("style", "font-family:Courier New;color:$ForegroundColor;background:$backgroundColor");
  $node.InnerText = $text;
  $script:xml.LastChild.AppendChild($node) | Out-Null;
 }
 Function Add-HtmlBreak { $script:xml.LastChild.AppendChild($script:xml.CreateElement("br")) | Out-Null; }
 #endregion

 #region core code

 # Check the host name and exit if the host is not the Windows PowerShell console host.
 if ($host.Name -ne "ConsoleHost") { Write-Warning "$((Get-Variable -ValueOnly -Name MyInvocation).MyCommand)runs only in the console host. You cannot run this script in $($Host.Name)."; return; }

 # handle [switch] parameters in nested functions
 if (!$Full) { $Full = $_boolFull; }
 if (!$Preview) { $Preview = $_boolPreview; }

 # initialize document name and object
 [xml]$script:xml = "<pre style='MARGIN: 0in 10pt 0in;line-height:normal' />";
 $Path += "html";

 # Grab the console screen buffer contents using the Host console API.
 $bufferWidth = $Host.UI.RawUI.BufferSize.Width
 $bufferHeight = $Host.UI.RawUI.CursorPosition.Y

 # Line at which capture starts is either top of buffer or top of window.
 if ($Full) { $startY = 0; } elseif (($startY -eq $bufferHeight - $Host.UI.RawUI.WindowSize.Height) -lt 0) { $startY = 0; }

 $rec = New-Object System.Management.Automation.Host.Rectangle 0,$startY,($bufferWidth - 1),$bufferHeight
 $buffer = $Host.UI.RawUI.GetBufferContents($rec);

 # Iterate through the lines in the console buffer.
 for($i = 0; $i -lt $bufferHeight; $i++) {
  $stringBuilder = New-Object System.Text.StringBuilder;

  # Track the colors to identify spans of text with the same formatting.
  $currentForegroundColor = $buffer[$i, 0].ForegroundColor;
  $currentBackgroundColor = $buffer[$i, 0].BackgroundColor;

  for($j = 0; $j -lt $bufferWidth; $j++) {
   $cell = $buffer[$i,$j];
   # If the colors change, generate an HTML span and append it to the HTML string builder.
   if (($cell.ForegroundColor -ne $currentForegroundColor) -or ($cell.BackgroundColor -ne $currentBackgroundColor)) {
    Add-HtmlSpan -Text $stringBuilder.ToString() -ForegroundColor $currentForegroundColor -BackgroundColor $currentBackgroundColor;
    # Reset the span builder and colors.
    $stringBuilder = New-Object System.Text.StringBuilder;
    $currentForegroundColor = $cell.ForegroundColor;
    $currentBackgroundColor = $cell.BackgroundColor;
   }
   $stringBuilder.Append($cell.Character) | Out-Null;
  }
  Add-HtmlSpan -Text $stringBuilder.ToString() -ForegroundColor $currentForegroundColor -BackgroundColor $currentBackgroundColor;
  Add-HtmlBreak;
 }

 & { $script:xml.OuterXml; } | Out-File -FilePath $Path -Encoding ascii;

 #Write name or Open file
 if (Test-Path -Path $Path) { if ($Preview) { <#Invoke-Item $Path#>; Invoke-Item $(($Path -split("\\") |Select-Object -skiplast 1) -join '\') } ; Write-StarLine ; write-centered $Path; Write-StarLine} else { Write-Warning "Unable to save to -Path $Path"; }
 #endregion
}

# Tweak Windows
Function Remove-Windows10NonEnterpriseApps {
 $ApplistOnline = Get-AppXProvisionedPackage -online
 $Applist = Get-AppxPackage -AllUsers
 $AppToRemove=@("3DBuilder","MicrosoftSolitaireCollection","MicrosoftOfficeHub","OneNote","OneConnect",
                "WindowsFeedbackHub","Xbox","Print3D","SkypeApp","Microsoft3DViewer","Microsoft.People","StorePurchaseApp",
                "BingWeather","windowscommunicationsapps","WindowsMaps","Messaging","Wallet","ZuneMusic","ZuneVideo",
                "MixedReality.Portal","Sway","NetworkSpeedTest","BingNews","OfficeLens","Microsoft.YourPhone")
 # Ignore Package 'Microsoft.XboxGameCallableUI' since it cannot be removed
 $AppToIgnore=@("Microsoft.XboxGameCallableUI")
 $AppToRemove | ForEach-Object {
  $App=$_
  $ApplistOnline | Where-Object {$_.packagename -like "*$App*"} | ForEach-Object {
   try {
    write-Colored -Color "cyan" -NonColoredText "Removing Provisionned Package : " -ColoredText $_.PackageName -filepath $LogPath
    $_ | Remove-AppxProvisionedPackage -online | Out-Null
   } catch {
    write-Colored -Color "Red" -NonColoredText "App $App `: " -ColoredText $($error[0]) -filepath $LogPath
   }
  }
  $Applist | where-object {$_.name -like "*$App*"} | ForEach-Object {
   try {
    write-Colored "cyan" -NonColoredText "Removing Appx Package : " -ColoredText $_.Name -filepath $LogPath
    if (! $AppToIgnore.Contains($_.Name)) { Remove-AppxPackage $_ -AllUsers | Out-Null }
   } catch {
    write-Colored -Color "Red" -NonColoredText "Appx $App `: " -ColoredText $($error[0]) -filepath $LogPath
   }
  }
 }
}
Function Disable-Windows10UnusedServices {
 Get-Service | Where-Object {($_.Name -eq "OneSyncSvc") -or ($_.Name -eq "CDPUserSvc") -or ($_.Name -eq "MapsBroker") -or ($_.Name -eq "CDPSVC") } | Stop-Service -PassThru | Set-Service -StartupType Manual
 Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc*\" -Name Start -Value 4 | Out-Null
 set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc*\" -Name Start -Value 4 | Out-Null
}
Function Disable-Windows10Prefetch {
 Try { Set-RegKey "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" "0" "DWord"} catch {write-host -foregroundcolor "red" $error[0]}
 Try {Set-Service -ErrorAction "Stop" -Name "SysMain" -DisplayName "superfetch" -Status "Stopped" -StartupType "Manual"} catch {write-host -foregroundcolor "red" $error[0]}
}
Function Set-REGModsUser {
 $HKEYExplorer = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
 $HKEYExplorerAdvanced="$HKEYExplorer\Advanced"
 $ThumbsKey="HKCU:\Software\Policies\Microsoft\Windows\Explorer"

 #Disable Thumbs.db on network folders
 New-Item -force $ThumbsKey | Out-Null
 Set-ItemProperty $ThumbsKey DisableThumbsDBOnNetworkFolders 1 | Out-Null

 #Folder Options
 Set-ItemProperty $HKEYExplorerAdvanced Hidden 1
 Set-ItemProperty $HKEYExplorerAdvanced HideFileExt 0
 Set-ItemProperty $HKEYExplorerAdvanced ShowSuperHidden 1
 Set-ItemProperty $HKEYExplorerAdvanced SeparateProcess 1
 Set-ItemProperty $HKEYExplorerAdvanced HideFileExt 0
 Set-ItemProperty $HKEYExplorerAdvanced Start_ShowRun 1
 Set-ItemProperty $HKEYExplorerAdvanced Start_ShowSetProgramAccessAndDefaults 0
 Set-ItemProperty $HKEYExplorerAdvanced LaunchTo 1

 #Disable ShortcutTo on new shortcut
 Set-ItemProperty $HKEYExplorer -Name "link" -Value ([byte[]](0x00,0x00,0x00,0x00))

 #Show All icons in tray
 Set-ItemProperty $HKEYExplorer EnableAutoTray 0

 #Lock Taskbar
 Set-ItemProperty $HKEYExplorerAdvanced TaskbarSizeMove 0
}
Function Set-REGModsMachine {
 if ( ! (Assert-IsAdmin) ) {Write-Colored "red" "" "You must be admin to run this command" ; return}
 #Enable FastBoot
 Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" HiberbootEnabled 1
 #Disable Screensaver
 Disable-ScreenSaver
 #Enable Verbose startup/shutdown
 $RegKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
 Set-ItemProperty -force -path $RegKey -Name "VerboseStatus" -Value "1" -Type DWord | Out-Null
}
Function Set-REGModsMachineRemoveMyPCFolders {
#64Bits Remove All User Folders In This PC
#Music
remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}]"
remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}]"
#Downloads
remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}]"
remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}]"
#Pictures
remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}]"
remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}]"
#Videos
remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}]"
remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}]"
#Documents
remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}]"
remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}]"
#Desktop
remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}]"
remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}]"
}
Function Set-REGModsMachineDisableAdminShares {
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" LocalAccountTokenFilterPolicy 1
}
Function Clear-IconCache {
 Stop-Process explorer.exe
 Remove-Item $Env:LOCALAPPDATA\IconCache.db
 Remove-Item $Env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache*
}
Function Update-TimeZone {

 $Tmp_TimeZone=(Get-TimeZone).DisplayName
 write-host "Current TimeZone : [$Tmp_TimeZone] | $(get-date)"
 $Tmp_Value=read-host "Press enter to keep current any other key to update timezone"
 if (!($Tmp_Value)) {return}

 $TimeZoneList=Get-TimeZone -ListAvailable
 Write-StarLine "-"
 $Count=0 ; $TimeZoneList | ForEach-Object {write-host "[$Count] - $($_.DisplayName)" ; $Count++}
 Write-StarLine "-"
 $Tmp_Value=read-host "TimeZone | Enter ID [*] of timezone"

 if (!($Tmp_Value)) {return}

 $Tmp_TimeZone=$TimeZoneList[$Tmp_Value]
 if (! $Tmp_TimeZone) {write-host -foregroundcolor "red" "Value not found" ; return}

 Write-StarLine
 Write-Host -foregroundcolor "Cyan" "This key will be used : $($Tmp_TimeZone.DisplayName)"
 $Answer=read-host "Press 'Y' to confirm above information, any other key will cancel the process"
 Write-StarLine
 if ($Answer -eq "Y") {Set-TimeZone -ID $Tmp_TimeZone.ID}
}
Function Set-MemoryDump {
 Param(
 [ValidateSet("Full","None","Small","Kernel","Auto")][String]$DumpType="None"
 )
 switch ($DumpType) {
   "None" {$D_Type="0"; break}
   "Full" {$D_Type="1"; break}
   "Kernel" {$D_Type="2"; break}
   "Small" {$D_Type="3"; break}
   "Auto" {$D_Type="7"; break}
 }
 wmic RECOVEROS set DebugInfoType = $D_Type | out-null
 wmic RECOVEROS set AutoReboot = true | out-null
}
Function Set-FirewallRules {
 Configure-SMRemoting.exe -Enable | Out-Null
 Set-NetFirewallRule -DisplayGroup "Remote Event Log Management" -Enabled True -PassThru | Out-Null
 # Set-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' -Enabled true -PassThru | Out-Null
 Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True -PassThru | Out-Null
}
Function Enable-PowerSettingsUnhideAll {
 if (!$IsLinux -and !$IsMacOS) {
  # Unlock Power Plans by disabling "Connected Standby"
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'CSEnabled' -Value 0 -Force

  # Unlock hidden options
  $PowerSettings = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings' -Recurse -Depth 1 | Where-Object { $_.PSChildName -NotLike 'DefaultPowerSchemeValues' -and $_.PSChildName -NotLike '0' -and $_.PSChildName -NotLike '1' }
  ForEach ($item in $PowerSettings) { $path = $item -replace "HKEY_LOCAL_MACHINE","HKLM:"; Set-ItemProperty -Path $path -Name 'Attributes' -Value 2 -Force }
 }
}
Function Set-RDPNLA {
 if ( ! (Assert-IsAdmin) ) {Write-Colored -Color "red" -ColoredText "You must be admin to run this command" ; return}
 #Only ticks checkbox (if available)
 Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value "0" | Out-Null
 Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
 if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
  $RDPClass=Get-CimInstance -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
  Invoke-CimMethod -InputObject $RDPClass -MethodName SetEncryptionLevel -Arguments @{MinEncryptionLevel=4} | Out-Null
  Invoke-CimMethod -InputObject $RDPClass -MethodName SetSecurityLayer -Arguments @{SecurityLayer=2} | Out-Null
  Invoke-CimMethod -InputObject $RDPClass -MethodName SetUserAuthenticationRequired -Arguments @{UserAuthenticationRequired=1} | Out-Null
 } else {
  (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)
  #Modifies all RDP-TCP Configuration
  $RegKey="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal*Server\WinStations\RDP-TCP\"
  Set-RegKey $RegKey "MinEncryptionLevel" "4" "DWord"
  Set-RegKey $RegKey "UserAuthentication" "1" "DWord"
  Set-RegKey $RegKey "SecurityLayer" "2" "DWord"
 }
}
Function Set-NumlockOnStart {
 New-PSDrive HKU Registry HKEY_USERS |Out-Null
 Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -Value 2
}
Function Disable-NetbiosAndLMHostSearch {
 #Disable LMhostSearch
 $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters"
 Set-ItemProperty -Path "$regkey\" -Name EnableLMHOSTS -Value 0
 #Disable Netbios
 # Using Reg :
 # Get-ChildItem "$regkey\Interfaces" |ForEach-Object {
 #  Set-ItemProperty -Path "$regkey\Interfaces\$($_.pschildname)" -Name NetbiosOptions -Value 2
 # }
 # Using CIM
 Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -or ($_.TcpipNetbiosOptions -eq 0)} | ForEach-Object {
   Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null
 }
}
Function ConfigureMemoryDump {
 wmic RECOVEROS set DebugInfoType = 0 | out-null
 wmic RECOVEROS set AutoReboot = true | out-null
}
Function Enable-RDP {
 Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value "0" | Out-Null
 Enable-NetFirewallRule -DisplayGroup "Remote Desktop" | Out-Null
 (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1) | Out-Null
}
Function Disable-PSTelemetry {
 [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT','1',"Machine")
}
Function Clear-Windows {
 $DwordList = @(
  "Active Setup Temp Folders",
  "BranchCache",
  "Content Indexer Cleaner",
  "D3D Shader Cache",
  "Delivery Optimization Files",
  "Device Driver Packages",
  "Diagnostic Data Viewer database files",
  "Downloaded Program Files",
  "Internet Cache Files",
  "Language Pack",
  "Offline Pages Files",
  "Old ChkDsk Files",
  "Previous Installations",
  "Recycle Bin",
  "Service Pack Cleanup",
  "Setup Log Files",
  "System error memory dump files",
  "System error minidump files",
  "Temporary Files",
  "Temporary Setup Files",
  "Temporary Sync Files",
  "Thumbnail Cache",
  "Update Cleanup",
  "Upgrade Discarded Files",
  "User file versions",
  "Windows Defender",
  "Windows Error Reporting Files",
  "Windows ESD installation files",
  "Windows Upgrade Log Files")

 $SourceRegKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
 $DwordList | ForEach-Object {
  $RegKey=$SourceRegKey+$_
  New-Itemproperty $RegKey -PropertyType "DWord" -Name 'StateFlags0666' -Value 2
 }
 #Add removal for all non selected values
 Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:666' -WindowStyle Hidden -Wait
}
Function Set-MSDTC {
 $RegKey="HKLM:\Software\Microsoft\MSDTC\"
 Set-RegKey $RegKey "AllowOnlySecureRpcCalls" "0" "DWord"
 Set-RegKey $RegKey "FallbackToUnsecureRPCIfNecessary" "0" "DWord"
 Set-RegKey $RegKey "TurnOffRpcSecurity" "1" "DWord"

 $RegKey="HKLM:\Software\Microsoft\MSDTC\Security\"
 Set-RegKey $RegKey "NetworkDtcAccess" "1" "DWord"
 Set-RegKey $RegKey "NetworkDtcAccessClients" "1" "DWord"
 Set-RegKey $RegKey "NetworkDtcAccessAdmin" "1" "DWord"
 Set-RegKey $RegKey "XaTransactions" "1" "DWord"
 Set-RegKey $RegKey "NetworkDtcAccessTransactions" "1" "DWord"
 Set-RegKey $RegKey "NetworkDtcAccessInbound" "1" "DWord"
 Set-RegKey $RegKey "NetworkDtcAccessOutbound" "1" "DWord"
 Set-RegKey $RegKey "LuTransactions" "1" "DWord"

 Restart-Service -displayname "Distributed Transaction Coordinator"
}
Function Get-MSDTC {
 $MSDTC_Security=Get-ItemProperty "HKLM:\Software\Microsoft\MSDTC\Security" 2> $null

 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccess "Network DTC Access"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessClients "Client And Administration | Allow Remote Clients"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessAdmin "Client And Administration | Allow Remote Administration"
 Format-TypeMSDTC $MSDTC_Security.XaTransactions "Enable XA Transactions"
 Format-TypeMSDTC $MSDTC_Security.LuTransactions "Enable SNA LU 6.2 Transactions"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessTransactions "Transaction Manager Communication"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessInbound "Transaction Manager Communication | Allow Inbound"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessOutbound "Transaction Manager Communication | Allow Outbound"

 $MSDTC=Get-ItemProperty "HKLM:\Software\Microsoft\MSDTC" 2> $null

 $NoAuthenticatioNRequired=1
 if ( $MSDTC.AllowOnlySecureRpcCalls ) {$NoAuthenticatioNRequired=$NoAuthenticatioNRequired-1}
 if ( $MSDTC.FallbackToUnsecureRPCIfNecessary ) {$NoAuthenticatioNRequired=$NoAuthenticatioNRequired-1}
 if ( ! $MSDTC.TurnOffRpcSecurity ) {$NoAuthenticatioNRequired=$NoAuthenticatioNRequired-1}
 Format-TypeMSDTC $NoAuthenticatioNRequired "Transaction Manager Communication | No Authentication Required"
}
Function Set-DCOMUsers {
 # Add 'System' and 'Network Service' to 'Distributed COM Users'
 Add-LocalGroupMember -Group $(Get-UserFromSID 'S-1-5-32-562') -Member $(Get-UserFromSID 'S-1-5-18'),$(Get-UserFromSID 'S-1-5-20')
}
Function Remove-PublicDesktopIcons {
 Remove-Item $Env:PUBLIC\Desktop\*
}

# PowerManagement
Function Set-Powersettings {
 Param (
  $SettingsGUID="8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
 )
 #To find High Perf GUID:
 # (powercfg  /l | Select-String "High performance").ToString().split(" ")[3]
 powercfg /s $SettingsGUID
}
Function Get-Powersettings {
 $plan = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "isActive='true'"
 $regex = [regex]"{(.*?)}$"
 $planGuid = $regex.Match($plan.instanceID.Tostring()).groups[1].value
 powercfg -query $planGuid
}
Function Get-PowerSettingsAdvanced {
 # Created from https://gist.github.com/raspi/203aef3694e34fefebf772c78c37ec2c
 # List all possible Power Options
 # To UnHide an Option : powercfg -attributes $ID -ATTRIB_HIDE
 Get-CimInstance -ClassName Win32_PowerSetting -Namespace root\cimv2\power | Select-Object ElementName,@{name="ID";expression={$_.InstanceID.split("\")[1] -replace '}','' -replace '{',''}},Description | Sort-Object ElementName
}

#Sound
Function Set-Speaker {
 Param (
  $Volume,
  [switch]$ToggleMute
 )
 $wshShell = new-object -com wscript.shell;1..50 | ForEach-Object {
  $wshShell.SendKeys([char]174)
 };1..$Volume | ForEach-Object {
  $wshShell.SendKeys([char]175)
 }
 if ($ToggleMute) {
  $wshShell = new-object -com wscript.shell;$wshShell.SendKeys([char]173)
 }
}

# Office Tools
Function Save-ExcelToCSV {
 Param (
  $FileName
 )
 $excelApp = New-Object -ComObject Excel.Application
 $excelApp.DisplayAlerts = $false
 $workbook = $excelApp.Workbooks.Open($FileName)
 $NewFilePath = $FileName -replace "\.xlsx$", ".csv"
 $workbook.SaveAs($NewFilePath, [Microsoft.Office.Interop.Excel.XlFileFormat]::xlCSV)
 $workbook.Close()
}
Function Save-CSVToExcel {
 Param (
  $FileName
 )
 #Name management
 $FullPath=(Get-Item $FileName).FullName
 $BaseName=(Get-Item $FileName).BaseName
 $NewFilePath = $FullPath -replace "\.csv$", ".xlsx"

 $excelApp = New-Object -ComObject Excel.Application
 $excelApp.DisplayAlerts = $false

 #To Show the windows and what is happening:
 # $excelApp.Visible = $true

 # CANNOT USE THIS AS IT WILL OPEN AS DEFAULT:
 # $workbook = $excelApp.Workbooks.Open($FullPath)

 #Create new workbook
 $workbook = $excelApp.Workbooks.Add(1)
 $worksheet = $workbook.worksheets.Item(1)

 #Change Worksheet Name
 $worksheet.Name = $BaseName

 ### Build the QueryTables.Add command
 ### QueryTables does the same as when clicking "Data » From Text" in Excel
 $TxtConnector = ("TEXT;" + $FullPath)
 $Connector = $worksheet.QueryTables.add($TxtConnector,$worksheet.Range("A1"))
 $query = $worksheet.QueryTables.item($Connector.name)

 ### Set the delimiter (, or ;) according to your regional settings
 ### $Excel.Application.International(3) = ,
 ### $Excel.Application.International(5) = ;
 $query.TextFileOtherDelimiter = $excelApp.Application.International(5)

 ### Set the format to delimited and text for every column
 ### A trick to create an array of 2s is used with the preceding comma
 # $query.TextFileParseType  = 1
 # $query.TextFileColumnDataTypes = ,2 * $worksheet.Cells.Columns.Count
 $query.AdjustColumnWidth = 1

 ### Execute & delete the import query
 $query.Refresh()
 $query.Delete()

 $workbook.SaveAs($NewFilePath,51)
 $workbook.Close()
}

#Keycloak
Function Get-KeycloakToken {
 Param (
  [Parameter(Mandatory=$true)]$ClientID,
  [Parameter(Mandatory=$true)]$ClientSecret,
  [Parameter(Mandatory=$true)]$KeycloakURL,
  $Realm = 'master'
 )
 Try {
  $RequestFullURL = "https://$KeycloakURL/auth/realms/$Realm/protocol/openid-connect/token"
  $postParams = @{client_id=$ClientID;grant_type="client_credentials";client_secret=$ClientSecret}
  $Web_Response = Invoke-WebRequest -Uri $RequestFullURL -Method Post -Body $postParams -ErrorAction Stop
  return ($Web_Response.Content | ConvertFrom-Json).access_token
 } catch {
  Write-host -ForegroundColor 'Red' $Error[0]
 }
}
Function Get-KeycloakRealms {
 Param (
  [Parameter(Mandatory=$true)]$KeycloakURL,
  [Parameter(Mandatory=$true)]$BearerToken,
  $MaxAnswers = '20000'
 )
 (Invoke-WebRequest -Uri  "https://$KeycloakURL/auth/admin/realms?max=$MaxAnswers" -Method Get -header @{Authorization = "Bearer $BearerToken"}).Content | ConvertFrom-Json | Sort-Object ID
}
Function Get-KeycloakValue {
 Param (
  [Parameter(Mandatory=$true)]$KeycloakURL,
  $Realm = 'master',
  $MaxAnswers = '20000',
  [Parameter(Mandatory=$true)]$BearerToken,
  [Parameter(Mandatory=$true)]$Request
 )
 (Invoke-WebRequest -Uri "https://$KeycloakURL/auth/admin/realms/$Realm/$Request`?max=$MaxAnswers" -Method Get -header @{Authorization = "Bearer $BearerToken"}).Content | ConvertFrom-Json
}
Function Set-KeycloakValue {
 Param (
  [Parameter(Mandatory=$true)]$KeycloakURL,
  $Realm = 'master',
  $MaxAnswers = '20000',
  [Parameter(Mandatory=$true)]$BearerToken,
  [Parameter(Mandatory=$true)]$Request
 )
 #To be tested
 (Invoke-WebRequest -Uri "https://$KeycloakURL/auth/admin/realms/$Realm/$Request" -Method POST -header @{Authorization = "Bearer $BearerToken"}).Content
}
Function Remove-KeycloakValue {
 Param (
  [Parameter(Mandatory=$true)]$KeycloakURL,
  $Realm = 'master',
  $MaxAnswers = '20000',
  [Parameter(Mandatory=$true)]$BearerToken,
  [Parameter(Mandatory=$true)]$Request
 )
 #To be tested
 (Invoke-WebRequest -Uri "https://$KeycloakURL/auth/admin/realms/$Realm/$Request" -Method Delete -header @{Authorization = "Bearer $BearerToken"}).Content
}
Function Get-KeycloakValueForAllUsers {
 Param (
  [Parameter(Mandatory=$true)]$KeycloakURL,
  $Realm = 'master',
  [Parameter(Mandatory=$true)]$BearerToken,
  $MaxAnswers = '20000',
  [Parameter(Mandatory=$true)]$UserRequest
 )

 # TO DO : TRIM ON ALL VALUES

 #GenerateUserList
 $UserList = Get-KeycloakValue -KeycloakURL $KeycloakURL -BearerToken $BearerToken -Realm $Realm -Request "users" -MaxAnswers $MaxAnswers
 $UserList | ForEach-Object {
  #Request
  $CurrentValue = Get-KeycloakValue -KeycloakURL $KeycloakURL -BearerToken $BearerToken -Realm $Realm -Request "users/$($_.id)/$UserRequest"
  #Add Keycloak UserName and GUID
  $CurrentValue | Add-Member -MemberType NoteProperty "UserNameKC" -value $($_.username.Trim())
  $CurrentValue | Add-Member -MemberType NoteProperty "GUID" -value $($_.ID.Trim())
  $CurrentValue | Select-Object identityProvider,GUID,UserNameKC,@{Label="UserID";Expression={$_.userId.Trim()}},@{Label="UserName";Expression={$_.userName.Trim()}}
 }
}
Function Get-KeyCloakRolesFromID { #Get All Assigned Role from Users or Service Account
 Param (
  [Parameter(Mandatory=$true)]$KeyCloakID,
  [Parameter(Mandatory=$true)]$KeycloakURL,
  $Realm = 'master',
  [Parameter(Mandatory=$true)]$BearerToken,
  [ValidateSet("User","ServiceAccount")]$TypeOfClient = "User"
 )

 #Check Client
 if ($TypeOfClient -eq "User") {
  $ClientInfo = Get-KeycloakValue -KeycloakURL $KeycloakURL -Realm $Realm -BearerToken $BearerToken -Request users/$KeyCloakID

  $ClientName = $ClientInfo.username
  $ClientMail = $ClientInfo.email
  $UserID = $ClientInfo.ID
 } elseif ($TypeOfClient -eq "ServiceAccount") {
  $ClientInfo = Get-KeycloakValue -KeycloakURL $KeycloakURL -Realm $Realm -BearerToken $BearerToken -Request clients/$KeyCloakID
  # Find Hidden user:
  $HiddenAccount = Get-KeycloakValue -KeycloakURL $KeycloakURL -Realm $Realm -BearerToken $BearerToken -Request clients/$KeyCloakID/service-account-user

  $ClientName = $ClientInfo.clientId
  $ClientMail = "-"
  $UserID = $HiddenAccount.ID
 }
 $ClientMappings = Get-KeycloakValue -KeycloakURL $KeycloakURL -Realm $Realm -BearerToken $bearertoken -Request "users/$UserID/role-mappings"

 # GetDetailed Info :
 $DetailedRights = ($ClientMappings.clientMappings | get-member -Type NoteProperty).Name | ForEach-Object {
  $CurrentMappingName = $_
  $ClientMappings.clientMappings.$CurrentMappingName | select-object @{Label='Name';Expression={$CurrentMappingName}},@{Label='Rights';Expression={$_.mappings.Name -join ","}}
 }
  #Create Object
  $GlobalClientRights = @()
  $ClientMappings.realmMappings | ForEach-Object {
   $GlobalClientRights+=[pscustomobject]@{KeycloakURL=$KeycloakURL;Realm=$Realm;ClientName=$ClientName;ClientMail=$ClientMail;ClientID=$UserID;RightsName="RealmMappings";Rights=$_.name}
  }
  $DetailedRights | ForEach-Object {
   $GlobalClientRights+=[pscustomobject]@{KeycloakURL=$KeycloakURL;Realm=$Realm;ClientName=$ClientName;ClientMail=$ClientMail;ClientID=$UserID;RightsName=$_.Name;Rights=$_.Rights}
  }
  $GlobalClientRights
}

# KPI Active Directory
Function Get-KPIADComputer {
 Param (
  $Path="C:\Temp\KPI\"
 )
 Function IsOSServerOrWorkstation ($TypeOfOS,$OU) {
  if ((! $TypeOfOS) -or ($TypeOfOS -eq "unknown")) {return "Unknown"
  } elseif ( ($TypeOfOS.contains("Server")) -or ($TypeOfOS -eq "Samba") ) {return "Server"
  } else { return "Workstation" }
 }

 if ( ! (test-path $Path)) { write-Colored "Red" -ColoredText "Unavailable path : $Path" ; return }

 $StartDate=$(get-date -uformat "%Y-%m-%d %T")

 get-adcomputer -filter * -properties * | Select-Object Name,@{name="FQDN";expression={Progress "Checking Computer: " "$($_.DNSHostName)";$_.DNSHostName}},
  @{name="OU";expression={$_.CanonicalName | ForEach-Object {(($_ -split('/'))| Select-Object -skiplast 1) -join '/'}}},
  @{name="Enabled";expression={ if ($_.Enabled) {"TRUE"} else {"FALSE"} }},
  ObjectClass,OperatingSystem,IPv4Address,
  @{name="whenChanged";expression={Format-Date $_.whenChanged}},
  @{name="whenCreated";expression={Format-Date $_.whenCreated}},
  @{name="LastLogonDate";expression={Format-Date $_.LastLogonDate}} | Select-Object *,
  @{name="TypeOS";expression={IsOSServerOrWorkstation $_.OperatingSystem $_.OU}},
  @{name="BitlockerKeyLastCreation";expression={$Date=(Get-BitLockerKeyInAD -ServerName $_.Name | Select-Object -Last 1).Created;if ($Date){Format-Date $Date}}} `
  | Export-Csv "$Path\ComputerList-$(get-date -uformat '%Y-%m-%d').csv"  -encoding "unicode" -notypeinformation -Delimiter ";"
 ProgressClear
 write-host
 $EndDate=$(get-date -uformat "%Y-%m-%d %T")
 $Duration=(New-TimeSpan -Start $StartDate -End $EndDate)
 write-colored "Green" -ColoredText "$($MyInvocation.MyCommand) Finished in $Duration"
}
Function Get-KPIADUser {
 Param (
  $Path="C:\Temp\KPI\"
 )
 if ( ! (test-path $Path)) { write-Colored "Red" -ColoredText "Unavailable path : $Path" ; return }

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
 write-colored "Green" -ColoredText "$($MyInvocation.MyCommand) Finished in $Duration"
}
# KPI WSUS
Function Get-KPIWsus {
 Param (
  [Parameter(Mandatory=$true)]$WsusServersADGroup,
  $Path="C:\Temp\KPI"
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
 write-colored "Green" -ColoredText "$($MyInvocation.MyCommand) Finished in $Duration"

 write-host
 return $OutputFileWSUS
}
Function Get-KPIWsusFull {
 Param (
  [Parameter(Mandatory=$true)]$WsusServersADGroup,
  $Path = "C:\Temp\KPI"
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
 write-colored "Green" -ColoredText "$($MyInvocation.MyCommand) Finished in $Duration"

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
 $Path="C:\Temp\KPI",
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
 $Path="C:\Temp\KPI",
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
  $Path="C:\Temp\KPI",
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
 $Path="C:\Temp\KPI",
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
 $ResultFile = "C:\Temp\LinuxStatus.csv",
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

# Install APP (Generic Functions)
Function Add-ToPath {
 Param (
  [Parameter(Mandatory=$true)]$PathToAdd,
  $logfile
 )
 if (Assert-IsAdmin) {
  Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Adding $PathToAdd to Environnment Variable PATH (System - Persistent)" -FilePath $logfile
  Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Path variable before update" -FilePath $logfile
  $([Environment]::GetEnvironmentVariable('PATH', "MACHINE")) -split ";"
  $FullEnvPath="$([Environment]::GetEnvironmentVariable('PATH','MACHINE'));$PathToAdd"
  [Environment]::SetEnvironmentVariable("PATH", $FullEnvPath, "MACHINE")
  Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Path variable after update" -FilePath $logfile
  $([Environment]::GetEnvironmentVariable('PATH', "MACHINE")) -split ";"
  } Else {
   if ($([Environment]::GetEnvironmentVariable('PATH', "USER")).contains($PathToAdd)) {
    Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "$PathToAdd is already in PATH" -FilePath $logfile
  } else {
   Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Adding $PathToAdd to Environnment Variable PATH (User - $($Env:UserName) - Persistent)" -FilePath $logfile
   Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Path variable before update" -FilePath $logfile
   $([Environment]::GetEnvironmentVariable('PATH', "USER")) -split ";"
   $FullEnvPath="$([Environment]::GetEnvironmentVariable('PATH',"USER"));$PathToAdd"
   [Environment]::SetEnvironmentVariable("PATH", $FullEnvPath, "USER")
   Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Path variable after update" -FilePath $logfile
   $([Environment]::GetEnvironmentVariable('PATH', "USER")) -split ";"
  }
 }
 Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Adding $PathToAdd to Environnment Variable (CurrentSession)"
 if ($Env:path -notlike "*$PathToAdd*") {
  $Env:path += ";$PathToAdd"
 }
}
Function Install-MSI { #Generic MSI Installer with logs
 Param (
  [Parameter(Mandatory=$true)]$MsiPath,
  [switch]$Remove=$false
 )
 $ErrorActionPreference="Stop"

 try {
  if ( ! $(test-path $MsiPath) ) { throw "Path unavailable : $MsiPath" }
  $DataStamp = get-date -uformat "%Y%m%d-%H%M"
  $MsiFileName=[System.IO.Path]::GetFileNameWithoutExtension($MsiPath)
  $logFile = $("$env:SystemRoot\Temp")+"\"+$MsiFileName+"-"+$DataStamp+".log"
  if ($Remove) {$InstallOrRemove="x"} else {$InstallOrRemove="i"}
  $MSIArguments = @(
   "/$InstallOrRemove"
   ('"{0}"' -f $MsiPath)
   "/qn"
   "/norestart"
   "/L*"
   $logFile
  )
  Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

  write-output "$(get-date -uformat '%Y-%m-%d %T') - Install OK Check Log"

  Get-Content $logFile | Select-String "MSI \(s\)" | Out-String
 } catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-MSIRemote { #Copy and Install a MSI on a remote computer
 Param(
  [Parameter(Mandatory=$true)]$ServerName,
  [Parameter(Mandatory=$true)]$MSIPath,
  $TempPath='C:\Temp\'
 )

 $ErrorActionPreference="Stop"

 try {
  Write-Colored -Color Cyan -PrintDate -ColoredText "Retrieving MSI file Name from path"
  $MsiFileName=[System.IO.Path]::GetFileName($MsiPath)
  Write-Colored -Color Cyan -PrintDate -ColoredText "MSI Short Name : $MsiFileName"
  Write-Colored -Color Cyan -PrintDate -ColoredText "Opening PSSession to $ServerName"
  $ServerSessionID=New-PSSession -ComputerName $ServerName -Name $ServerName
  Write-Colored -Color Cyan -PrintDate -ColoredText "Sending remote command to $ServerName : Create Temp Folder"
  Invoke-Command -ErrorAction Stop -Session $ServerSessionID -ArgumentList $TempPath -ScriptBlock {
   new-item -type directory $Args[0] -ErrorAction SilentlyContinue | Out-Null
  }
  Write-Colored -Color Cyan -PrintDate -ColoredText "Copying files from MSIPath to Path $TempPath on $ServerName"
  $progressPreference = 'silentlyContinue'
  Copy-Item $MSIPath -ToSession $ServerSessionID -Destination $TempPath -Force
  Write-Colored -Color Cyan -PrintDate -ColoredText "Running install of $MsiFileName on $ServerName"
  Invoke-command -ErrorAction Stop -Session $ServerSessionID -ScriptBlock ${function:Install-MSI} -ArgumentList $($TempPath+$MsiFileName)
  Write-Colored -Color Cyan -PrintDate -ColoredText "Closing PS Session $ServerName"
  Remove-PSSession $ServerSessionID
 } catch {
  Write-Colored -Color Red -PrintDate -ColoredText "ERROR : $($Error[0])"
  Remove-PSSession $ServerSessionID
 }
}

# Install APP (UserMode)
Function Install-VsCode { # Download and install latest VSCode [User version] (Non Admin) [EXE]
 $FileName = Get-FileFromURL "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user"
 Invoke-Expression  "& { ./$FileName  /VERYSILENT /NORESTART /MERGETASKS=!runcode }"
}
Function Install-GIT { # Download and install latest GIT [User version] (Non Admin) [EXE]
 Param (
  $InstallDestination="C:\Apps\Git"
 )
 try {
  $DownloadLink = ((Invoke-WebRequest https://git-scm.com/download/win).links | Where-Object { ($_ -like  "*64-bit*") -and ($_ -notlike "*Portable*") }).href
  $SetupFileName = Get-FileFromURL $DownloadLink -OutputFile 'Git.exe'
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Invoke-Expression  "& { ./$SetupFileName /verysilent /Log /suppressmsgboxes /norestart /forcecloseapplications /restartapplications /lang=EN /dir='$InstallDestination' }"
  Remove-Item $SetupFileName
  Add-ToPath "$InstallDestination\cmd"
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-StorageExplorer { # Download and install latest Storage Explorer (Non Admin) [EXE]
 Param (
  $InstallDestination="C:\Apps\StorageExplorer"
 )
 try {
  $DownloadLink = "https://go.microsoft.com/fwlink/?LinkId=708343&clcid=0x409"
  $SetupFileName = Get-FileFromURL $DownloadLink -OutputFile 'StorageExplorer.exe'
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Invoke-Expression  "& { .\$SetupFileName /VERYSILENT /SUPPRESSMSGBOXES /FORCECLOSEAPPLICATIONS /LANG=US /CURRENTUSER /NORESTART /LOG=$InstallDestination\StorageExplorerInstall.log /dir='$InstallDestination' }"
  Remove-Item $SetupFileName
  Add-ToPath "$InstallDestination"
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-KubeCTL { # Download and 'install' latest KubeCTL - Add Binary to PATH [EXE]
 Param (
  $InstallDestination="C:\Apps\Kubectl"
 )
 $logfile = "$InstallDestination\Kubectl_Install.log"
 Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Getting latest version number" -FilePath $logfile
 $CurrentVersionNumber=$(Invoke-WebRequest 'https://storage.googleapis.com/kubernetes-release/release/stable.txt' -ErrorAction Stop -TimeoutSec 1 -UseBasicParsing).Content.Trim()

 Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Downloading latest version" -FilePath $logfile
 $FileName=Get-FileFromURL https://storage.googleapis.com/kubernetes-release/release/$CurrentVersionNumber/bin/windows/amd64/kubectl.exe

 Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Creating Folder" -FilePath $logfile
 new-item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null

 Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Move file to destination" -FilePath $logfile
 Move-Item $FileName $InstallDestination -force -ErrorAction Stop

 Add-ToPath -PathToAdd $InstallDestination -logfile $logfile

 if (Assert-IsAdmin) {
 Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Adding to Environnment Variable Kubectl_HOME (System - Persistent)" -FilePath $logfile
 [Environment]::SetEnvironmentVariable("Kubectl_HOME", $InstallDestination, "MACHINE")
 } Else {
  Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Adding to Environnment Variable Kubectl_HOME (User - $($Env:UserName) - Persistent)" -FilePath $logfile
  [Environment]::SetEnvironmentVariable("Kubectl_HOME", $InstallDestination, "USER")
 }
 Write-Colored -Color "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Adding to Environnment Variable (CurrentSession)" -FilePath $logfile
 $Env:Kubectl_HOME=$InstallDestination
}
Function Install-Terraform { # Download and 'install' latest Terraform - Add Binary to PATH [ZIP]
 Param (
  $InstallDestination="C:\Apps\Terraform"
 )
 # $LatestTerraformVersion = (Invoke-WebRequest "https://api.github.com/repos/hashicorp/terraform/releases/latest"  | ConvertFrom-Json).name -replace ("v","")
 # $DownloadLink = "https://releases.hashicorp.com/terraform/$LatestTerraformVersion/terraform_$LatestTerraformVersion`_windows_amd64.zip"
 $DownloadLink = ((Invoke-WebRequest https://www.terraform.io/downloads.html ).links | Where-Object { $_ -like  "*windows_amd64.zip*" }).href
 try {
  Get-FileFromURL $DownloadLink -OutputFile 'terraform.zip'
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path 'terraform.zip' -DestinationPath $InstallDestination -Force
  Remove-Item 'terraform.zip'
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-OpenJDK { # Download and 'install' latest OpenJDK - Add Binary to PATH [ZIP]
 Param (
  $InstallDestination="C:\Apps\OpenJDK"
 )
 $LatestBuild = ((Invoke-WebRequest https://openjdk.java.net/).links | Where-Object { $_ -like  "*/jdk.java.net/*" }).href
 $DownloadLink = ((Invoke-WebRequest $LatestBuild).Links | Where-Object {$_ -like "*windows-x64_bin.zip`"*"}).href
 try {
  Get-FileFromURL $DownloadLink -OutputFile 'OpenJDK.zip'
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path 'OpenJDK.zip' -DestinationPath $InstallDestination -Force
  Remove-Item 'OpenJDK.zip'
  $LatestFolder = Get-ChildItem $InstallDestination -Directory | Sort-Object LastWriteTime | Select-Object -Last 1
  Move-Item $LatestFolder\* $InstallDestination -Force
  Remove-Item $InstallDestination\jdk-* -Recurse
  Add-ToPath "$InstallDestination\bin"
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-Putty { # Download and 'install' latest Putty Suite - Add Binary to PATH [ZIP]
 Param (
  $InstallDestination="C:\Apps\Putty"
 )
 $DownloadLink = "https://the.earth.li/~sgtatham/putty/latest/w64/putty.zip"
 try {
  Get-FileFromURL $DownloadLink -OutputFile 'putty.zip'
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path 'putty.zip' -DestinationPath $InstallDestination -Force
  Remove-Item 'putty.zip'
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }

}
Function Install-K9S { # Download and 'install' latest K9S - Add Binary to PATH [TGZ] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\k9s"
 )
 $RootURL = "https://github.com"
 $DownloadLink = $RootURL + ((Invoke-WebRequest $RootURL/derailed/k9s/releases/latest).links | Where-Object { $_ -like  "*Windows_x86_64*" }).href
 try {
  Get-FileFromURL $DownloadLink -OutputFile 'k9s_Windows_x86_64.tar.gz'
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  tar -xvf 'k9s_Windows_x86_64.tar.gz' --directory $InstallDestination\
  Remove-Item 'k9s_Windows_x86_64.tar.gz'
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-FFMpeg { # Download and 'install' latest FFMpeg - Add Binary to PATH [ZIP] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\FFmpeg"
 )

 $RootURL = "https://github.com"
 $ProductName = "ffmpeg"

 $DownloadLink = $RootURL + ((Invoke-WebRequest $RootURL/BtbN/$ProductName-Builds/releases/latest).links | Where-Object { $_ -like "*$ProductName-n[0-9]*win64-gpl-shared*" }).href

 try {
  Get-FileFromURL $DownloadLink -OutputFile "$ProductName.zip"
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path "$ProductName.zip" -DestinationPath $InstallDestination -Force
  Remove-Item "$ProductName.zip"
  Move-Item $InstallDestination\$ProductName*\* $InstallDestination\ -Force
  Remove-Item $InstallDestination\$ProductName*\
  Add-ToPath $InstallDestination\bin
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-Robo3T { # Download and 'install' latest Robo3T - Add Binary to PATH [ZIP] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\Robo3T"
 )

 $ProductName = "robomongo"
 $ProductNameAlternative = "Robo3t"
 $RootURL = "https://github.com"

 $DownloadLink = $RootURL + ((Invoke-WebRequest $RootURL/Studio3T/$ProductName/releases/latest).links | Where-Object { $_ -like "*$ProductNameAlternative-*.zip*" }).href

 try {
  Get-FileFromURL $DownloadLink -OutputFile "$ProductName.zip"
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path "$ProductName.zip" -DestinationPath $InstallDestination -Force
  Remove-Item "$ProductName.zip"
  Move-Item $InstallDestination\$ProductNameAlternative*\* $InstallDestination\ -Force
  Remove-Item $InstallDestination\$ProductNameAlternative-*\
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-ShareX { # Download and 'install' latest ShareX - Add Binary to PATH [ZIP] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\ShareX"
 )
 $RootURL = "https://github.com"
 $ProductName = "ShareX"

 $DownloadLink = $RootURL + ((Invoke-WebRequest $RootURL/ShareX/$ProductName/releases/latest).links | Where-Object { ($_ -like  "*portable.zip*") -and ($_ -notlike  "*sha256*") }).href
 try {
  Get-FileFromURL $DownloadLink -OutputFile "$ProductName.zip"
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path "$ProductName.zip" -DestinationPath $InstallDestination -Force
  Remove-Item "$ProductName.zip"
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-MongoDBCompass { # Download and 'install' latest ShareX - Add Binary to PATH [ZIP] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\MongoDBCompass"
 )
 $RootURL = "https://github.com"
 $ProductName = "MongoDBCompass"

 $DownloadLink = $RootURL + ((Invoke-WebRequest $RootURL/mongodb-js/compass/releases/latest).links | Where-Object { ($_ -like  "*mongodb-compass-*-win32-x64.zip*") -and ($_ -notlike  "*isolated*") -and ($_ -notlike  "*readonly*")}).href
 Get-FileFromURL $DownloadLink -OutputFile "$ProductName.zip"
 Expand-Archive -Path "$ProductName.zip" -DestinationPath $InstallDestination -Force
 Remove-Item "$ProductName.zip"
 Add-ToPath $InstallDestination

}

# Install APP (Admin)
Function Install-RSAT { # Install Full RSAT (Remote Server Administration Tools) [Windows Component] - Can remote install
 Param (
  [Switch]$SkipWSUS,
  [Switch]$Remote # When connected in a remote sessions using Add-WindowsCapability will not work, so i added this to allow it anyway
 )

 If ($SkipWSUS) {
  $UseWSUSServerOldValue = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\").UseWUServer
  Restart-Service wuauserv
 }

 if (! $Remote) {
  get-WindowsCapability -online -Name RSAT.* | ForEach-Object { add-WindowsCapability -online -Name $_.Name }
 } else {
  $Name='Install-RSAT'
  Register-ScheduledJob -Name $name -ScriptBlock {get-WindowsCapability -online -Name RSAT.* | ForEach-Object { add-WindowsCapability -online -Name $_.Name }} -RunNow
  Start-Sleep 2
  Wait-Job $Name
  Unregister-ScheduledJob $Name -force
 }

 If ($UseWSUSServerOldValue) {
  Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" -Name UseWUServer -Value $UseWSUSServerOldValue
  Restart-Service wuauserv
 }

}
Function Install-WAC { # Download and install latest WAC (Windows Admin Center) [MSI]
 Param (
  $URL = '"http://aka.ms/WACDownload"'
 )
 $MSIInstallFile = Get-FileFromURL $URL
 Install-MSI $MSIInstallFile
}
Function Install-AzureCli { # Download and install latest AzureCLI [MSI]
 Param (
  $URL = 'https://aka.ms/installazurecliwindows'
 )
 $MSIInstallFile = Get-FileFromURL $URL
 Install-MSI $MSIInstallFile
}
Function Install-7zip { # Download and install latest 7Zip [MSI]
 Param (
  $InstallDestination="C:\Apps\7Zip"
 )
 $RootURL = "https://www.7-zip.org/"
 $DownloadLink = $RootURL + $((Invoke-WebRequest $RootURL/download.html).links | Where-Object { $_ -like  "*x64.msi*" } | Select-Object -first 1).href
 Get-FileFromURL $DownloadLink -OutputFile '7zip.msi'
 Install-MSI "7zip.msi"
 Remove-Item "7zip.msi"
}
Function Install-Nmap { # Download and install latest Nmap [EXE] - No silent install on Non-OEM installs
 Param (
  $InstallDestination="C:\Apps\Nmap"
 )
 try {
  $DownloadLink = ((Invoke-WebRequest https://nmap.org/download.html).links | Where-Object { ($_ -like  "*nmap-*.exe*") -and ($_ -notlike  "*beta*") }).href
  $SetupFileName = Get-FileFromURL $DownloadLink
  New-Item -Type Directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Invoke-Expression  "& { ./$SetupFileName }"
  Remove-Item $SetupFileName
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-NotepadPlusPlus { # Download and install latest Notepad++ [EXE] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\Notepad++"
 )
 $RootURL = "https://github.com"
 $ProductName = "notepad-plus-plus"

 $DownloadLink = $RootURL + ((Invoke-WebRequest $RootURL/notepad-plus-plus/$ProductName/releases/latest).links | Where-Object {($_ -like "*Installer.x64*") -and ($_ -notlike  "*sig*")}).href
 $SetupFileName = Get-FileFromURL $DownloadLink -OutputFile "$env:Temp\$ProductName.exe"
 Invoke-Expression  "& { $SetupFileName /S /D=$InstallDestination }"
}
Function Install-Bitvise { # Download and install latest Bitvise SSH Client [EXE]
 Param (
  $InstallDestination="C:\Apps\Bitvise"
 )
 $RootURL = "https://www.bitvise.com/"
 $DownloadLink = ((Invoke-WebRequest $RootURL/ssh-client-download).links | Where-Object { ($_ -like  "*BvSshClient-Inst*.exe*") -and ($_ -notlike  "*alternative*") }).href
 $SetupFileName = Get-FileFromURL $DownloadLink
 Invoke-Expression  "& { .\$SetupFileName -acceptEULA -installDir=$InstallDestination }"
 Remove-Item $SetupFileName
}
Function Install-WinSCP { # Download and install latest WinSCP [EXE]
 Param (
  $InstallDestination="C:\Apps\WinSCP"
 )
 $RootURL = "https://winscp.net"
 $ProductName = "WinSCP"

 #Must add intermediate link to follow link
 $DownloadLinkTMP = $RootURL + ((Invoke-WebRequest $RootURL/eng/downloads.php).links | Where-Object { ($_ -like  "*$ProductName-*.exe*") -and ($_ -notlike  "*beta*") }).href
 $DownloadLink = ((Invoke-WebRequest $DownloadLinkTMP).links | Where-Object {$_ -like "*Direct download*"}).href
 $SetupFileName = Get-FileFromURL $DownloadLink
 New-Item -Type Directory $InstallDestination -force -ErrorAction Stop | Out-Null
 Invoke-Expression  "& { .\$SetupFileName /LANG=EN /SILENT /CURRENTUSER /NORESTART /LOG=$InstallDestination\$ProductName.log /dir='$InstallDestination' }"
 Remove-Item $SetupFileName
}
Function Install-Python { # Download and install latest Python [EXE]
 Param (
  $InstallDestination="C:\Apps\Python"
 )
 $RootURL = "https://www.python.org"
 $ProductName = "Python"

 $DownloadLink = ((Invoke-WebRequest "$RootURL/downloads/").Links  | Where-Object { ($_ -like  "*Download $ProductName*") -and ($_ -like  "*amd64.exe*") } ).href
 try {
  $SetupFileName = Get-FileFromURL $DownloadLink -OutputFile "$ProductName.exe"
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Invoke-Expression  "& { .\$SetupFileName /quiet Include_test=0 PrependPath=1 /TargetDir='$InstallDestination' }"
  Remove-Item "$ProductName.exe"
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-Powershell { # Default Powershell 7 install - does not work fine with proxy | Function to update
 Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
}
Function Install-VisualStudio { # Install Visual Studio with some default options (Requires the Binary Path) | Function to update : Must auto download and restrict to allowed binaries
 Param (
  $BinaryPath = "vs_Professional.exe",
  $VsParams = "--includeOptional --add Microsoft.VisualStudio.Workload.NetCoreTools;includeOptional --add Microsoft.VisualStudio.Workload.Node;includeOptional --add Microsoft.VisualStudio.Workload.ManagedDesktop;includeOptional --add Microsoft.VisualStudio.Workload.NativeDesktop;includeOptional --add Microsoft.VisualStudio.Workload.NetWeb;includeOptional --add Component.GitHub.VisualStudio;includeOptional --quiet --wait",
  $ProductKey = "" # If product key is empty, will not activate the product
 )
 $startInfo = New-Object System.Diagnostics.ProcessStartInfo
 $startInfo.FileName = $BinaryPath
 $startInfo.Arguments = "$VsParams --productKey $ProductKey"
 $process = New-Object System.Diagnostics.Process
 $process.StartInfo = $startInfo
 $process.Start()
 $process.WaitForExit()
}
Function Install-DellDSIAPC { # Download and install latest Dell DSIAPC
 Param (
  $CompressedFileURL = "http://downloads.dell.com/catalog/DellSDPCatalogPC.cab",
  $ContentFile = "DellSDPCatalogPC.xml",
  $FilterToFind = "https://downloads.dell.com.*DSIAPC.*.msi",
  $TempFolder = "$env:TEMP\"
 )
 Try {
  #Download File from source
  Write-Colored -Color Cyan -PrintDate -ColoredText "Download compressed file"
  $FileName = Get-FileFromURL $CompressedFileURL -OutputFolder $TempFolder
  #Get content of compressed file
  Write-Colored -Color Cyan -PrintDate -ColoredText "Read compressed File $FileName"
  $shell = new-object -Comobject shell.application
  $CabContent = $shell.namespace("$FileName")
  #Get info on needed file
  Write-Colored -Color Cyan -PrintDate -ColoredText "Search compressed file for $ContentFile"
  $Item = $CabContent.items() | Where-Object Path -like "*$ContentFile"
  #Extract only needed file
  Write-Colored -Color Cyan -PrintDate -ColoredText "Extract $ContentFile from $FileName to $TempFolder"
  $shell.namespace("$TempFolder").copyhere($Item)
  #Search content file for String
  Write-Colored -Color Cyan -PrintDate -ColoredText "Search $FilterToFind in $TempFolder\$ContentFile"
  $URL = (Select-String $FilterToFind $TempFolder\$ContentFile).Matches[0].Value
  Write-Colored -Color Cyan -PrintDate -ColoredText "Downloading file from $URL"
  $FileToInstall = Get-FileFromURL $URL
  Write-Colored -Color Cyan -PrintDate -ColoredText "Installing MSI $FileToInstall"
  Install-MSI -MsiPath $FileToInstall
 } Catch {
  Write-Host -ForegroundColor Red $Error[0]
 }
}
