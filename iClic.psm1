# Notes
#   Type of indentation : K&R 1TBS
# Add de Beep to functions / commands
#   [console]::Beep()
# Mod default error output :
#   $ErrorView="CategoryView"
#   $ErrorView="Normal"
# List all Profiles
#   $PROFILE | Format-List * -Force
# To Test Function parameters : Show-Command
# To log all commands
#   $outputfile="d:\iClicLog_"+(get-date -uformat "%Y%m%d")+".log"
#   Start-Transcript -path $outputfile -append
# Change Security Protocol of NetFramework
#   [System.Net.ServicePointManager]::SecurityProtocol
#   [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'
# Remote Launch Function
#   Invoke-Command -ScriptBlock ${function:FUNCTIONNAME} -ComputerName $ServerName
# Add NuGet as package source
#   Register-PackageSource -Name NuGet.Org -Location https://www.nuget.org/api/v2 -ProviderName NuGet
# See security applied to PsSession and update them if needed
#   List : Get-PSSessionConfiguration
#   Modify : Set-PSSessionConfiguration -showSecurityDescriptorUI
# To pass variable from a function to the inside of a function use Splatting:
#   https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_splatting
#   Example with AzCli : Get-AzureServicePrincipal
#   Example with standard PowerShell cmdlet : Get-NetStat
# Create Objects
#   $Lic_List=@()
#   $Lic_List+=[pscustomobject]@{Name="Windows Server 2016 Datacenter";Key="1"}
#   $Lic_List+=[pscustomobject]@{Name="Windows Server 2016 Standard (MSDN)";Key="2"}
# Add comment only if verbose is set
#  $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
# Added --only-show-errors on all Az AD Cmdlets until the migration is dones to Microsoft Graph
# Azure Query filter
#  az account list --all --query "[?id=='$ObjectID'].{id:id, name:name}"
# To add dynamic number of values (Example to show all tags)
#  Get-MDCConfiguration
# Example to add all Members to an Object without knowing the name first
#  $TagList = [PSCustomObject]@{}
#  $_.Tags | ForEach-Object { $TagList | Add-Member -MemberType NoteProperty -Name ($_ -split ":")[0] -Value ($_ -split ":")[1] }
# Check Get-AzureADObjectInfo to see Error Management for AzCli cmdlines
# Methods to look into a hastable from slowest to fastest
#  Measure-Command {$AppRegistrationExpiration.apptags | Where-Object {$_.Contact -eq "$ValueToSearch"}}
#  Measure-Command {$AppRegistrationExpiration.apptags.Where{$_.Contact -eq "$ValueToSearch"}}
#  Measure-Command {$AppRegistrationExpiration[$AppRegistrationExpiration.apptags.indexof($ValueToSearch)]} # WARNING INDEXOF RETURN -1 IF NO VALUE FOUND
#  Best method : Convert to hashTable
#  $TotoHash = @{} ; $toto | ForEach-Object { $TotoHash[$_.ID] = $_ }
#  measure-command {$TotoHash[$TotoHash.ContainsKey("$KeyValueToCheck")]}
# AzCLI Token Management
#  To use Current user token for Az : $UserToken = az account get-access-token
# Re-Use Parameter in subfunction : $PSBoundParameters
# Console history found here : (Get-PSReadLineOption).HistorySavePath
# To generate Self Signed Certificate : $Certificate=New-SelfSignedCertificate –Subject CERTIFICATENAME -CertStoreLocation Cert:\CurrentUser\My -NotAfter $((get-date).AddMonths(6))

# Required Modules
# ActiveDirectory for : Set-AdUser, Get-AdUser etc.
# For Azure : Azure CLI or Microsoft.Graph
# For Exchange Management : ExchangeOnlineManagement
# To store secure data in Credential Manager : TUN.CredentialManager
# To decode JWT Tokens : JWT
# For Azure Certificat Authentication to avoid recoding every JWT Assertion Token : MSAL.PS - Will avoid this module if possible as this generates conflicts with other MS Modules

# ToDo : add measure-command function to time functions whenever possible

# Set future console in QuickEdit mode
if ( ($host.Name -match 'consolehost') ) {
 Try {
  set-itemproperty -path "HKCU:\Console" -name QuickEdit -Value 1 -ErrorAction Ignore
 } catch {
  Write-Verbose "Issue setting QuickEdit ${$Error[0]}"
 }
}

if ($env:LOCALAPPDATA) {
 $iClic_TempPath = "$($env:LOCALAPPDATA)\iClic\"
} else {
 $iClic_TempPath = "C:\Temp\"
}

if (! (Test-Path $iClic_TempPath)) {
 New-item -ItemType Directory $iClic_TempPath\ -Force | Out-Null
 Set-Location -Path "$iClic_TempPath"
} else {
 Set-Location -Path "$iClic_TempPath"
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
Function PSElevate { # Open an elevated Powershell window (not possible to elevate without opening a new window). If already elevated will open another window
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
  write-Colored -Color "Red" "Error while Elevate : " $error[0]
 }
}
Function Get-UptimePerso { # Show machine uptime, works with any OS and works remotely
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
Function KillAllPsSessions { # Remove all opened PS sessions
 $Sessions=get-pssession
 try {
  $Sessions | Remove-PSSession -ErrorAction Stop
 } catch {
  write-Colored -Color "Red" -ColoredText $Error[0]
 }
 write-colored "Magenta" -ColoredText "$($Sessions.Count) session(s) deleted"
 #Remove Temporary Modules
 Title
 Remove-Module -Name "tmp_*"
}

# Display Functions
Function Title { # Used to manage the title of the Powershell Window
 Param (
  $PostMsg
 )
 # $Host.UI.RawUI.WindowTitle = "PowerShell " + (get-host).Version.Major + "." + (get-host).Version.Minor + " $username`@$($env:computername)" + " (" + $pwd.Provider.Name + ") " + $pwd.Path
 if (Assert-IsAdmin) {$TitleAdmin="[*]"} else {$TitleAdmin=""}
 if (! $([Environment]::Is64BitProcess)) {$TitleArchitecture="<32>"} else {$TitleArchitecture=""}
 # $TitleUsername=$env:USERNAME
 $WHOAMI = whoami /UPN 2>$null
 $TitleUsername = if ($WHOAMI) {($WHOAMI -split("@"))[0]} else {((whoami).split("\"))[1]}
 $TitleUserDomain = $env:USERDOMAIN
 $TitleHostname=$env:COMPUTERNAME
 $TitleUserInfo="[$TitleUsername`@$TitleUserDomain`|$TitleHostname]"
 #Check if in RemoteSession
 if (! $PSSenderInfo) {
  # $HostInfo=get-host
  # $TitlePsVersion="PS$($psversiontable.PSVersion)"
 }
 #Add this to be able to import profile in parallele PS commands (Noninteractive check do not work)
 try {
  $Host.UI.RawUI.WindowTitle = "$TitleUserInfo$TitleAdmin$TitlePsVersion$PostMsg$TitleArchitecture"
 } catch {
  Write-Error "Nothing here"
 }
}
Function prompt { # Used to have a "pretty" Powershell prompt showing important info

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
   # $P_UserName = $env:USERNAME
   $WHOAMI = whoami /UPN 2>$null
   $P_UserName = if ($WHOAMI) {($WHOAMI -split("@"))[0]} else {((whoami).split("\"))[1]}
   $P_UserDomain = $env:USERDOMAIN
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
 write-colored $promptcolor -ColoredText $P_UserDomain -nonewline
 write-colored $ColorGray -ColoredText "|" -nonewline
 write-colored $promptcolor -ColoredText $P_ComputerName -nonewline
 # write-colored $ColorGray -ColoredText "] " -nonewline
 write-colored $ColorGray -ColoredText "] "

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
Function Question { # Function to ask simple yes/no question
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
Function Banner { # Prints a default banner
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
Function ClearProgressBar { # Remove Powershell process bar which sometimes is not closed
 for ($i = 1; $i -le 100; $i++ ) {write-progress -activity "Finishing" -status "$i% Complete:" -percentcomplete $i -Completed}
}
Function PSWindowResize { # Used to resize the Powershell Window
 Param (
  $windowsize="100"
 )
 #Console Size
 try {
  [console]::windowwidth=$windowsize
  [console]::SetBufferSize($windowsize,"999")
 # [console]::windowheight=(get-host).UI.RawUI.MaxPhysicalWindowSize.Height
 } catch {
  Write-Error "Nothing here"
 }
}
Function PSWindowsColors { # Used to change default Powershell colors
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
 } catch {
  Write-Error "Nothing here"
 }
}
Function Progress { # Default progress function, used to show a progress of something that may take time
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
 Write-Colored -Color $defaultblue -NonColoredText "`r$blanklinesize" -nonewline
 Write-Colored -Color $defaultblue -NonColoredText "`r$Time$Message" -ColoredText $Value -nonewline
}
Function ProgressClear { # Clear progress when a progress is done
 try {
  $blanklinesize=" "*([console]::windowwidth -2)
 } catch {$blanklinesize=" "*100}
 Write-Colored -Color $defaultblue -NonColoredText "`r$blanklinesize" -nonewline
}
Function Align { # Align function depending on the window size
 Param (
  $variable,
  $size,
  $ending=""
 )
 if ($variable.length -lt $size) {$variable=$variable+(" "*($size-$variable.length))+$ending}
 return $variable
}

# Write functions
Function Write-Centered { # Function to print text centered on the powershell screen
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
 Write-Colored -Color $Color -NonColoredText "" ("{0,$offsetvalue}" -f $message) $NoNewLineValue
}
Function Write-StarLine { # Print a line of a specific character
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
Function Write-Blank { # Print a blank line (\n equivalent)
 Write-Host
}
Function Write-Colored { # Advanced Write-Host function which can be used to print to a file at the same time as the screen
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
  Write-Colored -Color $Color -NonColoredText "" $line
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
  Write-Colored -Color $defaultblue -NonColoredText " Start Mode : " $_.startmode -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " | Status : " $_.state -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " | Login Name : " $LoginName
  Write-Colored -Color $defaultblue -NonColoredText " CommandLine : " $CommandLine
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
 if ($null -eq $gpresult ) {write-Colored -Color "Red" (Align -Variable $policy -Size $Tabsize -Ending " : ") "UNABLE TO CHECK GPOs - Please run script as Admin";return}
 if ($null -eq $POLICYTOCHECK) {write-Colored -Color "Red" (Align -Variable $policy -Size $Tabsize -Ending " : ") "NOT CONFIGURED (KO)" -foregroundcolor "red";return}

 #GetPosition of ":" | Get only end of name of GPO
 #$position=$POLICYTOCHECK.Line.indexof(":")
 #$policy=( $POLICYTOCHECK.Line.substring($position+1).trim() ).split('\')[-1]

 #Get Policy Value
 $value=$POLICYTOCHECK.Context.DisplayPostContext | Out-String

 #Check Policy Value
 if ( $policy -eq "MaxCompressionLevel" -and $value.Contains("3, 0, 0, 0")) {Write-colored "darkgreen" (Align -Variable $policy -Size $Tabsize -Ending " : ") "ENABLED (OK)" ; return}

 if ($value.Contains("1, 0, 0, 0")) {Write-colored "darkgreen" (Align -Variable $policy -Size $Tabsize -Ending " : ") "ENABLED (OK)"} -Size else -Ending {
  If ($value.Contains("0, 0, 0, 0")) {write-Colored -Color "Red" (Align -Variable $policy -Size $Tabsize -Ending " : ") -Size "DISABLED -Ending (KO)"}
  else {write-Colored -Color "Red" (Align -Variable $policy -Size $Tabsize -Ending " : ") "ERROR DURING CHECK - PLEASE -Size CHECK -Ending MANUALLY"}
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
  write-Colored -Color "Red" "" "$ValueText : 0"
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
  Write-Error "Nothing here"
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
Function Convert-GUIDToImmutableID {
 Param (
  [Parameter(Mandatory=$true)]$Guid
 )
 [Convert]::ToBase64String([guid]::New($Guid).ToByteArray())
}
Function Convert-ImmutableIDToGUID {
 Param (
  [Parameter(Mandatory=$true)]$ImmutableID
 )
 ([Guid]([Convert]::FromBase64String("$ImmutableID"))).GUID
}
function Convert-SIDToAzureObjectId { # Get Azure ObjectID From SID (based on : https://github.com/okieselbach/Intune/blob/master/Convert-AzureAdSidToObjectId.ps1)
 param(
  [String] $Sid
 )
 $text = $sid.Replace('S-1-12-1-', '')
 $array = [UInt32[]]$text.Split('-')

 $bytes = New-Object 'Byte[]' 16
 [Buffer]::BlockCopy($array, 0, $bytes, 0, 16)
 [Guid]$guid = $bytes

 return $guid
}
Function Convert-MacAddressFormat { # Convert Mac format to proper format [ Thanks Gemini ]
    <#
    .SYNOPSIS
        Converts a MAC address string to a standard format with colons.
    .DESCRIPTION
        This function takes a string representing a MAC address, removes any existing separators (hyphens or colons),
        validates that it contains exactly 12 hexadecimal characters, and then formats it with a colon every two characters.
    .PARAMETER MacAddress
        The MAC address string to be converted. It can be with or without separators.
    .EXAMPLE
        PS> ConvertTo-MacAddress -MacAddress "001122334455"
        00:11:22:33:44:55
    .EXAMPLE
        PS> ConvertTo-MacAddress -MacAddress "AA-BB-CC-DD-EE-FF"
        AA:BB:CC:DD:EE:FF
    .EXAMPLE
        PS> ConvertTo-MacAddress -MacAddress "aabbccddeeff"
        aa:bb:cc:dd:ee:ff
    .EXAMPLE
        PS> ConvertTo-MacAddress -MacAddress "00112233445Z"
        ERROR: Invalid character found in MAC address. Only hexadecimal characters (0-9, A-F) are allowed.
    #>
    param (
        [Parameter(Mandatory=$true)][string]$MacAddress,
        $JoinCharacter = ":"
    )

    # Remove any existing separators (hyphens or colons)
    $cleanedMac = $MacAddress -replace '[:-]'

    # Check if the cleaned string contains only valid hexadecimal characters and is 12 characters long
    if ($cleanedMac -notmatch '^[a-fA-F0-9]{12}$') {
        if ($cleanedMac.Length -ne 12) {
            Write-Error "Invalid MAC address length. The input string must resolve to 12 characters after removing separators."
        } else {
            Write-Error "Invalid character found in MAC address. Only hexadecimal characters (0-9, A-F) are allowed."
        }
        return
    }

    # Insert a colon every two characters
    $formattedMac = ($cleanedMac -split '(..)' | Where-Object { $_ }) -join "$JoinCharacter"

    return $formattedMac
}
function ConvertTo-Base64Url {
 param($InputObject)
  # Standard Base64 encoding can contain characters ('+', '/', '=') that are not URL-safe.
  # Base64Url replaces them and removes padding.
  $base64 = [System.Convert]::ToBase64String($InputObject)
  return $base64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
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
  if (! $HideTime) {Write-Colored -Color $defaultblue -NonColoredText "Test Date/Time : " $(get-date -uformat '%Y-%m-%d %T') -nonewline}

  if ($PrintCommand) {
   if ($NoNewLine) {Write-Colored -Color $defaultblue -NonColoredText " | Command : " $commandline -nonewline ; Write-Colored -Color $defaultblue -NonColoredText " | " -nonewline}
   else { Write-Colored -Color $defaultblue -NonColoredText " | Command : " $commandline}
  } else {
   if ($NoNewLine) {Write-Colored -Color $defaultblue -NonColoredText " | " "" -nonewline}
   else {Write-Colored -Color $defaultblue -NonColoredText " " ""}
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
 } catch {write-Colored -Color "Red" -ColoredText $error[0]}
}
Function Tail { # 'tail' equivalent
 Param (
  $filename,
  $tailsize=10
 )
 if ( ! (test-path $filename)) { write-Colored -Color "Red" "" "Unavailable path : $filename" ; return }
 get-content $filename -wait -tail $tailsize
}
Function Get-TopProcesses { # 'top' equivalent using Get-Process
 Param (
  $NumberOfProcess = 25
 )
 Get-Process | Sort-Object -Descending cpu | Select-Object -First $NumberOfProcess ProcessName,ID,@{N="Memory";E={Format-Filesize $_.PrivateMemorySize}},StartTime,
 @{N="TotalProcessorTime";E={($_.TotalProcessorTime).ToString().Split(".")[0]}},Path | Sort-Object CPU -Descending | Format-Table
}
Function Top { # 'top' equivalent using Windows Counters
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
 # Available only in powershell 5 or more : https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#span-idtextformattingspanspan-idtextformattingspanspan-idtextformattingspantext-formatting
 # Get Colors : https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#text-formatting

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
 $OfficeDocuments = @(".doc",".xls",".xlsx",".docx",".xml")

 #Search
 $Result = Get-ChildItem -ErrorAction Stop -force -Path $Path | Select-Object Mode,Name,Length,
  @{Label='LastWrite'; Expression={Get-Date $_.LastWriteTime -uformat '%Y-%m-%d %T'}},
  @{Label='Size'; Expression={ if ($_.Length -gt '1') {format-FileSize $_.Length }}},
  @{Label='Type'; Expression={ $Type=$($_.GetType().Name) ; if (! ($Type -like 'DirectoryInfo')) {$Type=$_.Extension.ToLower()};$Type}},Target

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
     write-colored -Color $_.Color -ColoredText "$(Align $($_.LastWrite) 19) $(Align $($_.Mode) 7) $(Align -Variable $($_.Size) 10) $($_.Name)"
    }
   }
   return
  }

  $EscapeChar=[char]27
  # When in remote session disable color for alignement
  if ($NoColor -or $PSSenderInfo) {
   $Result | Format-Table LastWrite,Mode,Name,Length,Size,Target
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
     },Length,Size,Target
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
   Write-Error "Nothing here"
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
Function Get-LastReboots { # 'last reboot' equivalent
 Param (
  [switch]$ShowAll,
  $EventID = "6009",
  $Server = $Env:COMPUTERNAME
 )
 # Event ID 6005 (alternate): "The event log service was started." This is synonymous to system startup.
 # Event ID 6006 (alternate): "The event log service was stopped." This is synonymous to system shutdown.
 # Event ID 6008 (alternate): "The previous system shutdown was unexpected." Records that the system started after it was not shut down properly.
 # Event ID 6009 (alternate): Indicates the Windows product name, version, build number, service pack number, and operating system type detected at boot time.

 Try {
  if ($ShowAll) {
   Get-WinEvent -FilterHashtable @{LogName='System';ID="$EventID"} -ComputerName $Server -ErrorAction Stop | Select-Object RecordID,
    @{name="Date";expression={$(get-date -Date $_.TimeCreated -UFormat "%Y-%m-%d %T")}}
  } else {
   (Get-WinEvent -FilterHashtable @{LogName='System';ID="$EventID"} -MaxEvents 1 -ComputerName $Server -ErrorAction Stop | Select-Object RecordID,
    @{name="Date";expression={$(get-date -Date $_.TimeCreated -UFormat "%Y-%m-%d %T")}}).Date
  }
 } Catch {
  Write-Host -Foreground 'Red' $Error[0]
 }

 #  It is also possible to do this using XML :
 #  $xml=@'
 # <QueryList><Query Id="0" Path="System"><Select Path="System">*[System[(EventID=6005)]]</Select></Query></QueryList>
 # '@
 #   Get-WinEvent -FilterXml $xml -MaxEvents $MaxEvents -ComputerName $Server | Select-Object @{Name="Reboots";Expression={Format-Date $_.TimeCreated}}
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
  Write-Error "Nothing here"
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
 } catch {write-Colored -Color "Red" -ColoredText $Error[0]}
}

# Wait for User Interractions
Function WaitForKeyPressAdvanced {
 Param (
  $Message = "Press any key to continue . . . "
 )
 If ($psISE) {
  # The "ReadKey" functionality is not supported in Windows PowerShell ISE ...
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
 $CurrentOSVersion=(Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
 if ( ! $OSVersion ) {Write-Colored -Color $defaultblue -NonColoredText "Current OS Version : " $CurrentOSVersion ; return $true}
 elseif ( [int]$CurrentOSVersion -lt [int]$OSVersion ) { write-Colored -Color "Red" "" "This function does not work on older than Windows Build $OSVersion OS (Current build : $CurrentOSVersion)" ; return $false}
 else {return $true}
}
Function Assert-OSType {
 Param (
  [switch]$PrintMessage
 )
 #Currently Only Check if Workstation OS is being used
 if ( (Get-CimInstance Win32_OperatingSystem).ProductType -eq "1" ) { if ($PrintMessage) {write-Colored -Color "Red" "" "This function does not work on workstation OS"} ; return $false} else {return $true}
}
Function Assert-IsCommandAvailable {
 Param (
  $commandname,
  [switch]$NoError
 )
 if (!$commandname) {Write-Colored -Color "red" -NonColoredText  "" "Provide command name";return}

 if ( !(Get-Command "$commandname" -ErrorAction SilentlyContinue)) {
  if (! $NoError) {Write-Colored -Color "red" -NonColoredText  "" "$commandname is not available (not in path or cmdlet not available)"}
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
   [pscustomobject]@{CLSID=$CLSID;ValueFound=$ValueFound;Value=$Value}
  }
 } else {
  reg query HKLM\$RegPath /s /f $DllName | Out-Null
  $Result=$LastExitCode
  if ($Result) { return $False } else { Return $True }
 }
}
Function Assert-IsInAAD {
 Param (
  [Parameter(Mandatory=$true)]$NameOrID, # Works with Name (UPN for users) & ID
  [ValidateSet("Group","User")]$Type="User",
  [switch]$PrintError
 )
 if ($Type -eq 'Group') {
  $ResultJson = az ad group show -g $NameOrID 2>&1
  $ErrorMessage = $ResultJson | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
  $Result = $ResultJson | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }
  if ($ErrorMessage) {
   if ($ErrorMessage -like "*More than one group*") {
    write-host -ForegroundColor "Red" -Object "Error searching for Group $NameOrID [$ErrorMessage]"
   }
   if ($PrintError) { write-host -ForegroundColor "Red" -Object "Error searching for Group $NameOrID [$ErrorMessage]" }
  }
 } else {
  $Result = az ad user show --id $NameOrID 2>&1
 }
 if ($Result) { return $True } else { return $False }
}
Function Assert-IsGUID {
 Param (
  [Parameter(Mandatory)]$Value
 )
 $ObjectGuid = [System.Guid]::empty
 # Returns True if successfully parsed, otherwise returns False.
 if ( [System.Guid]::TryParse($Value,[System.Management.Automation.PSReference]$ObjectGuid) ) { return $true } else {return $false}
}

# Tests
Function Test-Port { # TO DO : ADD UDP TEST : system.Net.Sockets.UDPClient
 Param (
  [Parameter(Mandatory)]$Server,
  [Parameter(Mandatory)]$Port,
  $Timeout=1000,
  [Switch]$UDP
  # [switch]$Verbose
 )
 # Code based on http://poshcode.org/85

 if ( ! (Assert-IsCommandAvailable Resolve-DNSName) ) { Write-Colored -Color "red" -NonColoredText  "Resolve-DNSName if not available, please use Test-PortOld (IPv6 test will not be available)" ; return $false }

 #If it is a name that is used as argument
 try {
  $IPType=([ipaddress]$Server).AddressFamily
 } catch {
  # if ($Server.contains(".")) { $ServerName=$Server.split(".")[0] } else {$ServerName=$Server}
  try {
   $ServerIP=(Resolve-DNSName -ErrorAction Stop $Server)
  } catch {
   if ($Verbose) {Write-Colored -Color "red" -NonColoredText  "Error during dns check : " $error[0]}
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
  Write-Colored -Color "red" -NonColoredText  "" "Test does not work with IPv6 - Please enter IPv4 $((Resolve-DNSName $Server)[1].ipaddress)"
  return $false
 } else {
  Write-Colored -Color "red" -NonColoredText  "Error while checking IP type : " $error[0]
  return $false
 }

 if ($UDP) {
  $UDPclient = new-Object system.Net.Sockets.Udpclient
  $UDPclient.Connect($Server,$Port)
  $UDPclient.Client.ReceiveTimeout = $Timeout
  $EncodingObject = new-object system.text.asciiencoding
  $byte = $EncodingObject.GetBytes("Anyone there ?")
  [void]$UDPclient.Send($byte,$byte.length)
  $RemoteEndpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any,0)
  Try {
   $receivebytes = $UDPclient.Receive([ref]$RemoteEndpoint)
  } Catch {
   if ($Verbose) {Write-Warning "$($Error[0])"}
  }
  If ($receivebytes) {
   if ($Verbose) {
    [string]$returndata = $EncodingObject.GetString($receivebytes)
    $returndata
   }
   return $true
  } Else {
   if ($Verbose) {Write-Colored -Color "red" -ColoredText "$Server : No response from Port $Port in UDP"}
   return $false
  }
  $UDPclient.close()
 } else {
  # Create TCP Client
  $tcpclient = new-Object system.Net.Sockets.TcpClient

 # Tell TCP Client to connect to machine on Port
 $iar = $tcpclient.BeginConnect($Server,$Port,$null,$null)
 # Set the wait time
 $wait = $iar.AsyncWaitHandle.WaitOne($Timeout,$false)

 #If connection failed return error
 $error.Clear()
 if( ! $wait ) {
  $tcpclient.Close()
  if ($Verbose) {Write-Colored -Color "red" -ColoredText "$Server : No response from Port $Port"}
  return $false
 }

 # Close the connection and report the error if there is one
 $error.Clear()
 try {
  $tcpclient.EndConnect($iar) 2>&1 | out-Null
 } catch {
  Write-Colored -Color "red" -NonColoredText  "" $error[0];return $false
 }
 $tcpclient.Close()

 # If no failure return $true
 return $true
 }
}
Function Test-PortOld {
 Param (
  $server,
  $port,
  $timeout=1000,
  $Verbose
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
 if ( ! (test-path $FilePath)) { Write-Colored -Color "red" -NonColoredText  "" "Unavailable path : $FilePath" ; return }
 Import-CSV -Encoding UTF8 -Delimiter ";" $FilePath | ForEach-Object {
  if (! $_.Service) {return}
  Write-Colored -Color $defaultblue -NonColoredText "Testing " (Align -Variable $_.Service 30) -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " | " (Align -Variable $_.IP 15) -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " | Port " (Align -Variable $_.Port 5) -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " | " "" -nonewline
  if (Test-Port $_.IP $_.Port) {write-colored "DarkGreen" "" "Access OK"} else {Write-Colored -Color "red" -NonColoredText  "" "No Access"}
 }
}
Function Test-ADPorts {
 Param (
  [Parameter(Mandatory)]$Domain
 )
 $DNSServerList = (Resolve-DnsName auto-contact.com).IPAddress
 $portlist = $('135','389','636','3268','3269','53','88','445','138','139','42')

 $DNSServerList | ForEach-Object {
  $CurrentServer = $_
  $portlist | ForEach-Object {
   Write-Colored -Color $defaultblue -NonColoredText "Testing " (Align -Variable TCP 3) -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " | " (Align -Variable $CurrentServer 15) -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " | Port " (Align -Variable $_ 5) -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " | " "" -nonewline
   if (Test-Port -Server $CurrentServer -Port $_) {write-colored "DarkGreen" -ColoredText "Access OK"} else {Write-Colored -Color "red" -ColoredText "No Access"}
   Write-Colored -Color $defaultblue -NonColoredText "Testing " (Align -Variable UDP 3) -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " | " (Align -Variable $CurrentServer 15) -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " | Port " (Align -Variable $_ 5) -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " | " "" -nonewline
   if (Test-Port -Server $CurrentServer -Port $_ -UDP) {write-colored "DarkGreen" -ColoredText "Access OK"} else {Write-Colored -Color "red" -ColoredText "No Access"}
  }
 }
}
Function Test-Account {
 Param (
  $AdUser=$env:USERNAME
 )
 # Check if account is in AD and if account is enabled
 if ( ! (Assert-IsCommandAvailable Get-ADUser) ) {return}
 if ( $(try { get-aduser $AdUser } catch { Write-Error "Nothing here" }) ) {if ( (get-aduser $AdUser).Enabled ) {return $true} else {return $false}} else {return $false}
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
   Write-Colored -Color $defaultblue -NonColoredText "Domain : " $Credential.GetNetworkCredential().Domain -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " | UserName : " $Credential.GetNetworkCredential().UserName -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " | Password : " $Credential.GetNetworkCredential().Password
   Write-StarLine "-"
  }

  Start-Process -FilePath cmd.exe /c -Credential $Credential
 } catch {
  if ($printerror) {Write-Colored -Color "red" -NonColoredText  "" $error[0] } ; return $false
 }

 return $true
}
Function Test-AccountPasswordList {
 Param (
  [Parameter(Mandatory=$true)]$FilePath
 )
 if ( ! (test-path $FilePath)) { Write-Colored -Color "red" -NonColoredText  "" "Unavailable path : $FilePath" ; return }
 Import-CSV $FilePath | ForEach-Object {
 if (! $_.Login) {return}
 $user=$_.Domain + "\" + $_.Login
 Write-Colored -Color $defaultblue -NonColoredText "Testing " $user -nonewline
 Write-Colored -Color $defaultblue -NonColoredText " with Password : " $_.Password -nonewline
 Write-Colored -Color $defaultblue -NonColoredText " -> " "" -nonewline
 if ( ! (Test-Account $_.Login)) {Write-Colored -Color "red" -NonColoredText  "" "Account does not exist" ; return}
 if (Test-AccountPassword $user $_.Password) {write-colored "DarkGreen" "" "OK"} else {Write-Colored -Color "red" -NonColoredText  "" "KO"}
 }
}
Function Test-URL {
 Param (
  [Parameter(Mandatory=$true)]$URL,
  [PSCredential]$credential,
  [Switch]$comment
 )
 # while ( ! $credential ) { $credential = get-credential }
 # try { (curl -uri $URL -credential $credential).StatusCode } catch { Write-Colored -Color "red" -NonColoredText  "" $Error[0].Exception.Message ; Write-Colored -Color "red" -NonColoredText  "-> " $Error[0] }
 if ( $comment ) {
  Write-Colored -Color $defaultblue -NonColoredText "Testing URL : " "$URL" -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " with account : " $credential.username
 }
 if ( $credential ) {
  try {
   (Invoke-WebRequest -uri $URL -credential $credential).StatusCode
  } catch {
   Write-Colored -Color "red" -NonColoredText  "Return Code : " $_.Exception.Response.StatusCode.Value__ -nonewline ; Write-Colored -Color "red" -NonColoredText  " -> " $Error[0]
  }
 }
 else {
  try {
   (Invoke-WebRequest -uri $URL -credential $credential).StatusCode
  } catch {
   Write-Colored -Color "red" -NonColoredText  "Return Code : " $_.Exception.Response.StatusCode.Value__ -nonewline ; Write-Colored -Color "red" -NonColoredText  " -> " $Error[0]
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
 } catch { if ($printmessage) {write-colored -Color "red" -ColoredText "$servername`t$false`t$($error[0])"} else { return $false } }
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

 if ( ! (Test-Account $user)) {Write-Colored -Color "red" -NonColoredText  "" "Account does not exist" ; return} else {$userinformation=Get-ADUser $user -Properties * | Select-Object *}

 Write-Blank

 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Name" -Size $Tabsize -Ending " = ") $userinformation.Name
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "DisplayName" -Size $Tabsize -Ending " = ") $userinformation.DisplayName
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "SamAccountName" -Size $Tabsize -Ending " = ") $userinformation.SamAccountName
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "UserPrincipalName" -Size $Tabsize -Ending " = ") $userinformation.UserPrincipalName
 if ( $userinformation.mail ) { Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "mail" -Size $Tabsize -Ending " = ") $userinformation.mail }
 if ( $userinformation.mailNickname ) { Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "mailNickname" -Size $Tabsize -Ending " = ") $userinformation.mailNickname }
 if ( $userinformation.OfficePhone ) { Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "OfficePhone" -Size $Tabsize -Ending " = ") $userinformation.OfficePhone }

 Write-Blank

 $TabSize = 40
 if ( $userinformation.Enabled ) { $color = "darkgreen" } else { $color = "red" }
 Write-Colored -Color $Color -NonColoredText (Align -Variable "Account Enabled" -Size $Tabsize -Ending " = ") $userinformation.Enabled

 if ( $userinformation.CannotChangePassword -or ! $noexpire ) { $color = "darkgreen" } else { $color = "red" }
 Write-Colored -Color $Color -NonColoredText (Align -Variable "User cannot change password" -Size $Tabsize -Ending " = ") $userinformation.CannotChangePassword

 if ( ! $userinformation.PasswordNotRequired ) { $color = "darkgreen" } else { $color = "red" }
 Write-Colored -Color $Color -NonColoredText (Align -Variable "User must change password at next logon" -Size $Tabsize -Ending " = ") $userinformation.PasswordNotRequired

 if ( ! $userinformation.LockedOut ) { $color = "darkgreen" } else { $color = "red" }
 Write-Colored -Color $Color -NonColoredText (Align -Variable "Account Locked" -Size $Tabsize -Ending " = ") $userinformation.LockedOut -nonewline
 if ( $userinformation.LastBadPasswordAttempt ) { Write-Colored -Color $defaultblue -NonColoredText " (Last Failed Attempt : " $userinformation.LastBadPasswordAttempt -nonewline ; ")" } else { Write-Blank }

 if ( $userinformation.PasswordNeverExpires -or ! $noexpire ) { $color = "darkgreen" } else { $color = "red" }
 Write-Colored -Color $Color -NonColoredText (Align -Variable "Password Never Expires" -Size $Tabsize -Ending " = ") $userinformation.PasswordNeverExpires

 if ( ! $userinformation.PasswordExpired ) { $color = "darkgreen" } else { $color = "darkgreen" }
 Write-Colored -Color $Color -NonColoredText (Align -Variable "Password Expired" -Size $Tabsize -Ending " = ") $userinformation.PasswordExpired -nonewline
 if ( $userinformation.AccountExpirationDate ) { Write-Colored -Color $defaultblue -NonColoredText " (Expiration date : " $userinformation.AccountExpirationDate -nonewline ; ")" } else { Write-Blank }

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

  #Get PC Model
  $ComputerSystemInfo = Get-CimInstance Win32_ComputerSystem
  #Get Motherboardinfo :
  $MotherBoardInfo = Get-CimInstance Win32_BaseBoard
  #Get BatteryInfo :
  $BatteryInfo = Get-CimInstance win32_battery
  #Installed RAM in GB :
  $RamInfo = Get-CimInstance Win32_PhysicalMemory
  $InstalledRam=($RamInfo | Measure-Object -Property capacity -Sum | ForEach-Object {[Math]::Round(($_.sum / 1GB),2)})
  #Processor :
  $ProcInfo=Get-CimInstance win32_Processor
  $BiosInfo=Get-ciminstance win32_bios

  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Hardware Info" -Size $Tabsize -Ending " : ") -ColoredText ($ComputerSystemInfo.manufacturer + " (Model : " + $ComputerSystemInfo.Model + ")")
  if ($MotherBoardInfo) {
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Motherboard Info" -Size $Tabsize -Ending " : ") ("Manufacturer : " + $MotherBoardInfo.Manufacturer + " | Product : " + $MotherBoardInfo.Product)
  }
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Bios Info" -Size $Tabsize -Ending " : ") ("Serial Number : " + $BiosInfo.SerialNumber + " | Bios Name : " + $BiosInfo.Name)
  write-host
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Installed RAM" -Size $Tabsize -Ending " : ") ($InstalledRam.tostring() + " GB")
  $RamInfo | foreach-object {
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "$($_.DeviceLocator)-RAM" -Size $Tabsize -Ending " : ") $("$($_.PartNumber.trim()) ($($_.Manufacturer)) | $(Format-FileSize $_.Capacity) ($($_.ConfiguredClockSpeed)Mhz/$($_.Speed)Mhz)")
  }
  write-host
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Processor Total" -Size $Tabsize -Ending " : ") ("$($ComputerSystemInfo.NumberOfProcessors) Physical | $($ComputerSystemInfo.NumberOfLogicalProcessors)  Logical")
  $ProcInfo | foreach-object {
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "$($_.SocketDesignation)-Processor" -Size $Tabsize -Ending " : ") $(($_.Name.trim() -replace '\s+',' ')," | ",$_.Description)
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "$($_.SocketDesignation)-Logical Processors" -Size $Tabsize -Ending " : ") ($_.NumberOfLogicalProcessors)
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "$($_.SocketDesignation)-Speed Current/Max" -Size $Tabsize -Ending " : ") ($_.CurrentClockSpeed,"Mhz /",$_.MaxClockSpeed,"Mhz")
  }
  write-host
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Hypervisor Present" -Size $Tabsize -Ending " : ") ($ComputerSystemInfo.HypervisorPresent)
  if ($BatteryInfo) {

   if ($BatteryInfo.EstimatedChargeRemaining -eq 100) {$BatteryColor = "Green"} elseif ($BatteryInfo.EstimatedChargeRemaining -ge 15) {$BatteryColor = "DarkYellow"} else {$BatteryColor = "Red"}
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Battery Info" -Size $Tabsize -Ending " : ") ($BatteryInfo.Name) -NoNewLine
   write-colored -Color $BatteryColor -NonColoredText " | % remaining : " -ColoredText $BatteryInfo.EstimatedChargeRemaining -NoNewLine
   write-colored -Color $defaultblue -NonColoredText " | Estimated runtime : " -ColoredText $BatteryInfo.EstimatedRunTime
  }
  write-host
 }

 if ( $Software ) {
  Write-Blank
  write-centered "SOFTWARE`n" "Magenta"

  $os = Get-CimInstance win32_operatingsystem

  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Windows Version" -Size $Tabsize -Ending " : ") (Get-WindowsVersion)
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Installation Date" -Size $Tabsize -Ending " : ") $(Format-Date ($os.InstallDate.tostring()))
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Uptime" -Size $Tabsize -Ending " : ") (Get-UptimePerso)
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "TimeZone" -Size $Tabsize -Ending " : ") (([TimeZoneInfo]::Local).DisplayName)

  #NLA (If Error Message NLA will be marked as KO)
  $NLA_Config=(Get-CimInstance "Win32_TSGeneralSetting "-Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired 2>$null
  if ( $NLA_Config) {Write-colored darkgreen (Align -Variable "NLA" -Size $TabSize -Ending " : ") "OK"} else { Write-colored red (Align -Variable "NLA" -Size $Tabsize -Ending " : ") "KO"}

  #SCCM
  if ((Get-SCCMSiteCode)) {
   if ( (test-path C:\SMSLogs\*JoinDomain*) ) {
    $installer=get-content "C:\SMSLogs\*JoinDomain*" | select-string "InstallerUserName" | get-unique | ForEach-Object { $_.Line.Split(":")[1].Trim()}
   }
   if ($installer) { Write-Colored -Color $defaultblue -NonColoredText " (Installed by : " "$installer" -nonewline ; write-Colored "Black" ")" } else {write-blank}
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "SCCM Site Code" -Size $Tabsize -Ending " : ") (Get-SCCMSiteCode)
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Business Category" -Size $Tabsize -Ending " : ") (Get-BusinessCategory)
  }

  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Swap" -Size $Tabsize -Ending " : ") (Get-Swap)

  #Get Proxy Settings
  # ([System.Net.WebProxy]::GetDefaultProxy()).Address

  #Bitlocker
  if (Assert-IsAdmin) {
   Try {
    Get-BitlockerVolume | Sort-Object MountPoint | ForEach-Object {
     Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Bitlocker $($_.MountPoint)" -Size $Tabsize -Ending " : ") ("$($_.VolumeStatus)")
    }
   } Catch {
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Bitlocker" -Size $Tabsize -Ending " : ") "Not Available"
   }
  }

  #Secure Boot
  if (Assert-IsAdmin) {
   Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Secure Boot" -Size $Tabsize -Ending " : ") $(Try {Confirm-SecureBootUEFI -ErrorAction Stop} catch {$False})
  }

  #Fast Boot
  $FastBootBinary = Try {
   (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled
  } catch {
   ""
  }
  if ($FastBootBinary -eq 0) {
   $FastBoot = 'Disabled'
  } elseif ( $FastBootBinary -eq 1 ) {
   $FastBoot = 'Enabled'
  } else {
   $FastBoot = "Unknown"
  }
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Fast Boot" -Size $Tabsize -Ending " : ") -ColoredText $FastBoot

  #SMB1 Check
  if (Assert-IsAdmin) {
   $SMB1Enabled=(Get-SmbServerConfiguration).EnableSMB1Protocol
   if ($SMB1Enabled) {$SMBColor = "Red"} else {$SMBColor = "Green"}
   Write-Colored -Color $SMBColor -NonColoredText (Align -Variable "SMB1 Enabled" -Size $Tabsize -Ending " : ") -ColoredText $SMB1Enabled
  }

  #Credential Guard

  # Info : https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity
  Try {
   $CredentialGuardInfo=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
   $VirtualizationBasedSecurityStatus=switch ($CredentialGuardInfo.VirtualizationBasedSecurityStatus)
   {
    0 {"Red","Disabled"}
    1 {"Yellow","Enabled but not Running"}
    2 {"Green","Enabled and Running"}
   }
   Write-Colored -Color $VirtualizationBasedSecurityStatus[0] -NonColoredText (Align -Variable "Virtualization Security" -Size $Tabsize -Ending " : ") -ColoredText $VirtualizationBasedSecurityStatus[1]

   if ($CredentialGuardInfo.SecurityServicesRunning[0] -eq 0) {
    Write-Colored -Color "red" -NonColoredText  (Align -Variable "Credential Guard" -Size $Tabsize -Ending " : ") "No Service Running"
   } else {
    if ($CredentialGuardInfo.SecurityServicesRunning -Contains('1') ){ Write-Colored -Color "Green" -NonColoredText (Align -Variable "Credential Guard" -Size $Tabsize -Ending " : ") "Windows Defender Credential Guard is running" }
    if ($CredentialGuardInfo.SecurityServicesRunning -Contains('2') ){ Write-Colored -Color "Green" -NonColoredText (Align -Variable "Credential Guard" -Size $Tabsize -Ending " : ") "Memory integrity is running (HVCI)" }
    if ($CredentialGuardInfo.SecurityServicesRunning -Contains('3') ){ Write-Colored -Color "Green" -NonColoredText (Align -Variable "Credential Guard" -Size $Tabsize -Ending " : ") "System Guard Secure Launch is running" }
    if ($CredentialGuardInfo.SecurityServicesRunning -Contains('4') ){ Write-Colored -Color "Green" -NonColoredText (Align -Variable "Credential Guard" -Size $Tabsize -Ending " : ") "SMM Firmware Measurement is running" }
   }

  } Catch {
   Write-Colored -Color "red" -NonColoredText  (Align -Variable "Credential Guard" -Size $Tabsize -Ending " : ") "Error checking status"
  }


  $LSA_Info = Try { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" } catch { "" }
  $RunAsPPLColor="Red"
  if ($LSA_Info.RunAsPPL -eq 0) {
    $RunAsPPL = 'Disabled' ; $RunAsPPLColor = "Red"
  } elseif ( $LSA_Info.RunAsPPL -eq 1 ) { $RunAsPPL = 'Enabled with UEFI Lock' ; $RunAsPPLColor = "Green"
  } elseif ( $LSA_Info.RunAsPPL -eq 2 ) { $RunAsPPL = 'Enabled without UEFI Lock' ; $RunAsPPLColor = "DarkYellow"
  } else { $RunAsPPL = "Unknown" ; $RunAsPPLColor = "Red" }
  if ($LSA_Info.RunAsPPLBoot -gt 0 ) { $RunAsPPLOnBoot = 'Enabled' ; $RunAsPPLOnBootColor = "Green" } else { $RunAsPPLOnBoot = 'Disabled' ; $RunAsPPLOnBootColor = "Red" }

  Write-Colored -Color $RunAsPPLColor -NonColoredText (Align -Variable "RunAsPPL" -Size $Tabsize -Ending " : ") -ColoredText $RunAsPPL
  Write-Colored -Color $RunAsPPLOnBootColor -NonColoredText (Align -Variable "RunAsPPLOnBoot" -Size $Tabsize -Ending " : ") -ColoredText $RunAsPPLOnBoot

  #Anvitirus
  $AntivirusResult=Get-AntiVirus
  If ($AntivirusResult) {
   $Count=0
   $AntivirusResult | ForEach-Object {
    $Count++
    Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Antivirus [$Count]" -Size $Tabsize -Ending " : ") $_.DisplayName -NoNewLine
    Write-Colored -Color $defaultblue " - " -NoNewLine
    if ($_.'Real-time Protection Status' -ne 'On') {$Color='Red'} else {$Color='Green'}
    Write-Colored -Color $Color -ColoredText "$($_.'Real-time Protection Status') " -NoNewLine
    if ($_.'Definition Status' -ne 'Up To Date') {$Color='Red'} else {$Color='Green'}
    Write-Colored -Color $Color -ColoredText "[$($_.'Definition Status')]"
   }
  }

 }
}
Function Get-LocalDomainInfo {
 $TabSize=20
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Server Hostname" -Size $Tabsize -Ending " : ") $env:computerName
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Server FQDN" -Size $Tabsize -Ending " : ") ([System.Net.Dns]::GetHostByName(($env:computerName))).HostName
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Server Domain" -Size $Tabsize -Ending " : ") (Get-CimInstance WIN32_ComputerSystem).Domain
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "User DNS Domain" -Size $Tabsize -Ending " : ") $env:USERDNSDOMAIN
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "User Domain" -Size $Tabsize -Ending " : ") $env:USERDOMAIN
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "User Domain Roaming" -Size $Tabsize -Ending " : ") $env:USERDOMAIN_ROAMINGPROFILE
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Logon Server" -Size $Tabsize -Ending " : ") $env:LOGONSERVER
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
 Write-Colored -NonColoredText (Align -Variable "$($_.OperationMasterRoles) ($($_.Domain))" -Size $Tabsize -Ending " : ") -ColoredText "$($_.Name) ($($_.IPV4Address))"
 }
}
Function Get-WindowsVersion {
 Param (
  $ServerName,
  [Switch]$Quick
 )
 Try {
  if (! ($Quick)) {
   #Check Command Availability (PS 5.1+)
   if ($ServerName) {
    $AdvCommandAvailable=invoke-command -ComputerName $ServerName -ScriptBlock {$(get-command Get-ComputerInfo -ErrorAction SilentlyContinue)}
   } else {
    $AdvCommandAvailable=$(get-command Get-ComputerInfo -ErrorAction SilentlyContinue)
   }
  }

  $BuildVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion

  if ($AdvCommandAvailable ) {
   if ($ServerName) {
    $ComputerInfo=invoke-command -ComputerName $ServerName -ScriptBlock {Get-ComputerInfo -Property OsName,WindowsVersion,OsHardwareAbstractionLayer,BiosFirmwareType,OsLanguage,OsArchitecture} -ErrorAction Stop
   } else {
    $ComputerInfo=Get-ComputerInfo -Property OsName,WindowsVersion,OsHardwareAbstractionLayer,BiosFirmwareType,OsLanguage,OsArchitecture
   }

   if ($($ComputerInfo.WindowsVersion)) { $OsSpecificVersion=$ComputerInfo.WindowsVersion } else { $OsSpecificVersion="("+$ComputerInfo.OsHardwareAbstractionLayer+")" }
   if ($($ComputerInfo.BiosFirmwareType.Value)) { $BiosType=$ComputerInfo.BiosFirmwareType.Value } else { $BiosType=$ComputerInfo.BiosFirmwareType }
   $version=$ComputerInfo.OsName + " " + $OsSpecificVersion + " [" + $BiosType + "]" + "[" + $ComputerInfo.OsLanguage + "]" + "[" + $ComputerInfo.OsArchitecture + "]" + "[" + $BuildVersion + "] "

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
   $version="$OSNAME $OSSP ($OSBUILD$Revision | $OSArchitecture | $BuildVersion)"
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

 if (! ($result)) {Write-Colored -Color "red" -NonColoredText  "" "Server is not activated"} else {
  ($result | out-string).split("`r`n") | Where-Object { $_ }
  if ($result.KeyServer -eq "No Key Server Defined" -and $result.KeyServerDiscovered -eq "No Key Server Discovered") {Write-Colored -Color "red" -ColoredText "No KMS server found"}
  Write-Colored -Color "darkgreen" -ColoredText "Server is Activated"
 }
 write-blank
 $LicenseKey=(Get-CimInstance -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey
 if (! $LicenseKey) {$LicenseKey="Not found"}
 Write-Colored -Color $defaultblue -NonColoredText "Windows License Key : " $LicenseKey
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
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "OS Language" -Size $alignsize -Ending " : " ) $PsUICulture
  #get-culture | format-list -property * => Get all Regional Properties
  $RegionalInfo = get-culture
  $RegionalInfoFull=$RegionalInfo.Name+" [ "+$RegionalInfo.DisplayName+" ]"
  Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Regional Settings" -Size $alignsize -Ending " : " ) $RegionalInfoFull

  #$PsCulture => Get Only Name of Regional Settings
}
Function Get-LangForAllUser {
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command" ; return}
 New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
 $ObjUserList=@()
 foreach( $user in $((Get-ChildItem HKU:\).PSChildName | Sort-Object)) {
  try {$DateFormat=(Get-ItemProperty -ErrorAction SilentlyContinue -Path "HKU:\$user\Control Panel\International")} catch { Write-Error "Nothing here" }
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
  If ($_.FeatureType -eq "Role") { Write-Colored -Color "Magenta" -NonColoredText ("   " *$_.Depth+"[") -ColoredText "R" -nonewline} else { Write-Colored -Color $defaultblue -NonColoredText ("   " *$_.Depth+"[") -ColoredText "F" -nonewline}
  write-colored -NonColoredText "] " -ColoredText ($_.DisplayName+" ("+$_.Name+")")
 }
 $ProgressPreference = "Continue";
}
Function Get-KMS {
 $KMSServerList=(nslookup -type=srv _vlmcs._tcp 2>$errormessage | Select-Object -skip 3 | select-string -notmatch -pattern "internet address =|nameserver =")
 # if ( $KMSServerList[0].line.contains("DNS request timed out") ) { Write-Colored -Color "red" -NonColoredText  "" "No kms server found" ; return}
 if ( $KMSServerList | select-string "timeout" )  { Write-Colored -Color "red" -NonColoredText  "" "DNS request timed out" ; return}
 $KMSServerList_Split = $KMSServerList -replace "_vlmcs._","__SplitHere" -split "SplitHere" -replace "\s+"," " -join "," -split "__" -replace ", ","," -replace "^,","" -notmatch '^\s*$'

 foreach($server in $KMSServerList_Split) {
  $server_line=($server | Select-string -pattern ",").line.split(',')
  $Priority=$server_line[1].TrimStart("priority =")
  $Weight=$server_line[2].TrimStart("weight =")
  $Port=$server_line[3].TrimStart("port =")
  $ServerName=$server_line[4].TrimStart("svr hostname =")

  Write-Colored -Color $defaultblue -NonColoredText "Server : " (Align -Variable $ServerName 20) -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " | Port : " (Align -Variable $Port 4) -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " | Priority : " (Align -Variable $Priority 2) -nonewline
  Write-Colored -Color $defaultblue -NonColoredText " | Weight : " (Align -Variable $Weight 2) -nonewline
  if ( ! (Test-Port $ServerName $Port) ) { Write-Colored -Color "red" -NonColoredText  "| Access : " "KO" } else { write-colored "DarkGreen" "| Access : " "OK" }
 }

}
Function Get-TimeZoneCIM {
 #Does not seem to be the same as the clock (must check)
 # [TimeZoneInfo]::Local
 (Get-CimInstance -ClassName win32_timezone).Caption
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

 } catch {Write-Colored -Color "red" -NonColoredText  "" $error[0]}

 $AllHotFix | Sort-Object HotfixID | Where-Object {
  $globalcount++
  #Color specified hotfixes
  if ($KBInstalled -contains $_.HotfixID) {$color="red"} else { $color=$defaultblue }
  #Last occurence global
  if ($globalcount -eq $AllHotFix.count -or ! $AllHotFix.count) {
   #If last occurence is the first of a line
   # if ($count -ne 0 ) {write-colored -NonColoredText " | " -nonewline}
   Write-Colored -Color $Color -NonColoredText " | " (Align -Variable $_.HotfixID -Size $alignsize) -nonewline
   Write-Colored -Color $Color -NonColoredText " |"
   Write-StarLine "-" ([console]::foregroundcolor)
  }
  #First occurence per line
  elseif ($count -eq 0 ) { Write-Colored -Color $Color -NonColoredText " | " (Align -Variable $_.HotfixID -Size $alignsize) -nonewline ; $count++}
  #Last occurence per line
  elseif ($count -eq 7 ) { Write-Colored -Color $Color -NonColoredText " | " (Align -Variable $_.HotfixID -Size $alignsize) -nonewline ;  Write-Colored -Color $Color -NonColoredText " |" ; $count=0}
  #All other occurence
  else { Write-Colored -Color $Color -NonColoredText " | " (Align -Variable $_.HotfixID -Size $alignsize) -nonewline ; $count++}
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
 } catch {Write-Colored -Color "Red" -ColoredText $Error[0] ; return}
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
  Write-Colored -Color "Red" -ColoredText $Error[0].Exception.Message
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
Function Get-EventLogPCNSSVC {
 Param (
  $PCNSSVCServer
 )
 Get-WinEvent -ComputerName $PCNSSVCServer -FilterHashtable @{LogName='application';ProviderName='PCNSSVC';ID=2100} | `
  Select-Object @{Name="Date";Expression={Format-Date $_.TimeCreated}},
   @{Name="UpdatedUser";Expression={$_.Properties[2].value}},
   @{Name="MIM_SRV_ID";Expression={$_.Properties[3].value}}
}
Function Get-EventLogLockedAccounts { # Check all latest lockout accounts (needs access to PDC and must be elavated)
 Param (
  $PDCEmulatorServer = (Get-ADDomain).pdcemulator
 )
 Get-EventLog -LogName security -ComputerName $PDCEmulatorServer -InstanceId 4740
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
  # Because of a bug, it will not list PPP (VPN) connections : https://docs.microsoft.com/en-US/troubleshoot/windows/win32/win32-networkadapterconfiguration-unable-retrieve-information
  $NetworkInfo=Get-CimInstance Win32_NetworkAdapter -property * | where-object MACAddress | Sort-Object NetConnectionStatus

  $NetworkInfo | foreach-object {
   if ( (! $NoFilter) -and (! $_.NetConnectionStatus ) ) { Return }
   if ((($_.NetConnectionStatus -eq "0") -or ($_.NetConnectionStatus -eq "7")) -and (! $ShowDisconnected)) {Return}

  Write-StarLine "-" ; write-centered $_.MACAddress "Magenta" ; Write-StarLine "-"
   write-colored $fontcolor (Align -Variable "Interface Name " -Size $alignsize -Ending " : ") $_.ProductName
   write-colored $fontcolor (Align -Variable "Interface Alias " -Size $alignsize -Ending " : ") $_.NetConnectionID
   write-colored $fontcolor (Align -Variable "Interface Index " -Size $alignsize -Ending " : ") $_.InterfaceIndex
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
    write-colored $ConnectionStatusColor (Align -Variable "Interface Status " -Size $alignsize -Ending " : ") $ConnectionStatus[0]
   } else {
   }

   write-colored $fontcolor (Align -Variable "Interface Last Reset " -Size $alignsize -Ending " : ") $_.TimeOfLastReset
   if ( (Assert-IsCommandAvailable Get-NetAdapter -NoError) ) {
    $NetworkInfoHard=Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
    If (! $NetworkInfoHard) {Write-Blank ; Return}
    Write-Colored -Color $fontcolor -NonColoredText (Align -Variable "LinkSpeed " -Size $alignsize -Ending " : ") -ColoredText $NetworkInfoHard."LinkSpeed" -NoNewLine
    if (! $NetworkInfoHard.FullDuplex) {
      if ($ConnectionStatus[0] -ne "Connected") {
        Write-Colored "Gray" -ColoredText " (Not connected)"
       } else {
       write-Colored -Color "Red" -ColoredText " (NOT FULL DUPLEX)"
       }
    }else {
     Write-Colored -Color "Green" -ColoredText " (Full Duplex)"
    }
    write-colored -Color $fontcolor -NonColoredText (Align -Variable "Driver " -Size $alignsize -Ending " : ")  -nonewline
    Write-Colored -Color $fontcolor -NonColoredText "Provider " -ColoredText $NetworkInfoHard.DriverProvider -nonewline
    Write-Colored -Color $fontcolor -NonColoredText " | Version " -ColoredText $NetworkInfoHard.DriverVersion -nonewline
    Write-Colored -Color $fontcolor -NonColoredText " | Date " -ColoredText $NetworkInfoHard.DriverDate
  }
  if ($ConnectionStatus[0] -ne "Connected") { Return }

  $NetworkConfig=Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object InterfaceIndex -eq $_.InterfaceIndex

  if ($NetworkConfig.IPAddress.count -eq 0) { Return }

  write-Blank
  $count=0 ; while ($count -lt $NetworkConfig.IPAddress.count) {
   if (([IpAddress]$NetworkConfig.IPAddress[$count]).AddressFamily -eq "InterNetworkV6") { $type="IPv6" } else { $type="IPv4" }
   write-colored $fontcolor (Align -Variable "IP Address($count) - $type" -Size $alignsize -Ending " : ") (Align -Variable $NetworkConfig.IPAddress[$count] 40) -nonewline
   write-colored $fontcolor (Align -Variable "Mask($count)" 8 ": ") $NetworkConfig.IPSubnet[$count]
   $count++
  }

  if ($NetworkConfig.DefaultIPGateway) {
   write-blank
   write-colored $fontcolor (Align -Variable "Gateway - IPv4" -Size $alignsize -Ending " : ") $NetworkConfig.DefaultIPGateway[0]
   if ($NetworkConfig.DefaultIPGateway.length -gt 1) {
    $count=1
    write-colored $fontcolor (Align -Variable "Gateway - IPv6" -Size $alignsize -Ending " : ") $NetworkConfig.DefaultIPGateway[$count]
    $count++
   }
  }

  write-blank

  $count=0 ; $NetworkConfig.DNSServerSearchOrder | Where-Object { write-colored $fontcolor (Align -Variable "DNS Servers ($count)" -Size $alignsize -Ending " : ") $_ ; $count++ }

  if ($NetworkConfig.WINSPrimaryServer) {write-blank; write-colored $fontcolor (Align -Variable "WINS Server (0)" -Size $alignsize -Ending " : ") ($NetworkConfig.WINSPrimaryServer)}
  if ($NetworkConfig.WINSSecondaryServer) {write-colored $fontcolor (Align -Variable "WINS Server (1)" -Size $alignsize -Ending " : ") ($NetworkConfig.WINSSecondaryServer)}

  write-Blank
  if (! $NetworkConfig.DHCPServer) { $DHCP_Server="N/A" } else { $DHCP_Server=$NetworkConfig.DHCPServer }
  write-colored $fontcolor (Align -Variable "DHCP Server" -Size $alignsize -Ending " : ") $DHCP_Server -nonewline
  write-colored $fontcolor " (Enabled: " $NetworkConfig.DHCPEnabled -nonewline
  write-colored -NonColoredText ")`n"

  write-colored $fontcolor(Align -Variable "DNS Domain" -Size $alignsize -Ending " : ") $NetworkConfig.DNSDomain

  $count=0 ; $NetworkConfig.DNSDomainSuffixSearchOrder | Where-Object { write-colored $fontcolor (Align -Variable "DNS Suffix Search Order ($count)" -Size $alignsize -Ending " : ") $_ ; write-blank ; $count++ }

  # Format-PrintLineByLine $_.DNSDomainSuffixSearchOrder $fontcolor

  write-colored $fontcolor (Align -Variable "IP Metric " -Size $alignsize -Ending " : ") $NetworkConfig.IPConnectionMetric

  write-blank

  if ( ! $NetworkConfig.FullDNSRegistrationEnabled) { $color="red" } else { $color="darkgreen" }
  Write-Colored -Color $Color -NonColoredText (Align -Variable "DNS Auto Register" -Size $alignsize -Ending " : ") $NetworkConfig.FullDNSRegistrationEnabled -NoNewLine
  if ( $NetworkConfig.DomainDNSRegistrationEnabled) { $color="red" } else { $color="darkgreen" }
  Write-Colored -Color $Color -NonColoredText " (Uses Suffix : " $NetworkConfig.DomainDNSRegistrationEnabled -NoNewLine
  Write-Colored -Color $Color -NonColoredText ")"

  if ($NetworkConfig.WINSEnableLMHostsLookup) { $color="red" } else { $color="darkgreen" }
  Write-Colored -Color $Color -NonColoredText (Align -Variable "WINS Search for LMHosts" -Size $alignsize -Ending " : ") $NetworkConfig.WINSEnableLMHostsLookup -nonewline
  if ($NetworkConfig.DNSEnabledForWINSResolution) { $color="red" } else { $color="darkgreen" }
  Write-Colored -Color $Color -NonColoredText " (WINS DNS Resolution : " $NetworkConfig.DNSEnabledForWINSResolution -nonewline
  Write-Colored -Color $Color -NonColoredText ")"

  if ($NetworkConfig.TcpipNetbiosOptions -ne 2) { $color="red" } else { $color="darkgreen" }
  $NetBiosValue = switch ($NetworkConfig.TcpipNetbiosOptions) {
   "0"  {"Enabled via DHCP"; break}
   "1"   {"Enabled"; break}
   "2"   {"Disabled"; break}
  }
  Write-Colored -Color $Color -NonColoredText (Align -Variable "NETBIOS" -Size $alignsize -Ending " : ") $NetBiosValue

 }
 } Catch {
  Write-Colored -Color "Red" -ColoredText $Error[0]
 }
}
Function Get-IP {
 Param (
  [Switch]$ShowSubInterface, # Show Interfaces without Index (Sub Interfaces linked to real cards
  [Switch]$ShowDisconnected, # Show all Interfaces
  [Switch]$ShowDriverInfo, # Slower
  [Switch]$ShowBindings, # Slower
  $MacFilter
 )
 $alignsize=35
 $fontcolor="Cyan"
 $ErrorActionPreference="Stop"

 # Get Interface info

 $InterfaceList=[System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object Name -ne 'Loopback Pseudo-Interface 1' | Sort-Object Name | ForEach-Object {
  if ((($_.OperationalStatus -in "Down","NotPresent") -or ($_.Speed -eq '-1')) -and ! ($ShowDisconnected)) {Return}
  $IpProperties=$_.GetIPProperties()
  $IpStatistics=$_.GetIPStatistics()
  $IpMetricInfo=Get-NetIPInterface -InterfaceAlias $_.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
  if ((! $IpMetricInfo.ifIndex) -and (! $ShowSubInterface) ) {Return}
  if (! $IpMetricInfo -and ! $ShowDisconnected -and ! $ShowSubInterface) {return}
  New-Object PSObject -Property @{
   MAC=$_.GetPhysicalAddress()
   Name=$_.Name
   Index=$IpMetricInfo.ifIndex
   Metric=$IpMetricInfo.InterfaceMetric
   AutomaticMetric=$IpMetricInfo.AutomaticMetric
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

 # Get all DNS info not be available on interface
 $DNSInfo = Get-DnsClient

 # Get all Route info
 $RouteInfo = Get-NetRoute

 if ($MacFilter) {
  $InterfaceList = $InterfaceList | Where-Object Mac -eq $MacFilter
 }

 if ($HideSubInterface) {
  $InterfaceList = $InterfaceList | Where-Object
 }

 $InterfaceList | Sort-Object OperationalStatus,Metric | ForEach-Object {
  Write-StarLine -character "-"
  if ($_.Mac.ToString().Trim() -eq "") {
   $DeviceDisplay = $_.Name
   $MAC = ""
  } else {
   $MAC = Convert-MacAddressFormat -MacAddress $_.MAC
   $DeviceDisplay = "$($_.Name) [$MAC]"
  }
  Write-Centered -Color 'Magenta' -message $DeviceDisplay
  Write-StarLine -character "-"

  # Interface info
  write-colored $fontcolor (Align -Variable "Interface Name " -Size $alignsize -Ending " : ") $_.Name
  if ($MAC) { write-colored $fontcolor (Align -Variable "Interface MAC " -Size $alignsize -Ending " : ") "$($_.MAC) ($MAC)" }
  write-colored $fontcolor (Align -Variable "Interface Description " -Size $alignsize -Ending " : ") $_.Description
  write-colored $fontcolor (Align -Variable "Interface Type " -Size $alignsize -Ending " : ") $_.NetworkInterfaceType
  if ($_.Metric) { write-colored $fontcolor (Align -Variable "Interface Metric " -Size $alignsize -Ending " : ") "$($_.Metric)$(if ($_.AutomaticMetric) {" (Automatic)"})" }
  if ($_.Index) { write-colored $fontcolor (Align -Variable "Interface Index " -Size $alignsize -Ending " : ") $_.Index }
  if ($_.OperationalStatus -eq "Up") {$StatusColor = "Green"} elseif ($_.OperationalStatus -eq "Down") {$StatusColor = "Red"} else {$StatusColor = "DarkYellow"}
  write-colored $StatusColor (Align -Variable "Interface Status " -Size $alignsize -Ending " : ") $_.OperationalStatus
  if ($_.InterfaceSpeed) { write-colored $fontcolor (Align -Variable "Interface Speed " -Size $alignsize -Ending " : ") $_.InterfaceSpeed }
  if ($_.DNSSuffix) {write-colored $fontcolor (Align -Variable "Interface DNS Suffix " -Size $alignsize -Ending " : ") $_.DNSSuffix}
  $RouteInfoForThisInterface = $RouteInfo | Where-Object ifIndex -eq $_.Index
  if ($RouteInfoForThisInterface) {
   write-colored $fontcolor (Align -Variable "Number of routes " -Size $alignsize -Ending " : ") $RouteInfoForThisInterface.Count
  }

  # Driver info
  if ($ShowDriverInfo -and $_.Index) {
   $AdapterInfo = Get-NetAdapter -InterfaceIndex $_.Index -ErrorAction SilentlyContinue | Select-Object DriverProvider,DriverVersionString,NdisVersion,DriverDescription,DriverDate
   if ($AdapterInfo) {
    write-colored $fontcolor (Align -Variable "Driver Description " -Size $alignsize -Ending " : ") $AdapterInfo.DriverDescription
    write-colored $fontcolor (Align -Variable "Driver Info " -Size $alignsize -Ending " : ") $($AdapterInfo.DriverProvider,"[",$AdapterInfo.DriverVersionString,"]","(",$AdapterInfo.DriverDate,")")
    write-colored $fontcolor (Align -Variable "Driver Ndis Version " -Size $alignsize -Ending " : ") $AdapterInfo.NdisVersion
   }
  }

    # Driver info
    if ($ShowBindings -and $_.Index) {
     $AdapterBindings = ( Get-NetAdapter -InterfaceIndex $_.Index -ErrorAction SilentlyContinue  | Get-NetAdapterBinding | Where-Object Enabled ).ComponentID -join ","
     if ($AdapterBindings) {
      write-colored $fontcolor (Align -Variable "Enabled bindings " -Size $alignsize -Ending " : ") $AdapterBindings
     }
    }

  # Network Category
  if ($_.IP) {
   If (Assert-IsCommandAvailable Get-NetConnectionProfile) {
    try {
     $ConnectionProfile=Get-NetConnectionProfile -InterfaceIndex $_.Index -ErrorAction SilentlyContinue
     # Network Category
     if ($ConnectionProfile.NetworkCategory -eq 'Public') {$StatusColor = "Red"} else { $StatusColor="Green" }
     write-colored $StatusColor (Align -Variable "Network Category " -Size $alignsize -Ending " : ") $ConnectionProfile.NetworkCategory
     # Internet Connectivity (IPv4)
     if ($ConnectionProfile.IPv4Connectivity -ne 'Internet') {$StatusColor = "Red"} else { $StatusColor="Green" }
     write-colored $StatusColor (Align -Variable "Internet Access (IPv4)" -Size $alignsize -Ending " : ") $ConnectionProfile.IPv4Connectivity
     # Internet Connectivity (IPv6)
     if ($ConnectionProfile.IPv6Connectivity -ne 'Internet') {$StatusColor = "Red"} else { $StatusColor="Green" }
     write-colored $StatusColor (Align -Variable "Internet Access (IPv6)" -Size $alignsize -Ending " : ") $ConnectionProfile.IPv6Connectivity
    } Catch {
     Write-Error "Nothing here (Category Info) ($($Error[0]))"
    }
   }

   # IP information
   $count=0
   $countIPv6=0
   $_.IP | Sort-Object PrefixLength | ForEach-Object {
    if ($_.PrefixLength -le "32") {
     # IPv4
     if ($count -eq 0) {
      write-colored $fontcolor (Align -Variable "IP" -Size $alignsize -Ending " : ") "$($_.Address) | $($_.IPv4Mask) ($($_.PrefixLength)) | Source : $($_.PrefixOrigin)"
     }
     else {
      write-colored $fontcolor (Align -Variable "IP ($count)" -Size $alignsize -Ending " : ") "$($_.Address) | $($_.IPv4Mask) ($($_.PrefixLength)) | Source : $($_.PrefixOrigin)"
     }
     $count++
    }
    if (($_.PrefixLength -gt "32")) {
     # IPv6
     if ($countIPv6 -eq 0) {
      write-colored $fontcolor (Align -Variable "IPv6" -Size $alignsize -Ending " : ") "$($_.Address) ($($_.PrefixLength)) | Source : $($_.PrefixOrigin)"
     }
     else {
      write-colored $fontcolor (Align -Variable "IPv6 ($countIPv6)" -Size $alignsize -Ending " : ") "$($_.Address) ($($_.PrefixLength)) | Source : $($_.PrefixOrigin)"
     }
     $countIPv6++
    }
   }
  }

  # Gateway information
  if ($_.Gateway) {
   $_.Gateway | ForEach-Object {
    $IPTypeCheck = ([IPAddress]$_).AddressFamily
    $IPType = if ($IPTypeCheck -eq "InterNetworkV6") {"IPv6"} elseif ($IPTypeCheck -eq "InterNetwork") {"IPv4"}
    write-colored $fontcolor -NonColoredText (Align -Variable "Gateway $IPType" -Size $alignsize -Ending " : ") -ColoredText $_
   }
  }

  # WINS information
  if ($_.WINS) {
   $count=0
   $_.DNS | ForEach-Object {
    $count++
    write-colored $fontcolor (Align -Variable "WINS Server ($count)" -Size $alignsize -Ending " : ") $_
   }
  }

  # DHCP information
  if ($_.DHCP) {write-colored $fontcolor (Align -Variable "DHCP Server" -Size $alignsize -Ending " : ") $_.DHCP}

  # DNS information
  if ($_.DNS) {
   write-colored $fontcolor -NonColoredText (Align -Variable "DNS Server " -Size $alignsize -Ending " : ") -NoNewLine
   $count=0
   $_.DNS | ForEach-Object {
    if ($count -eq 0) {write-colored -Color $fontcolor -ColoredText $_ -NoNewLine} else {write-colored -Color $fontcolor -ColoredText " | $($_)" -NoNewLine}
    $count++
   }
   Write-Host
  }
  $DNSInfoForThisInterface = $DNSInfo | Where-Object InterfaceIndex -eq $_.Index
  if ($DNSInfoForThisInterface) {
   if ($DNSInfoForThisInterface.Suffix) {
    write-colored $fontcolor (Align -Variable "DNS Suffix " -Size $alignsize -Ending " : ") $DNSInfoForThisInterface.Suffix
   }
   $DNSSuffixSearchListCount = 0
   $DNSInfoForThisInterface.SuffixSearchList | ForEach-Object {
    write-colored $fontcolor (Align -Variable "DNS SuffixSearchList [$DNSSuffixSearchListCount]" -Size $alignsize -Ending " : ") $DNSInfoForThisInterface.SuffixSearchList[$DNSSuffixSearchListCount]
    $DNSSuffixSearchListCount++
   }
   if ($DNSInfoForThisInterface.RegisterThisConnectionsAddress) {$StatusColor = "Green"} else { $StatusColor="Red" }
   write-colored $StatusColor (Align -Variable "DNS RegisterConnectionsAddress " -Size $alignsize -Ending " : ") $DNSInfoForThisInterface.RegisterThisConnectionsAddress
   if ($DNSInfoForThisInterface.UseSuffixWhenRegistering) {$StatusColor = "Red"} else { $StatusColor="Green" }
   write-colored $StatusColor (Align -Variable "DNS UseSuffixWhenRegistering " -Size $alignsize -Ending " : ") $DNSInfoForThisInterface.UseSuffixWhenRegistering
  }
  if ($_.Sent) {write-colored $fontcolor (Align -Variable "Sent | Received " -Size $alignsize -Ending " : ") "$($_.Sent) | $($_.Received)"}
 }

 # NRPT Information
 $NRPTPolicies = Get-DnsClientNrptPolicy -Effective
 if ($NRPTPolicies) {
  Write-StarLine -character "-"
  Write-Centered -Color 'Magenta' "NRPT Policies"
  Write-StarLine -character "-"
  $NRPTPolicies | ForEach-Object {
   write-colored $fontcolor (Align -Variable "$($_.Namespace) " -Size $alignsize -Ending " : ") $_.NameServers
  }
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
  $colInterfaces = Get-CimInstance -ClassName Win32_PerfFormattedData_Tcpip_NetworkInterface |Select-Object BytesTotalPersec, CurrentBandwidth,PacketsPersec|Where-Object {$_.PacketsPersec -gt 0}
   foreach ($interface in $colInterfaces) {
    Write-Colored -Color $defaultblue -NonColoredText "`rCurrent bandwith: " (Align -Variable ((Format-FileSize $interface.BytesTotalPersec)+"/s") 25) -nonewline
    $totalBandwidth = $totalBandwidth + $interface.BytesTotalPersec ; $count++
   }
   Start-Sleep -milliseconds 150
   # recalculate the remaining time
   $timeSpan = new-timespan $(Get-Date) $endTime
}

 $averageBandwidth = $totalBandwidth / $count
 # $value = "{0:N2}" -f $averageBandwidth
 $value = ((Format-FileSize $averageBandwidth)+"/s")
 Write-Colored -Color $defaultblue -NonColoredText "Average Bandwidth after $durationinminutes minutes: " $value

}
Function Get-DNSResponseTime {
 Param (
  $DNSServer=(Get-DnsClientServerAddress | Where-Object {($_.AddressFamily -eq "2") -and ($_.ServerAddresses)})[0].ServerAddresses[0],
  $DurationInMinutes="0.5",
  $SleepDurationInMs='150',
  $Request,
  [Switch]$DNSServerCheck
 )

 $startTime = get-date
 $endTime = $startTime.addMinutes($durationinminutes)
 $timeSpan = new-timespan $startTime $endTime

 if (! $Request) { $Request=$DNSServer }

 $count = 0 ; $TotalResult = 0 ; $AverageResult = 0 ; $MinResult = 10000 ; $MaxResult = 0

 if ($DNSServerCheck) {
  try {
   $DNSServerFQDN=(Resolve-DnsName $DNSServer -ErrorAction Stop -QuickTimeout -DnsOnly).NameHost
  Write-Colored -Color $defaultblue -ColoredText "Testing response time using DNS Server $DNSServer ($DNSServerFQDN) during $DurationInMinutes minutes (destination : $Request) (Pause time : $SleepDurationInMs`ms)"
  } catch {
   write-host -foregroundcolor "Red" $Error[0]
   Return
  }
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
 Write-Colored -Color $defaultblue -NonColoredText "Average response time after $durationinminutes minutes: " "$AverageResult ms" -NoNewLine
 Write-Colored -Color $defaultblue -NonColoredText " (Min : " $MinResult -NoNewLine
 Write-Colored -Color $defaultblue -NonColoredText " - Max : " $MaxResult -NoNewLine
 Write-Colored -Color $defaultblue -NonColoredText ")"
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
   $PathFilter="*",
   $LocalAddress,
   $LocalPort,
   $RemoteAddress,
   $RemotePort,
   [ValidateSet('Bound','Closed','CloseWait','Closing','DeleteTCB','Established','FinWait1','FinWait2','LastAck','Listen','SynReceived','SynSent','TimeWait')]$State
  )
  $NetConnectionParams = $PSBoundParameters
  $NetConnectionParams.Remove('PathFilter') | Out-Null
  Get-NetTCPConnection @NetConnectionParams | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,
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
 #Found here https://gallery.technet.microsoft.com/scriptcenter/Listen-Port-Powershell-8deb99e4
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
  $ServerName = $env:COMPUTERNAME,
  [Switch]$Filter
 )
 try {
  if ($ServerName -eq $env:COMPUTERNAME) {
   $result = Get-CimInstance Win32_Service -ErrorAction Stop
  } else {
   $result = Get-CimInstance Win32_Service -ErrorAction Stop -ComputerName $ServerName
  }
  if ($Filter) {
   $result = $result | Where-Object {
    $_.PathName -notlike "$env:windir\system32\svchost.exe*" -and
    $_.PathName -notlike "$env:windir\system32\SearchIndexer.exe*" -and
    $_.PathName -notlike "$env:windir\system32\SgrmBroker.exe*" -and
    $_.PathName -notlike "$env:windir\system32\lsass.exe" -and
    $_.PathName -notlike "$env:windir\system32\sppsvc.exe" -and
    $_.PathName -notlike "$env:windir\system32\SecurityHealthService.exe" -and
    $_.PathName -notlike "$env:windir\System32\spoolsv.exe"
   }
  }
  $result = $result | Where-Object { (($_.startmode -eq 'Auto') -or ($_.state -eq 'Running')) }
 } catch {
  write-Colored -Color "Red" -ColoredText $error[0] ; return
 }
 if (! ($result)) {
  Write-Colored "darkgreen" -coloredtext "No service found"
 } else {
  $result | ForEach-Object { Format-TypeServices $._ $ServerName -formattable }
 }
}
Function Get-ServicesFiltered { # Search specific service(s), can do actions on all the services (Start/Stop)
 Param (
  [Switch]$Start,
  [Switch]$Stop,
  $Services=@('')
 )

 #For VmWare : $Services=@('Vmware')
 #For SQL : $Services=@('MSSQL','SQLAgent')

 $ServicesList=Get-CimInstance Win32_Service
 $Result=$Services | ForEach-Object {
  $ServiceName=$_
  $ServicesList | Where-Object {$_.Name -like "*$ServiceName*"}
 }

 if ( ! $result) {write-Colored -Color "Red" -ColoredText "$Services Services Not Found" ; return}

 #Print Service List
 if ((! $Start) -and (! $Stop)) {
  $result | ForEach-Object {Format-TypeServices $._}
 }

 if ($Stop) {
  if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command" ; return}
  $result | ForEach-Object {Write-Colored -Color $defaultblue -NonColoredText "Stopping : " $_.displayname ; Stop-Service -force $_.name }
 }
 if ($Start) {
  if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command" ; return }
  $result | ForEach-Object { Write-Colored -Color $defaultblue -NonColoredText "Starting : " $_.displayname ; Start-Service $_.name }
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
   Write-Colored -Color $defaultblue -NonColoredText "Status : " $_."Scheduled Task State" -nonewline
   Write-Colored -Color $defaultblue -NonColoredText " - Last Run : " $_."Last Run Time"
   Write-Colored -Color $defaultblue -NonColoredText "CommandLine : " $_."Task To Run"
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
   $LogPath="$iClic_TempPath\TasksLogsExport_$(get-date -uformat '%Y-%m-%d').csv"
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

  if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command" ; return}

  try {
  write-host -ForegroundColor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Checking Scheduled Tasks between $StartTime and $EndTime"
  if ($NoFilter) {
   $AllEvents=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';StartTime=$StartTime;EndTime=$EndTime} | `
   Where-Object {($_.Task -ne '314')}
  } else {
   $AllEvents=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';StartTime=$StartTime;EndTime=$EndTime;ID=100,101,102,111,329}
  }

 } catch {
  write-Colored -Color "Red" -ColoredText $error[0] ; return
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
 } catch {write-Colored -Color "Red" -ColoredText $error[0] ; return}

 #Convert XML  to PS Object
 [xml]$xml = try {
  get-content $tempPath -ErrorAction Stop
 } catch {
  write-Colored -Color "Red" -ColoredText $error[0] ; return
 }

 #Computer
 $ComputerResult=$xml.DocumentElement.ComputerResults.GPO | Where-Object {
  # ($_.IsValid -eq $true) -and ($_.Enabled -eq $true) -and ($_.FilterAllowed -eq $true) -and ($_.AccessDenied -eq $False)
  ($_.IsValid -eq $true) -and ($_.Enabled -eq $true)
 } | Select-Object @{LABEL="Computer";EXPRESSION={$ServerToCheck}},
            @{LABEL="User";EXPRESSION={"N/A"}},
            @{LABEL="Type";EXPRESSION={"Computer"}},
            @{LABEL="LinkOrder";EXPRESSION={[int]$_.link.linkorder}},
            @{LABEL="Denied";EXPRESSION={$_.AccessDenied}},
            Name,
            @{LABEL="LinkLocation";EXPRESSION={$_.link.SOMPath}},SecurityFilter | Sort-Object { [int]$_.linkorder[0] }

 #User
 $UserResult=$xml.DocumentElement.UserResults.GPO | Where-Object {
  # ($_.IsValid -eq $true) -and ($_.Enabled -eq $true) -and ($_.FilterAllowed -eq $true) -and ($_.AccessDenied -eq $False)
  ($_.IsValid -eq $true) -and ($_.Enabled -eq $true)
 } | Select-Object @{LABEL="Computer";EXPRESSION={$ServerToCheck}},
            @{LABEL="User";EXPRESSION={$UserToCheck}},
            @{LABEL="Type";EXPRESSION={"User"}},
            @{LABEL="LinkOrder";EXPRESSION={[int]$_.link.linkorder}},
            @{LABEL="Denied";EXPRESSION={$_.AccessDenied}},
            Name,
            @{LABEL="LinkLocation";EXPRESSION={$_.link.SOMPath}},SecurityFilter | Sort-Object { [int]$_.linkorder[0] }

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
 if (!$SQLREQUEST) {write-Colored -Color "Red" -ColoredText "Provide SQL request";return}
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
 if ( ! (test-path $path)) { Write-Colored -Color "red" -NonColoredText  "" "Unavailable path : $path" ; return }
 Get-ItemProperty -Path $path | Format-list -Property *
}
Function Get-FileInfo {
 Param (
  [Parameter(Mandatory=$true)]$path
 )
 if (!$path) { Write-Colored -Color "red" -NonColoredText  "" "Please provide a path" ; return }
 if ( ! (test-path $path)) { Write-Colored -Color "red" -NonColoredText  "" "Unavailable path : $path" ; return }
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
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command"; return}

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
   $physicalmemMB = [int]((Get-CimInstance -Classname Win32_ComputerSystem).TotalPhysicalMemory/1mb)
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
  $Name=(Align -Variable $_.SamAccountName 10)
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
  } catch {
   Write-Error "Nothing here"
  }
 }
 clear-host
 $allmails
 # Get-ADMembersWithMails | Out-File "$iClic_TempPath\ADUsersMails.csv"
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
 catch {Write-Colored -Color "red" -NonColoredText  "" "Server $ServerName does not exist" ; return}
 if ( $GROUPLIST ) { ($GROUPLIST.split(',') | select-string "CN=").line.substring(3) | Sort-Object } else { Write-Colored -Color "red" -NonColoredText  "" "Server $ServerName is not in any group" }
}
Function Get-ADSubnetsOld {
 Param (
  [Parameter(Mandatory=$true)]$AD_site_name
 )
 if ( ! (Assert-IsCommandAvailable "Get-ADRootDSE") ) {return}
 $configNCDN = (Get-ADRootDSE).ConfigurationNamingContext
 $siteContainerDN = ("CN=Sites," + $configNCDN)
 $siteDN = "CN=" + $AD_site_name + "," + $siteContainerDN
 $siteObj = try {Get-ADObject -Identity $siteDN -properties "siteObjectBL", "description", "location"} catch {Write-Colored -Color "red" -NonColoredText  "" $error[0]}
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
 # Get-ADUsersMailsWithNoExchangeAccount | Export-Csv "$iClic_TempPath\ADUsersMailsWithNoExchangeAccount.csv" -encoding "unicode" -notypeinformation
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
 # Get-ADUsersUPN | Export-Csv "$iClic_TempPath\AllUsers.csv" -encoding "unicode" -notypeinformation
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
Function Update-ADUserUPN_Full_OU {
 Param (
  [Parameter(Mandatory=$true)]$OldUPNSuffix,
  [Parameter(Mandatory=$true)]$NewUPNSuffix,
  $Filter="*"
 )
 Get-ADUser -Filter { Name -like "$Filter" } -properties UserPrincipalName,Created,Modified | Select-Object Name,SamAccountName,UserPrincipalName,Created,Modified |
 Where-Object {$_.UserPrincipalName -like "*@$OldUPNSuffix"} | ForEach-Object {
  $OldUPN=$_.UserPrincipalName
  $OldSamAccount=($OldUPN -split("@"))[0]
  $NewUPN="$OldSamAccount`@$NewUPNSuffix"
  #Could use one liner but notepad ++ does not understand the syntax : "$(($OldUPN -split("@"))[0])`@$NewUPNSuffix"

  write-host "UPN Before : $OldUPN | After: $NewUPN"
  write-host "Set-ADUser $($_.SamAccountName) -UserPrincipalName $NewUPN"

  if ( $(read-host "Continue with the action (Y/N)") -eq "N" ) {write-host "Skipped" ; return}

  try {
   Set-ADUser $($_.SamAccountName) -UserPrincipalName $NewUPN
   write-host "Done"
  } catch {
   write-host -foregroundcolor "red" $error[0]
  }
 }
 write-host "Finished updating"
}
Function Update-ADUserUPN {
 Param (
  [Parameter(Mandatory=$true)]$SamAccountName,
  [Parameter(Mandatory=$true)]$NewUPNSuffix
 )
 $UserInfo = Get-Aduser -Identity $SamAccountName
 $OldUPN = $UserInfo.UserPrincipalName
 $UPNPrefix = ($OldUPN -split("@"))[0]
 $NewUPN = $UPNPrefix + "@" + $NewUPNSuffix

 if ($OldUPN -eq $NewUPN) {
  Write-Host -ForegroundColor Cyan "Nothing to do, UPN is already set $NewUPN"
 } else {
  write-host "UPN Before : $OldUPN | After: $NewUPN"
  write-host "Set-ADUser $SamAccountName -UserPrincipalName $NewUPN"
  Set-ADUser $SamAccountName -UserPrincipalName $NewUPN
 }
}
Function Update-ADUserSamAccountName {
 Param (
  [Parameter(Mandatory=$true)]$OldSamAccountName,
  [Parameter(Mandatory=$true)]$NewSamAccountName
 )
 Set-ADUser $OldSamAccountName -Replace @{samaccountname=$NewSamAccountName}
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
 } catch {Write-Colored -Color "red" -NonColoredText  "Error during check ($($error[0]))"}
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
 } catch {Write-Colored -Color "red" -NonColoredText  "Error during check ($($error[0]))"}
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

# SCCM Management
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

# MS GUID Conversion scripts
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

# MS-DS-ConsistencyGUID Management
Function Get-ADUserGUID {
 Param (
  $user=$env:ComputerName
 )
 Try {
 ([GUID]((Get-ADUser $user -property mS-DS-ConsistencyGuid)."mS-DS-ConsistencyGuid")).GUID
 } Catch {
  write-host -ForegroundColor 'Red' "User $User does not have an mS-DS-ConsistencyGuid"
 }
}
Function Get-ADComputerGUID {
 Param (
  $Computer=$env:ComputerName
 )
 Try {
 ([GUID]((Get-ADComputer $Computer -property mS-DS-ConsistencyGuid)."mS-DS-ConsistencyGuid")).GUID
 } Catch {
  write-host -ForegroundColor 'Red' "Computer $Computer does not have a mS-DS-ConsistencyGuid"
 }
}
Function Set-ADComputerObjectIDAsMSDSConsistencyGUID { # Set the Object ID as the ms-ds-consistencyGUID
 Param (
  [Parameter(Mandatory=$true)]$Computer
 )
 $ComputerGUID = (Get-ADComputer -Identity $Computer).ObjectGUID
 Set-ADComputer -Identity $Computer -Replace @{'mS-DS-ConsistencyGuid'=$ComputerGUID}
}
Function Set-ADUserObjectIDAsMSDSConsistencyGUID { # Set the Object ID as the ms-ds-consistencyGUID
 Param (
  [Parameter(Mandatory=$true)]$User
 )
 $UserGUID = (Get-ADUser -Identity $User).ObjectGUID
 Set-ADUser -Identity $User -Replace @{'mS-DS-ConsistencyGuid'=$UserGUID}
}
Function Set-ADGroupObjectIDAsMSDSConsistencyGUID { # Set the Object ID as the ms-ds-consistencyGUID
 Param (
  [Parameter(Mandatory=$true)]$Group
 )
 $GroupGUID = (Get-ADGroup -Identity $Group).ObjectGUID
 Set-ADGroup -Identity $Group -Replace @{'mS-DS-ConsistencyGuid'=$GroupGUID}
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

# Exchange/O365 - Old Not Updated
#Exchange Connexion
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
 Write-Colored -Color $defaultblue -NonColoredText "" $($_.ProductName,$_.Comments,"(",$_.ProductVersion,")")
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
  Write-Colored -Color "red" -NonColoredText  "" "Error with account $DisplayName ($($error[0]))"
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
 if (! $Mailbox) {write-Colored -Color "Red" -ColoredText "A Mailbox Name is mandatory";return}

 #Get Mailbox SendAs permission
 try { $MailboxPermissionSendAs = Get-RecipientPermission $Mailbox -ErrorAction "Stop" } catch {if ($verbose) {write-Colored -Color "Red" -ColoredText $error[0]}}
 # Ignore Deny and Self
 if ($MailboxPermissionSendAs) {
  $MailboxPermissionSendAs = $MailboxPermissionSendAs | Where-Object {! (( $_.IsInherited ) -or ( $_.Deny ) -or ($_.Trustee -like "*nt authority\self*"))}
 }

 #Get Mailbox Full Access permission
 try { $MailboxPermissionFullAccess = Get-MailboxPermission $Mailbox -ErrorAction "Stop" } catch {if ($verbose) {write-Colored -Color "Red" -ColoredText $error[0]}}
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
Function Get-ExchangeUserDetails { # Uses Exchange Module - Does 1000 elements at the time (and loop is about every 2 to 5 seconds)
 Param (
  $PropertyList = @("Name","DisplayName","WindowsLiveID","ExternalDirectoryObjectId","IsDirSynced","CustomAttribute10","RecipientType","RecipientTypeDetails"),
  $RecipientTypeToCheck = @("MailUser","UserMailbox"),
  $RecipientTypeDetailsToCheck = @("MailUser","DiscoveryMailbox","EquipmentMailbox","RoomMailbox","SchedulingMailbox","SharedMailbox","TeamMailbox","UserMailbox"),
  $ExportFileName = "$iClic_TempPath\Global_ExchangeUserDetails_$([DateTime]::Now.ToString("yyyyMMdd")).csv",
  [Switch]$UsingToken,
  [Switch]$Export
 )
 if (! $UsingToken) {
  if (!((Get-ConnectionInformation).State -eq "Connected")) { Connect-ExchangeOnline }
 }
  $Result = Get-Recipient -Properties $PropertyList -RecipientType $RecipientTypeToCheck -RecipientTypeDetails $RecipientTypeDetailsToCheck -ResultSize unlimited | Select-Object $PropertyList
 if ($Export) {
  $Result | Export-Csv $ExportFileName
  return $ExportFileName
 } else {
  $Result
 }
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
  if (! $NoError) {Write-Colored -Color "red" -NonColoredText  "" "Error while searching for $DLMail ($($error[0]))"}
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
  if ($ShowMessage) {Write-Colored -Color "red" -NonColoredText  "" "Error while searching Office 365 for $SearchValue ($($error[0]))"}
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
 } catch {Write-Colored -Color "red" -NonColoredText  "$(get-date -uformat '%Y-%m-%d-%T') | Fatal Error | $loginname | " "Error during account check ($($error[0]))" $logfile ; return}

 Write-StarLine "-"
 #Backup Info
 write-colored "blue" "$(get-date -uformat '%Y-%m-%d-%T') | Normal | $loginname | Account check" "" $logfile
 write-colored "blue" "target address : " "$($accountinfo.targetAddress)" $logfile
 write-colored "blue" "LegacyExchangeDN address : " "$($accountinfo.legacyExchangeDN)" $logfile
 write-colored "blue" "Proxy Addresses : " "$($accountinfo.proxyAddresses) " $logfile
 Write-StarLine "-"

 return $accountinfo
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
   Write-Colored -Color "red" -NonColoredText  "$(get-date -uformat '%Y-%m-%d-%T') | Fatal Error | $User | " "Error during the backup of $user ($($error[0]))" $logfile ; return
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
  New-item -ItemType Directory $iClic_TempPath\ -Force | Out-Null
  write-host "Removing User $Mail from Distribution Group $($_.DisplayName)"
  Remove-DistributionGroupMember -Identity $_.DisplayName -Member $UPN
  write-output "Removed user $UPN from Distribution Group $($_.DisplayName)" >> "$iClic_TempPath\O365-DG-Removal.log"
 }
}
Function Get-DistributionGroupMemberRecursive {
 Param ($GroupIdentity)
	$member_list = Get-DistributionGroupMember -Identity $GroupIdentity
	foreach ($member in $member_list) {
		if ($member.RecipientType -like '*Group*') {
			Get-DistributionGroupMemberRecursive -GroupIdentity $member.ExchangeObjectId
		} else {
			$member | Select-Object Name,PrimarySmtpAddress,DisplayName,RecipientType
		}
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

 $WINDOWSUPDATE = Get-ItemProperty $MsUpdateReg 2>$null
 $WINDOWSUPDATE_WU_AU = Get-ItemProperty "$MsUpdateReg\AU" 2>$null

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
 $WINDOWSUPDATE=Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" 2>$null
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
  $ScriptLog="$iClic_TempPath\$($MyInvocation.MyCommand).Log",
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

    $ReturnResult = $Updates | Select-Object @{name="ServerName";expression={$ServerName}}, Title, MsrcSeverity, RebootRequired,
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
     $ReturnInfo = $Downloader.Download()
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
Function Convert-WuaResultCodeToName {
 param( [Parameter(Mandatory=$true)]
  [int] $ResultCode
 )
 $Result = $ResultCode
 switch($ResultCode)
  { 2 { $Result = "Succeeded"
  } 3 { $Result = "Succeeded With Errors"
  } 4 { $Result = "Failed"
  }
 }
 return $Result
}
function Get-WuHistory { # Get latest updates
 # Get a WUA Session
 $session = (New-Object -ComObject 'Microsoft.Update.Session')
 # Query the latest 1000 History starting with the first recordp
 $history = $session.QueryHistory("",0,1000) | ForEach-Object {
  $Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode
  # Make the properties hidden in com properties visible.
  $_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
  $Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
  $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
  $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
  $_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
  Write-Output $_
 }
 #Remove null records and only return the fields we want
 $history | Where-Object {![String]::IsNullOrWhiteSpace($_.title)} | Select-Object Result, Date, Title,Description, SupportUrl, Product, UpdateId, RevisionNumber
}

# WSUS
Function Install-WSUS { # Install WSUS Service on a Server
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
Function Set-WSUSConfig { # Fully configure WSUS using commandlines
 Param (
  $ProxyInfo,
  [Parameter(Mandatory=$true)]$ProductsToEnable, # List of products to enable, works with wildcards : @("Product1","Product2","Product3*")
  [Parameter(Mandatory=$true)]$ComputerTargetGroups, # Filter on specific groups, does not work with wildcards : @("All Computers")
  [Parameter(Mandatory=$true)]$UpdateClassificationsIDs, # Filter selected classification, does not work with wildcards, uses ID because of potential Language issues : @('e6cf1350-c01b-414d-a61f-263d14d133b4', 'e0789628-ce08-4437-be74-2495b842f43b' , '68c5b0a3-d1a6-4553-ae49-01d3a7827828')
  [Parameter(Mandatory=$true)]$AutoApproveRuleName, # Name of AutoApproval Rule
  $TimeOfSync = (New-TimeSpan -Hours 0 -Minutes 0), # Default Midnite
  [Parameter(Mandatory=$true)]$NumberOfSync = 3 # Number of Synchronisation per day
 )

 # Get WSUS Name
 $WsusServer = Get-WSUSServer

 # Connect to WSUS server configuration
 $wsusConfig = $WsusServer.GetConfiguration()

 # Set to download updates from Microsoft Updates
 Set-WsusServerSynchronization -SyncFromMU | Out-Null

 # Set Update Languages to English
 $wsusConfig.AllUpdateLanguagesEnabled = $false
 $wsusConfig.SetEnabledUpdateLanguages("en")

 #If Proxy is required
 if ($ProxyInfo) {
  $wsusConfig.ProxyName=$ProxyInfo[0]
  $wsusConfig.ProxyServerPort=$ProxyInfo[1]
  $wsusConfig.UseProxy=$true
 }

 # Save WSUS Config settings
 $wsusConfig.Save()

 # Get WSUS Subscription
 $subscription = $WsusServer.GetSubscription()
 $subscription.StartSynchronizationForCategoryOnly()

 # Perform initial synchronization to get latest categories
 While ($subscription.GetSynchronizationStatus() -ne 'NotProcessing') {
  Write-Host "`r$(get-date -uformat '%Y-%m-%d %T') Subscription Sync In Progress - Please Wait - May take multiple minutes" -NoNewline
  Start-Sleep -Seconds 1
 }

 # Configure the Classifications (Disable Drivers by default)
 Get-WsusClassification | Where-Object { $_.Classification.Title -notlike "*driver*" } | Set-WsusClassification

 # Get all available products
 $ProductList = $WsusServer | Get-WsusProduct

 # To List products names : $ProductList.Product.Title

 # Disable all products
 $ProductList | Set-WsusProduct -Disable

 # Create Object for all required Products
 $ProductsToEnableObj = $ProductsToEnable | foreach-object {
  $CurrentProductName = $_
  $ProductList | Where-Object { $_.product.title -like $CurrentProductName }
 }

 # Enable only required products
 $ProductsToEnableObj | Set-WsusProduct

 #Configure Synchronizations
 $subscription.SynchronizeAutomatically=$true

 #Set Auto Approvals
 # List current rules :
 #  $ApprovalRules = $WsusServer.GetInstallApprovalRules()
 #   Get configured target groups : $ApprovalRules.GetComputerTargetGroups()
 #   Get configured classifications : $ApprovalRules.GetUpdateClassifications()

 # Get Available Computer Target Groups
 #  $WsusServer.GetComputerTargetGroups()
 # Get Available Classigication
 #  $WsusServer.GetUpdateClassifications()

 # Remove existing Approval Rule if it exists
 $ExistingApprovalRule = $WsusServer.GetInstallApprovalRules() | Where-Object Name -eq $AutoApproveRuleName
 if ($ExistingApprovalRule) {
  $WsusServer.DeleteInstallApprovalRule($ExistingApprovalRule.ID)
 }

 # Create Approval Rule
 $ApprovalRule = $WsusServer.CreateInstallApprovalRule($AutoApproveRuleName)

 # Create Classification Object
 $ClassificationForAutoApproval = $WsusServer.GetUpdateClassifications() | Where-Object Id -in $UpdateClassificationsIDs
 $ClassificationForAutoApprovalObj = New-Object Microsoft.UpdateServices.Administration.UpdateClassificationCollection
 Write-Host -ForegroundColor Cyan "Adding Update classifications : $($ClassificationForAutoApproval.Title -join ";")"
 if (! $ClassificationForAutoApproval) {
  Write-Host -ForegroundColor Red "Error adding classifications"
  Return
 }
 $ClassificationForAutoApprovalObj.AddRange($ClassificationForAutoApproval)
 $ApprovalRule.SetUpdateClassifications($ClassificationForAutoApprovalObj)

 #Create Target Group Object
 $TargetGroupForAutoApproval = $WsusServer.GetComputerTargetGroups() | Where-Object Name -in $ComputerTargetGroups
 $TargetGroupForAutoApprovalObj = New-Object Microsoft.UpdateServices.Administration.ComputerTargetGroupCollection
 Write-Host -ForegroundColor Cyan "Adding Target Groups : $($TargetGroupForAutoApproval.Name -join ";")"
 if (! $TargetGroupForAutoApproval) {
  Write-Host -ForegroundColor Red "Error adding groups"
  Return
 }
 $TargetGroupForAutoApprovalObj.AddRange($TargetGroupForAutoApproval)
 $ApprovalRule.SetComputerTargetGroups($TargetGroupForAutoApprovalObj)

 $ApprovalRule.Enabled = $True # Set Rule as Enabled
 $ApprovalRule.Save()          # Save Rule
 $ApprovalRule.ApplyRule()     # Apply Rule

 # Set synchronization scheduled
 $subscription.SynchronizeAutomaticallyTimeOfDay=$TimeOfSync
 $subscription.NumberOfSynchronizationsPerDay=$NumberOfSync
 $subscription.Save()

 # Launch Sync
 $subscription.StartSynchronization()

 # Monitor Progress of Synchronisation
 Start-Sleep -Seconds 15 # Wait for sync to start before monitoring
 while ($subscription.GetSynchronizationProgress().ProcessedItems -ne $subscription.GetSynchronizationProgress().TotalItems) {
  $ProgressPercentage=[System.Math]::Round($subscription.GetSynchronizationProgress().ProcessedItems * 100/($subscription.GetSynchronizationProgress().TotalItems),2)
  Write-Host "`r$(get-date -uformat '%Y-%m-%d %T') Sync In Progress $($subscription.GetSynchronizationProgress().ProcessedItems)/$($subscription.GetSynchronizationProgress().TotalItems) - $ProgressPercentage %    " -NoNewline
  Start-Sleep -Seconds 1
 }

 write-host
 write-host "WSUS Configuration Done"
}
Function Remove-WSUSSuperseeded { # Decline all superseeded updates
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
 write-host "Total Declined Updates: $count"
}
Function Get-WSUSConfiguredCategories { # List all enabled categories on a WSUS Server
 Param (
  $wsusServer=$(Get-WsusServer)
 )
 $wsusSubscription = $wsusServer.GetSubscription()
 $wsusSubscription.GetUpdateCategories() | select-object Title,Description
}
Function Get-WSUSConfiguredClassifications { # List all enabled classification on a WSUS Server
 Param (
  $wsusServer=$(Get-WsusServer)
 )
 $wsusSubscription = $wsusServer.GetSubscription()
 $wsusSubscription.GetUpdateClassifications() | Select-Object Title,Description
}
Function Get-WSUSConfiguredApprovalRules { # List all approval rules on a WSUS Server
 Param (
  $wsusServer=$(Get-WsusServer)
 )
 $ApprovalRulesList=@()
 $wsusServer.GetInstallApprovalRules() | ForEach-Object {
  $ApprovalRulesList+=[pscustomobject]@{
   Name=$_.Name;
   TargetGroups=$_.GetComputerTargetGroups().Name -join ",";
   UpdateClassification=$_.GetUpdateClassifications().Title -join ","
   Enabled=$_.Enabled
   Action=$_.Action
   Deadline=$_.Deadline
   CanSetDeadline=$_.CanSetDeadline
  }
 }
 return $ApprovalRulesList
}
Function Connect-WSUS { # Open connection to WSUS service
 Param (
  [Parameter(Mandatory=$true)]$WsusServer, #WSUS FQDN
  [Switch]$NoSSL,
  $Path="$iClic_TempPath\"
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
Function Get-WSUSUpdatesFull { # List all Updates on WSUS Servers
 Param (
  $wsus=$(Connect-WSUS)
 )
 $updates = $wsus.GetUpdates()
 return $updates
}
Function Get-WSUSUpdatesWaitingForApproval { # List all updates waiting for approval from
 Param (
  [Parameter(Mandatory=$true)]$ServerGroup
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
try { $IP=[IPAddress]$Server } catch { Write-Error "Nothing here" }

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
 try {[ipaddress]$GatewayIP 2>&1>$null} catch { Write-Error "Nothing here" }
 if (!$? -or !$GatewayIP -or [regex]::matches("$GatewayIP","\.").count -ne 3) { Write-Colored -Color "red" -NonColoredText  "" "You must provide a correct Gateway IP" ; return}

 #2) Show which Gateway will be used
 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Checking Gateway" 20 " : ") $GatewayIP -nonewline

 #3) Test Gateway Ping response :
 if ( ! (Test-Connection -Cn $GatewayIP -BufferSize 16 -Count 1 -ea 0 -quiet) ) { Write-Colored -Color "red" -NonColoredText  " - ping " "KO" } else { Write-Colored -Color "Green" -NonColoredText " - ping " "OK" }

 #4) Get Reverse zone
 $IPElements=$GatewayIP.split('.')
 $Reverse=$IPElements[2]+"."+$IPElements[1]+"."+$IPElements[0]

 Write-Colored -Color $defaultblue -NonColoredText (Align -Variable "Reverse Zone" 20 " : ") $Reverse

 #5) Check Reverse zone
 try {
  $NameServers=(nslookup -type=NS "$Reverse.in-addr.arpa" 2>&1 | Select-string -pattern "nameserver").line | ForEach-Object {$_.split("=")[1].trim()}
  Write-Colored -Color $defaultblue -NonColoredText "Reverse zone defined on following DNS Servers : "
  Format-PrintLineByLine $NameServers $defaultblue
  } catch { Write-Colored -Color "red" -NonColoredText  "" "Failed checking reverse zone or reverse zone not defined" }
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
  write-Colored -Color "Red" -ColoredText $Error[0] ; return
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
   write-colored $textcolor -ColoredText (Align -Variable ($DriveLetter+" ($drivetype $($_.FileSystem) : $volumelabel$SWAP)") 38) -nonewline
   if ($_.Freespace) {
    write-colored $sizecolor -NonColoredText " | Total $(Align -Variable $(Format-FileSize($_.Capacity)) 10) / Free $(Align -Variable $(Format-FileSize($_.freespace)) 10) " -ColoredText $(Align -Variable "( $drivefreespace% )" 12) -nonewline
   }
   Write-Colored -Color $defaultblue -ColoredText $(Format-FileSize $_.BlockSize)
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

 try {
  # while ( ! $path ) { $path = read-host "Enter path to check" }
  if ( ! ($(try {test-path $path -ErrorAction SilentlyContinue} catch { Write-Error "Nothing here" }))) {write-Colored -Color "Red" -ColoredText "Please provide a valid path. `"$path`" is not accessible" ; return}
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
 } Catch {
  write-host -foregroundcolor "Red" "Error checking rights on folder $path ($($Error[0]))"
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
  Write-Colored -Color $defaultblue -NonColoredText "Share Name : " ($_.Name,"(",$Description,")")

  if ($ServerName) {$dnsname=$ServerName} else {$dnsname=$env:computerName}

  $ShareFullPath="\\"+([System.Net.Dns]::GetHostByName($dnsname)).HostName+"\"+$_.Name
  Write-Colored -Color $defaultblue -NonColoredText "Local Path : " $_.Path
  Write-Colored -Color $defaultblue -NonColoredText "Remote Path : " $ShareFullPath

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
  write-Colored -Color "Red" -ColoredText "Unavailable source path : $Source"
  return
 }

 Try {
  $FullPath=(Resolve-Path $Source -ErrorAction Stop).ProviderPath
  write-colored -Color "Green" -ColoredText "Using path : $FullPath"
 } catch {
  write-Colored -Color "Red" -ColoredText "Error finding full path"
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
  write-Colored -Color "Red" -ColoredText $Error[0]
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
 Write-Colored -Color $Color -NonColoredText (Align -Variable "SCCM Site Code" -Size $alignsize -Ending " : ") $sitecode
 try {
  $SCCMVersion=(Get-CimInstance -ErrorAction "Stop" -Namespace root\ccm -ClassName SMS_Client).clientversion
  $color=$defaultblue
 } catch {
  $SCCMVersion="SCCM Client not installed"
  $color="red"
 }
 Write-Colored -Color $Color -NonColoredText (Align -Variable "SCCM Client Version" -Size $alignsize -Ending " : ") $SCCMVersion
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
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command"; return}
 if ( ! (test-path $KasperskyPath)) { write-Colored -Color "Red" -ColoredText "Unavailable path : $KasperskyPath" ; return }

 $command=$KasperskyPath+"klnagchk.exe"
 & $command
}
Function Set-KasperskyServer {
 Param (
  [Parameter(Mandatory=$true)]$ServerIP, # Kaspersky Serveur IP
  $KasperskyPath="${env:ProgramFiles(x86)}\Kaspersky Lab\NetworkAgent\"
 )
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command"; return}
 if ( ! (test-path $KasperskyPath)) { write-Colored -Color "Red" -ColoredText "Unavailable path : $KasperskyPath" ; return }

 $command=$KasperskyPath+"klmover.exe"
 &$command -address $ServerIP
}
Function Set-KasperskyCert {
 Param (
  $CertLocation="$iClic_TempPath\klserver.cer",
  $KasperskyPath="${env:ProgramFiles(x86)}\Kaspersky Lab\NetworkAgent\"
 )
 # Cert location on server %ALLUSERSPROFILE%\Application Data\KasperskyLab\adminkit\1093\cert
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command"; return}
 if ( ! (test-path $KasperskyPath)) { Write-host -ForegroundColor "red" "Unavailable path : $KasperskyPath" ; return }

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
 # $KLServerEncoded=Convert-StringToBase64UTF8 $KLServer

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
 $Marker=0

 #Starting with Windows 10 or Windows 2016 we can use Disable-TlsCipherSuite / Get-CipherSuite
 $AdvancedCmdLine=$(get-command Get-TlsCipherSuite -ErrorAction SilentlyContinue)

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
   $Marker++
   if ($AdvancedCmdLine) {
    $CipherListToRemove += $CipherListFull | Where-Object {$_ -like "$Cipher"}
   } else {
    $CipherListToReplace = $CipherListToReplace -split "," | Where-Object {$_ -notlike $Cipher}
   }
  } else {
   write-host -foregroundcolor "Cyan" "Cipher not present"
  }
 }

 if ($Marker -gt 0) {
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
  # CurrentDirectory = $null;
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
 Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc*\" -Name Start -Value 4 | Out-Null
 set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc*\" -Name Start -Value 4 | Out-Null
}
Function Disable-Windows10Prefetch {
 Try {
  Set-RegKey -RegKey "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value "0" -Type "DWord"
 } catch {
  write-host -foregroundcolor "red" $error[0]
 }
 Try {Set-Service -ErrorAction "Stop" -Name "SysMain" -DisplayName "superfetch" -Status "Stopped" -StartupType "Manual"} catch {write-host -foregroundcolor "red" $error[0]}
}
Function Set-REGModsUser {
 $HKEYExplorer = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
 $HKEYExplorerAdvanced="$HKEYExplorer\Advanced"
 $ThumbsKey="HKCU:\Software\Policies\Microsoft\Windows\Explorer"

 #Disable Thumbs.db on network folders
 New-Item -force $ThumbsKey | Out-Null
 Set-ItemProperty -Path $ThumbsKey -Name DisableThumbsDBOnNetworkFolders -Value 1 | Out-Null

 #Folder Options
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name Hidden -Value 1
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name HideFileExt -Value 0
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name ShowSuperHidden -Value 1
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name SeparateProcess -Value 1
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name HideFileExt -Value 0
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name Start_ShowRun -Value 1
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name Start_ShowSetProgramAccessAndDefaults -Value 0
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name LaunchTo -Value 1

 #Disable ShortcutTo on new shortcut
 Set-ItemProperty -Path $HKEYExplorer -Name "link" -Value ([byte[]](0x00,0x00,0x00,0x00))

 #Show All icons in tray
 Set-ItemProperty -Path $HKEYExplorer -Name EnableAutoTray -Value 0

 #Lock Taskbar
 Set-ItemProperty -Path $HKEYExplorerAdvanced -Name TaskbarSizeMove -Value 0
}
Function Set-REGModsMachine {
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command"; return}
 #Enable FastBoot
 Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -Value 1
 #Disable Screensaver
 Disable-ScreenSaver
 #Enable Verbose startup/shutdown
 $RegKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
 Set-ItemProperty -path $RegKey -Name "VerboseStatus" -Value "1" -Type DWord -Force | Out-Null
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
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1
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
Function Set-RDPNLA {
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command"; return}
 #Only ticks checkbox (if available)
 Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value "0" | Out-Null
 Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
 if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
  $RDPClass=Get-CimInstance -classname "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
  Invoke-CimMethod -InputObject $RDPClass -MethodName SetEncryptionLevel -Arguments @{MinEncryptionLevel=4} | Out-Null
  Invoke-CimMethod -InputObject $RDPClass -MethodName SetSecurityLayer -Arguments @{SecurityLayer=2} | Out-Null
  Invoke-CimMethod -InputObject $RDPClass -MethodName SetUserAuthenticationRequired -Arguments @{UserAuthenticationRequired=1} | Out-Null
 } else {
  (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)
  #Modifies all RDP-TCP Configuration
  $RegKey="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal*Server\WinStations\RDP-TCP\"
  Set-RegKey -RegKey $RegKey -Name "MinEncryptionLevel" -Value "4" -Type "DWord"
  Set-RegKey -RegKey $RegKey -Name "UserAuthentication" -Value "1" -Type "DWord"
  Set-RegKey -RegKey $RegKey -Name "SecurityLayer" -Value "2" -Type "DWord"
 }
}
Function Set-NumlockOnStart {
 New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS |Out-Null
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
 Set-RegKey -RegKey $RegKey -Name "AllowOnlySecureRpcCalls" -Value "0" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "FallbackToUnsecureRPCIfNecessary" -Value "0" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "TurnOffRpcSecurity" -Value "1" -Type "DWord"

 $RegKey="HKLM:\Software\Microsoft\MSDTC\Security\"
 Set-RegKey -RegKey $RegKey -Name "NetworkDtcAccess" -Value "1" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "NetworkDtcAccessClients" -Value "1" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "NetworkDtcAccessAdmin" -Value "1" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "XaTransactions" -Value "1" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "NetworkDtcAccessTransactions" -Value "1" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "NetworkDtcAccessInbound" -Value "1" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "NetworkDtcAccessOutbound" -Value "1" -Type "DWord"
 Set-RegKey -RegKey $RegKey -Name "LuTransactions" -Value "1" -Type "DWord"

 Restart-Service -displayname "Distributed Transaction Coordinator"
}
Function Get-MSDTC {
 $MSDTC_Security=Get-ItemProperty "HKLM:\Software\Microsoft\MSDTC\Security" 2>$null

 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccess "Network DTC Access"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessClients "Client And Administration | Allow Remote Clients"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessAdmin "Client And Administration | Allow Remote Administration"
 Format-TypeMSDTC $MSDTC_Security.XaTransactions "Enable XA Transactions"
 Format-TypeMSDTC $MSDTC_Security.LuTransactions "Enable SNA LU 6.2 Transactions"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessTransactions "Transaction Manager Communication"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessInbound "Transaction Manager Communication | Allow Inbound"
 Format-TypeMSDTC $MSDTC_Security.NetworkDtcAccessOutbound "Transaction Manager Communication | Allow Outbound"

 $MSDTC=Get-ItemProperty "HKLM:\Software\Microsoft\MSDTC" 2>$null

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
Function Enable-PowerSettingsUnhideAll {
 if (!$IsLinux -and !$IsMacOS) {
  # Unlock Power Plans by disabling "Connected Standby"
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'CSEnabled' -Value 0 -Force

  # Unlock hidden options
  $PowerSettings = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings' -Recurse -Depth 1 | Where-Object { $_.PSChildName -NotLike 'DefaultPowerSchemeValues' -and $_.PSChildName -NotLike '0' -and $_.PSChildName -NotLike '1' }
  ForEach ($item in $PowerSettings) { $path = $item -replace "HKEY_LOCAL_MACHINE","HKLM:"; Set-ItemProperty -Path $path -Name 'Attributes' -Value 2 -Force }
 }
}

# Sound
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
Function Set-KeycloakValue { #To be tested
 Param (
  [Parameter(Mandatory=$true)]$KeycloakURL,
  $Realm = 'master',
  [Parameter(Mandatory=$true)]$BearerToken,
  [Parameter(Mandatory=$true)]$Request
 )
 (Invoke-WebRequest -Uri "https://$KeycloakURL/auth/admin/realms/$Realm/$Request" -Method POST -header @{Authorization = "Bearer $BearerToken"}).Content
}
Function Remove-KeycloakValue { #To be tested
 Param (
  [Parameter(Mandatory=$true)]$KeycloakURL,
  $Realm = 'master',
  [Parameter(Mandatory=$true)]$BearerToken,
  [Parameter(Mandatory=$true)]$Request
 )
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
Function Get-KeyCloakRolesFromID { # Get All Assigned Role from Users or Service Account
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
  $Path="$iClic_TempPath\KPI\"
 )
 Function IsOSServerOrWorkstation ($TypeOfOS,$OU) {
  if ((! $TypeOfOS) -or ($TypeOfOS -eq "unknown")) {return "Unknown"
  } elseif ( ($TypeOfOS.contains("Server")) -or ($TypeOfOS -eq "Samba") ) {return "Server"
  } else { return "Workstation" }
 }

 if ( ! (test-path $Path)) { write-Colored -Color "Red" -ColoredText "Unavailable path : $Path" ; return }

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

# Powershell history management (Found on github : https://github.com/PowerShell/PSReadLine/issues/1778)
Function Remove-PSReadlineHistory {
 param (
  [Parameter(Mandatory = $true)]
  [string]$Pattern
 )
 $historyPath = (Get-PSReadLineOption).HistorySavePath
 $historyLines = [System.IO.File]::ReadAllLines($historyPath)
 $filteredLines = $historyLines | Where-Object { $_ -notmatch $Pattern }
 [System.IO.File]::WriteAllLines($historyPath, $filteredLines)

 Write-Host "Removed $($historyLines.Count - $filteredLines.Count) line(s) from PSReadLine history."
}
Function Remove-PSHistory {
 param (
  [Parameter(Mandatory = $true)]
  [string]$Pattern
 )

 $historyLines = Get-History
 $matchingLines = $historyLines | Where-Object { $_.CommandLine -match $Pattern }
 $matchingLines | ForEach-Object { Clear-History -Id $_.Id }
 Write-Host "Removed $($matchingLines.Count) line(s) from PowerShell history."
}
Function Remove-History {
 param (
  [Parameter(Mandatory = $true)]
  [string]$Pattern
 )
 Remove-PSReadlineHistory -Pattern $Pattern
 Remove-PSHistory -Pattern $Pattern
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
  $ProductName = "Product",
  $LogfileLocation = $("$env:SystemRoot\Temp"),
  [switch]$Remove=$false
 )
 $ErrorActionPreference="Stop"

 try {
  if ( ! $(test-path $MsiPath) ) { throw "Path unavailable : $MsiPath" }
  $DataStamp = get-date -uformat "%Y%m%d-%H%M"
  $MsiFileName=[System.IO.Path]::GetFileNameWithoutExtension($MsiPath)
  $logFile = $LogfileLocation+"\"+$MsiFileName+"-"+$DataStamp+".log"
  if ($Remove) {$InstallOrRemove="x"} else {$InstallOrRemove="i"}
  $MSIArguments = @(
   "/$InstallOrRemove"
   ('"{0}"' -f $MsiPath)
   "/qn"
   "/norestart"
   "/Lv*x"
   $logFile
  )
  Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

  write-output "$(get-date -uformat '%Y-%m-%d %T') $($Env:COMPUTERNAME) - Install OK Check Log"

  Get-Content $logFile | Select-String "MSI \(s\)" | Select-String $ProductName |  Out-String
 } catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-MSIRemote { #Copy and Install a MSI on a remote computer
 Param(
  [Parameter(Mandatory=$true)]$ServerName,
  [Parameter(Mandatory=$true)]$MSIPath,
  $TempPath='$iClic_TempPath\'
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
Function Get-GITHUB_App_LatestVersion { # Find latest version on Github if using standardized tree
 Param (
  [Parameter(Mandatory=$true)]$Developper,
  [Parameter(Mandatory=$true)]$ApplicationName,
  $FileNamePrefix,
  $FileNameSuffix,
  [ValidateSet("None","Base","Trimmed")]$VersionInFileNameType = "None"
 )

 if (! $FileNamePrefix) { $FileNamePrefix = $ApplicationName }
 if (! $FileNameSuffix) { $FileNameSuffix = ".zip" }

 # GITHUB Base URL
 $URL = "https://github.com/$Developper/$ApplicationName/releases/latest"

 # Get latest tag URL (Can Browse)
 $Request = [System.Net.WebRequest]::Create($URL)
 $Response = $Request.GetResponse()
 $TagUrl = $Response.ResponseUri.OriginalString

 # Get Latest version number
 $BaseVersion = $TagUrl.split('/')[-1]
 $version = $TagUrl.split('/')[-1].Trim('v').Trim('n')

 # Generate FileName with available info
 if ($VersionInFileNameType -eq 'None') {
  $FileName = $FileNamePrefix + $FileNameSuffix
 } elseif ($VersionInFileNameType -eq 'Base') {
  $FileName = $FileNamePrefix + $BaseVersion + $FileNameSuffix
 } elseif ($VersionInFileNameType -eq 'Trimmed') {
  $FileName = $FileNamePrefix + $version + $FileNameSuffix
 }


 # Get latest Download URL (Cannot Browse)
 $DownloadUrl = $TagUrl.Replace('tag', 'download') + '/' + $fileName
 $BaseDownloadUrl = $TagUrl.Replace('tag', 'download') + '/'

 return [pscustomobject]@{BaseVersion=$BaseVersion;Version=$Version;TagURL=$TagUrl;BaseDownloadUrl=$BaseDownloadUrl;DownloadUrl=$DownloadUrl}
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

 $Binary = "Git.exe"
 $Installer = "Git_Installer.exe"

 # Check current version
 if (Assert-IsCommandAvailable $Binary -NoError) {
  $CurrentVersion = Invoke-Expression -Command "$Binary version" -ErrorAction SilentlyContinue
  if ($CurrentVersion) {
   Write-Colored -NonColoredText "Current installed version : " -ColoredText $CurrentVersion -PrintDate
  }
 }

 try {
  $DownloadLink = ((Invoke-WebRequest https://git-scm.com/downloads/win).links | Where-Object { ($_ -like  "*-64-bit*") -and ($_ -notlike "*Portable*") }).href[0]
  #Check Newest Version :
  $NewestVersion = ($DownloadLink -split "/" | Select-Object -Last 1) -replace '-64-bit.exe','' -replace 'Git-',''
  Write-Colored -NonColoredText "Newest version : " -ColoredText $NewestVersion -PrintDate

  if ($CurrentVersion) {
   $Answer = Question -message "Install newest version ?" -defaultChoice '1'
   if (! $Answer) {
    Return
   }
  }

  $SetupFileName = Get-FileFromURL $DownloadLink -OutputFile $Installer
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Invoke-Expression  "& { ./$SetupFileName /verysilent /Log /suppressmsgboxes /norestart /forcecloseapplications /restartapplications /CURRENTUSER /lang=EN /dir='$InstallDestination' }"
  Wait-ProcessTermination -Process $SetupFileName -Message "Waiting for the end of the installation"
  Write-Blank
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
  Wait-ProcessTermination -Process $SetupFileName -Message "Waiting for the end of the installation"
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
 New-Item -Type Directory $InstallDestination -Force
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
 # Current version : k9s version
 $Developer = 'derailed'
 $ApplicationName = "k9s"
 $FileNamePrefix = $ApplicationName
 $FileNameSuffix = "_Windows_amd64.zip"
 $TempFileName = $FileNamePrefix + $FileNameSuffix
 try {
  $GitHubInfo = Get-GITHUB_App_LatestVersion -Developper $Developer -ApplicationName $ApplicationName -FileNamePrefix $FileNamePrefix -FileNameSuffix $FileNameSuffix
  Get-FileFromURL $GitHubInfo.DownloadUrl -OutputFile $TempFileName
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  tar -xvf $TempFileName --directory $InstallDestination\
  Remove-Item $TempFileName
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-FFMpeg { # Download and 'install' latest FFMpeg - Add Binary to PATH [ZIP] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\FFmpeg"
 )
  # Current version : FFMpeg -version
 $Developer = 'BtbN'
 $ApplicationName = "FFmpeg-Builds"
 $FileNamePrefix = "ffmpeg-master-"
 $FileNameSuffix = "-win64-gpl-shared.zip"
 $TempFileName = $FileNamePrefix + $FileNameSuffix
 try {
  $GitHubInfo = Get-GITHUB_App_LatestVersion -Developper $Developer -ApplicationName $ApplicationName -FileNamePrefix $FileNamePrefix -FileNameSuffix $FileNameSuffix -VersionInFileNameType Base
  Get-FileFromURL $GitHubInfo.DownloadUrl -OutputFile $TempFileName
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path $TempFileName -DestinationPath $InstallDestination -Force
  Remove-Item $TempFileName
  Move-Item $InstallDestination\$FileNamePrefix*\* $InstallDestination\ -Force
  Remove-Item $InstallDestination\$FileNamePrefix*\
  Add-ToPath $InstallDestination\bin
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-Robo3T { # Download and 'install' latest Robo3T - Add Binary to PATH [ZIP] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\Robo3T"
 )
 # Current version : Get-FileInfo $InstallDestination\robo3t.exe
 $Developer = 'Studio3T'
 $ApplicationName = "robomongo"
 $FileNamePrefix = "robo3t-"
 $FileNameSuffix = "-windows-x86_64-HASH.zip"
 $TempFileName = $FileNamePrefix + $FileNameSuffix

 try {
  $GitHubInfo = Get-GITHUB_App_LatestVersion -Developper $Developer -ApplicationName $ApplicationName -FileNamePrefix $FileNamePrefix -FileNameSuffix $FileNameSuffix -VersionInFileNameType Trimmed
  #Get Latest Hash to get correct filename
  $LastHash = ((((Invoke-WebRequest $GitHubInfo.TagURL).Links | Where-Object 'data-hovercard-type' -eq 'commit').href -split "/")[-1]).SubString(0,8)

  Get-FileFromURL $($GitHubInfo.DownloadUrl -replace 'HASH',$LastHash) -OutputFile $TempFileName
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path $TempFileName -DestinationPath $InstallDestination -Force
  Remove-Item $TempFileName
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
 $Developer = 'ShareX'
 $ApplicationName = "ShareX"
 $FileNamePrefix = "ShareX-"
 $FileNameSuffix = "-portable.zip"
 $TempFileName = $FileNamePrefix + $FileNameSuffix

 try {
  $GitHubInfo = Get-GITHUB_App_LatestVersion -Developper $Developer -ApplicationName $ApplicationName -FileNamePrefix $FileNamePrefix -FileNameSuffix $FileNameSuffix -VersionInFileNameType Trimmed
  Get-FileFromURL $GitHubInfo.DownloadUrl -OutputFile $TempFileName
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path $TempFileName -DestinationPath $InstallDestination -Force
  Remove-Item $TempFileName
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-MongoDBCompass { # Download and 'install' latest ShareX - Add Binary to PATH [ZIP] - SRC : GITHUB
 Param (
  $InstallDestination="C:\Apps\MongoDBCompass"
 )
 $Developer = 'mongodb-js'
 $ApplicationName = "compass"
 $FileNamePrefix = "mongodb-compass-"
 $FileNameSuffix = "-win32-x64.zip"
 $TempFileName = $FileNamePrefix + $FileNameSuffix

 try {
  $GitHubInfo = Get-GITHUB_App_LatestVersion -Developper $Developer -ApplicationName $ApplicationName -FileNamePrefix $FileNamePrefix -FileNameSuffix $FileNameSuffix -VersionInFileNameType Trimmed
  Get-FileFromURL $GitHubInfo.DownloadUrl -OutputFile $TempFileName
  New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
  Expand-Archive -Path $TempFileName -DestinationPath $InstallDestination -Force
  Remove-Item $TempFileName
  Add-ToPath $InstallDestination
 } Catch {
  write-output "$(get-date -uformat '%Y-%m-%d %T') - ERROR : $($Error[0])"
 }
}
Function Install-WinSCP { # Download and install latest WinSCP [ZIP]
 Param (
  $InstallDestination="C:\Apps\WinSCP"
 )
 $RootURL = "https://winscp.net"
 $ProductName = "WinSCP"

 #Must add intermediate link to follow link
 $DownloadLinkTMP = $RootURL + ((Invoke-WebRequest $RootURL/eng/downloads.php).links | Where-Object { ($_ -like  "*$ProductName-*.zip*") -and ($_ -notlike  "*beta*") -and ($_ -notlike  "*Automation*") -and ($_ -notlike  "*Source*")  }).href
 $DownloadLink = ((Invoke-WebRequest $DownloadLinkTMP).links | Where-Object {$_ -like "*Direct download*"}).href
 $SetupFileName = Get-FileFromURL $DownloadLink
 New-Item -Type Directory $InstallDestination -force -ErrorAction Stop | Out-Null
 Expand-Archive -Path $SetupFileName -DestinationPath $InstallDestination -Force
 Remove-Item $SetupFileName
 Add-ToPath $InstallDestination
}
Function Install-Filezilla { # Download and install latest Filezilla [ZIP]
 Param (
  $InstallDestination="C:\Apps\FileZilla"
 )
 $RootURL = "https://filezilla-project.org"
 $ProductName = "FileZilla"

 #Must add intermediate link to follow link
 $DownloadLink = ((Invoke-WebRequest $RootURL/download.php?show_all=1).links  | Where-Object { ($_ -like  "*$ProductName-*64.zip*")}).href
 Get-FileFromURL $DownloadLink -OutputFile "$ProductName.zip"
 New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
 Expand-Archive -Path "$ProductName.zip" -DestinationPath $InstallDestination -Force
 Remove-Item "$ProductName.zip"
 Move-Item $InstallDestination\$ProductName-*\* $InstallDestination\ -Force
 Remove-Item $InstallDestination\$ProductName-*\
 Add-ToPath $InstallDestination
}
Function Install-OpenSSL { # Download and install lastest OpenSSL (from firedaemon)
 Param (
  $InstallDestination="C:\Apps\OpenSSL"
 )
 $RootURL = "https://kb.firedaemon.com/support/solutions/articles/4000121705"
 $ProductName = "OpenSSL"

 # Check current version
 if (Assert-IsCommandAvailable $ProductName -NoError) {
  $CurrentVersion = Invoke-Expression -Command "$ProductName version" -ErrorAction SilentlyContinue
  if ($CurrentVersion) {
   Write-Colored -NonColoredText "Current installed version : " -ColoredText $CurrentVersion -PrintDate
  }
 }

 #Must add intermediate link to follow link
 $DownloadLinks = ((Invoke-WebRequest $RootURL).links  | Where-Object { ($_ -like  "*$ProductName-*.zip*")}).href
 # Get latest version :
 $LatestVersionNumber = (($DownloadLinks | ForEach-Object { ($_ -split "-")[-1] }) -replace ".zip","" | Sort-Object)[-1]

 Write-Colored -NonColoredText "Newest version : " -ColoredText $LatestVersionNumber -PrintDate

 if ($CurrentVersion) {
  $Answer = Question -message "Install newest version ?" -defaultChoice '1'
  if (! $Answer) {
   Return
  }
 }

 $DownloadLink = $DownloadLinks | Where-Object { $_ -like "*$LatestVersionNumber*" }
 Get-FileFromURL $DownloadLink -OutputFile "$ProductName.zip"
 New-Item -type directory $InstallDestination -force -ErrorAction Stop | Out-Null
 Expand-Archive -Path "$ProductName.zip" -DestinationPath $InstallDestination -Force
 Copy-Item $InstallDestination\$ProductName-*\* $InstallDestination\ -Recurse -Force
 Remove-Item "$ProductName.zip"
 Remove-Item "$InstallDestination\$ProductName-*\" -Recurse
 Add-ToPath "$InstallDestination\x64\bin"
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
  $URL = 'http://aka.ms/WACDownload'
 )
 $MSIInstallFile = Get-FileFromURL $URL
 Install-MSI -MsiPath $MSIInstallFile -ProductName "Windows Admin Center"
 Remove-Item $MSIInstallFile
}
Function Install-AzureCli { # Download and install latest AzureCLI [MSI]
 Param (
  $URL = 'https://aka.ms/installazurecliwindows'
 )
 $MSIInstallFile = Get-FileFromURL $URL
 Install-MSI -MsiPath $MSIInstallFile -ProductName "Microsoft Azure CLI"
 Remove-Item $MSIInstallFile
}
Function Install-7zip { # Download and install latest 7Zip [MSI]
 Param (
  $InstallDestination="C:\Apps\7Zip"
 )
 $MSIInstallFile = '7zip.msi'
 $RootURL = "https://www.7-zip.org/"
 $DownloadLink = $RootURL + $((Invoke-WebRequest $RootURL/download.html).links | Where-Object { $_ -like  "*x64.msi*" } | Select-Object -first 1).href
 Get-FileFromURL $DownloadLink -OutputFile $MSIInstallFile
 Install-MSI -MsiPath $MSIInstallFile -ProductName "7-Zip"
 Remove-Item $MSIInstallFile
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
Function Install-Python { # Download and install latest Python [EXE] - Possible to use the Store in Windows 11 (at least)
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
Function Install-SSMS { # Download and install latest SQL Server Management Studio [EXE]
 $SetupFileName = Get-FileFromURL "https://aka.ms/ssmsfullsetup"
 $Arguments = @(
  "/quiet"
 )
 Start-Process -FilePath $SetupFileName -ArgumentList $Arguments -Wait
 Remove-Item $SetupFileName
}

# Git
Function Get-GitLabGroups {
 Param (
  $Access_Token = $env:GitLabKey,
  $MaxResult = 1000,
  [Parameter(Mandatory=$true)]$GitLabURL #"https://FQDN/api/v4"
 )
 curl -s "$GitLabURL/groups?private_token=$Access_Token;per_page=$MaxResult" | ConvertFrom-Json | Select-Object name,full_path,visibility,
 @{name="LDAPGroup_Reporter(20)";expression={($_.ldap_group_links | Where-Object group_access -eq 20).cn -join ";"}},
 @{name="LDAPGroup_Owner(50)";expression={($_.ldap_group_links | Where-Object group_access -eq 50).cn -join ";"}},
 @{name="LDAPGroup_Maintainer(40)";expression={($_.ldap_group_links | Where-Object group_access -eq 40).cn -join ";"}},
 @{name="LDAPGroup_Developer(30)";expression={($_.ldap_group_links | Where-Object group_access -eq 30).cn -join ";"}} | Sort-Object full_path
}
Function Get-GitLabRunners {
 Param (
  $Access_Token = $env:GitLabKey,
  [Parameter(Mandatory=$true)]$GitLabURL #"https://FQDN/api/v4"
 )
 curl -s "$GitLabURL/runners/all?private_token=$Access_Token" | ConvertFrom-Json | Select-Object description,ip_address
}
Function Get-GitLabUsers {
 Param (
  $Access_Token = $env:GitLabKey,
  $NumberOfPages = 4,
  [Parameter(Mandatory=$true)]$GitLabURL #"https://FQDN/api/v4"
 )
 $UserList = @()
 For ($i=1; $i -le $NumberOfPages; $i++) {
  $UserList += curl -s -H "private-token: $Access_Token" "$GitLabURL/users?per_page=100&page=$i" | ConvertFrom-Json | `
   Select-Object Id,name,username,state,created_at,last_sign_in_at,last_activity_on,using_license_seat,external,two_factor_enabled,is_admin,email
 }
 $UserList
}
Function Set-GitConfig {
 Param (
  $UserName = $env:USERNAME,
  $Email,
  [switch]$Proxy,
  $ProxyURL
 )
 git config --global user.name $UserName
 if ($Email) { git config --global user.email $Email }
 # If error http HTTP Basic : Access Denied => git config --global http.emptyAuth true
 if ($Proxy -and $ProxyURL) {
  git config --global http.proxy $ProxyURL
 } else {
  git config --global --unset http.proxy
 }
}
Function Get-GitConfig {
 write-host -ForegroundColor Blue "Global"
 git config --global --list
 write-host -ForegroundColor Blue "System"
 git config --system --list
}

# Misc Functions
Function Add-ValuesToArray { # Example to add values to a Powershell Array
 Param (
  $userlist=@(""),
  $FirstColumnLabel,
  $SecondColumnLabel,
  $SecondColumnValue,
  $ThirdColumnLabel,
  $ThirdColumnValue
 )
 $OutputArray = @()
 $UserList | Sort-Object | ForEach-Object {
  $TmpObj = New-Object PSObject
  $TmpObj | Add-Member -type NoteProperty -Name $FirstColumnLabel -Value $_
  $TmpObj | Add-Member -type NoteProperty -Name $SecondColumnLabel -Value $SecondColumnValue
  $TmpObj | Add-Member -type NoteProperty -Name $ThirdColumnLabel -Value $ThirdColumnValue
  $OutputArray += $TmpObj
 }
 $OutputArray
}
Function Clear-Temp { # Clean all temp folder of a machine - Can be used for any folder - Will add rights if needed
 Param(
  [int]$NumberOfDays="5",
  [switch]$NoConfirm,
  $TempPath
 )

 #System Temp : [environment]::GetEnvironmentVariable("temp","machine")
 #Local Temp : $($env:Temp)
 #All users Temp : Get-ChildItem C:\Users\*\AppData\Local\Temp | Select-Object FullName

 if (! $TempPath) {
  if (Assert-IsAdmin) {
   $TempPath=@($($env:Temp),$([environment]::GetEnvironmentVariable("temp","machine")),$((Get-ChildItem -ErrorAction SilentlyContinue C:\Users\*\AppData\Local\Temp).FullName -join ";"))
  } else {
   $TempPath=@($($env:Temp))
  }
 }

 $TempPath -split ";" | ForEach-Object {
  try {
   $FileList=Get-ChildItem $_ -Recurse -ErrorAction Stop | Where-Object {($_.LastWriteTime -lt (Get-Date).AddDays(-$NumberOfDays))} | Select-Object FullName
   $ObjectCount=$FileList.count
   if (! $ObjectCount) {write-colored -Color "Green" -ColoredText "Nothing to do in folder $($_)" ; return}
   if (! $NoConfirm) {$Answer=Question "Are you sure you want to remove $ObjectCount files older than $NumberOfDays days in $($_)" "1"} else {$Answer=$true}
   if ($Answer) {
    write-Centered -Color "Magenta" -Message "[****** Removing $ObjectCount files from $($_) ******]"
    write-Blank
    $FileList | ForEach-Object {
     $CurrentError=''
     try {
      $CurrentFile=$_.FullName
      Progress -Message "Removing File " -Value $_.FullName
      Remove-Item $_.FullName -ErrorAction Stop -Force -Recurse
     } catch {
      ProgressClear
      $CurrentError=$Error[0]
      #Change rights if access is denied
      if ($CurrentError.CategoryInfo.Reason -eq "UnauthorizedAccessException") {
       write-colored -Color "DarkYellow" -NonColoredText "`r" -ColoredText "Changing rights for file $CurrentFile"
       #Change Owner To Admin Group
       Set-Rights $CurrentFile -ChangeOwner | Out-Null
       #Reenable Inheritance
       Set-Rights $CurrentFile -GlobalInheritance Add -Commit  | Out-Null
       #Change Rights to Admin Group
       # $Dump=Set-Rights $CurrentFile -User $(Get-UserFromSID('S-1-5-32-544')) -UserRights FullControl -UserInheritance None -Commit
       Remove-Item $CurrentFile -Force -ErrorAction Stop
       Return
      }
      #Print message if not file not found (because of recurse)
      if ($CurrentError.CategoryInfo.Reason -ne "ItemNotFoundException") {
       write-colored -Color "Red" -NonColoredText "`r$CurrentFile : " -ColoredText $Error[0]
      }
     }
    }
    ProgressClear
    $ObjectCountAfterAction=$ObjectCount-$((Get-ChildItem $_ -ErrorAction Stop | Where-Object {($_.LastWriteTime -lt (Get-Date).AddDays(-$NumberOfDays))})).Count
    write-Blank
    write-Centered -Color "Green" -Message "[****** $ObjectCountAfterAction files deleted from $($_) ******]"
   } else {
     write-host -foregroundcolor "Magenta" "Cancelled"
   }
   Write-StarLine
  } catch {
   write-colored -Color "Red" -ColoredText $Error[0]
  }
 }
}
Function ConvertTo-PDF { # Convert any file to PDF using the MS Print To PDF virtual Printer
 Param (
  [Parameter(Mandatory=$true)]$TextDocumentPath
 )
 Add-Type -AssemblyName System.Drawing
 $doc = New-Object System.Drawing.Printing.PrintDocument
 $doc.DocumentName = $TextDocumentPath
 $doc.PrinterSettings = new-Object System.Drawing.Printing.PrinterSettings
 $doc.PrinterSettings.PrinterName = 'Microsoft Print to PDF'
 $doc.PrinterSettings.PrintToFile = $true
 $file=[io.fileinfo]$TextDocumentPath
 $pdf= [io.path]::Combine($file.DirectoryName,$file.BaseName) + '.pdf'
 $doc.PrinterSettings.PrintFileName = $pdf
 $doc.Print()
 $doc.Dispose()
}
Function Disable-ScreenSaver { # Disable screensaver GPO (Will work only until the GPO reapplies)
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command"; return}
 $RegKey="\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
 $("ScreenSaveActive","ScreenSaverIsSecure","ScreenSaveTimeOut") | ForEach-Object {
  Set-RegAllUserRegKey $RegKey -RegName $_ -RegValue 0
 }
}
Function Disable-IEEnhancedSecurity { # Disable IEEnhancedSecurity on Windows Server
 $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
 Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
}
Function Expand-ZIPFile { # Unzip all files of a Zip to a specific destination - Non external app required
 Param (
  [Parameter(Mandatory=$true)]$File,
  [Parameter(Mandatory=$true)]$Destination
 )
 if ( ! (test-path $File)) { write-Colored -Color "Red" -ColoredText "Unavailable file : $File" ; return }

 New-Item -type directory "$Destination" 2>&1 | Out-Null
 $Shell = new-object -com shell.application
 $Zip = $Shell.NameSpace($File)
 foreach($item in $zip.items()) { $Shell.Namespace($Destination).copyhere($Item),16 }
}
Function Read-ZipFile2 { # Read Zip File content
 Param (
  [Parameter(Mandatory=$true)]$File
 )
 if ( ! (test-path $File)) { write-Colored -Color "Red" -ColoredText "Unavailable file : $File" ; return }

 $Shell = new-object -com shell.application
 $FullPath = (Resolve-Path $File).Path
 $Zip = $Shell.NameSpace($FullPath)
 $Zip.items()
}
Function Read-ZipFile { # Read Zip File content using dotnet Object (faster but locks the file)
 Param (
  [Parameter(Mandatory=$true)]$File
 )
 if ( ! (test-path $File)) { write-Colored -Color "Red" -ColoredText "Unavailable file : $File" ; return }

 $FullPath = (Resolve-Path $File).Path
 $ZipFileRead = [System.IO.Compression.ZipFile]::OpenRead($FullPath)
 $FileContent = $ZipFileRead.Entries
 $ZipFileRead.Dispose()
 $FileContent
}
Function Find-TextInFiles {
 Param (
  $Path,
  $TextToFind
 )
 Get-ChildItem -path $Path -Recurse -exclude *.dll,*.exe | Select-String $TextToFind | Select-Object -unique path | ForEach-Object { $_.path}
}
Function Get-FileFromURL { # Download file from URL - Try to follow link if possible
 Param (
  [Parameter(Mandatory=$true)]$Link,
  $OutputFile,
  $OutputFolder
 )
 #Should use browser authentication (check with basic parsing => mandatory for Core Server)

 #This will speed file download a lot !
 $progressPreference = 'silentlyContinue'

 $start_time = Get-Date
 Write-Colored -Color Cyan -PrintDate -ColoredText "Checking real filename"

 #Check if destination file is specified
 if (! $outputfile) {
  try {
   #Get Real FileName if available
   #Direct Connexion
   $FullLink = (Invoke-WebRequest -Uri $link -Method Head -UseBasicParsing).BaseResponse.ResponseUri.AbsoluteUri
   #Via Proxy
   if (! $FullLink) {
    $FullLink = (Invoke-WebRequest -Uri $link -Method Head -UseBasicParsing).BaseResponse.RequestMessage.RequestUri.OriginalString
   }
   $outputfile=[System.IO.Path]::GetFileName(($FullLink))
  } catch {
   #If cannot find filename and nothing is specified then the end of the link name will be used
   $outputfile=[System.IO.Path]::GetFileName(($link))
  }
 }

 Write-Colored -Color Cyan -PrintDate -ColoredText "Starting download of file $outputfile, please wait"

 try {
  Invoke-WebRequest -Uri $link -OutFile "$OutputFolder$outputfile" -UseBasicParsing -ErrorAction Stop
 } catch {
  write-Colored -Color "Red" -PrintDate -ColoredText $error[0]
  return
 }

 $FileSize = Format-FileSize (Get-ChildItem "$OutputFolder$outputfile").Length

 Write-Colored -Color Cyan -PrintDate -ColoredText "Downloaded file $($OutputFolder+$outputfile) in $((Get-Date).Subtract($start_time).Seconds) second(s) [$FileSize]"

 return "$OutputFolder$outputfile"
}
Function Get-FileContent { # Can be used to search for a string in a file
 Param (
  [Parameter(Mandatory=$true)]$File,
  [Parameter(Mandatory=$true)]$StringToSearch,
  [Switch]$Context
 )
 write-blank
 Write-Colored -Color $defaultblue -NonColoredText "Search for message " $StringToSearch -nonewline
 Write-Colored -Color $defaultblue -NonColoredText " in " $File

 if ( $Context ) {
  $filecontent=get-content $File | select-string $StringToSearch -context 0,1
 } else {
  $filecontent=get-content $File | select-string $StringToSearch
 }

 if ( ! $filecontent ) { write-blank ; write-colored "darkgreen" "" "Cannot find `"$StringToSearch`" in $File"} else { $filecontent }
}
Function Get-RDPSession { # List open RDP Sessions (Convert qwinsta them to PS Object)
 $Results = qwinsta
 #Extract titles
 $PropertiesTitle = $Results[0].Trim(" ") -replace (" +",";")
 #Convert to Title Case
 $PropertiesTitle = (Get-Culture).TextInfo.ToTitleCase($PropertiesTitle.ToLower()).split(";")
 #Add Column
 $PropertiesTitle += "Current"
 #Get sessions
 $Sessions = $Results[1..$($Results.Count -1)]

 Foreach ($Session in $Sessions) {
  #If first character is > then it's current session
  if ( $($Session.Substring(0,1).Trim()) -eq "`>" ) { $current = $true } else { $current = $false }
  $hash = [ordered]@{
   $PropertiesTitle[0] = $Session.Substring(1,18).Trim()
   $PropertiesTitle[1] = $Session.Substring(19,22).Trim()
   $PropertiesTitle[2] = $Session.Substring(41,7).Trim()
   $PropertiesTitle[3] = $Session.Substring(48,8).Trim()
   $PropertiesTitle[4] = $Session.Substring(56,12).Trim()
   $PropertiesTitle[5] = $Session.Substring(68,8).Trim()
   $PropertiesTitle[6] = $current
   'ComputerName' = $env:ComputerName
  }
  New-Object -TypeName PSObject -Property $hash
 }
}
Function Get-NetAdapterPowersaving { # Check Powersaving values on Network Adapters - Can disable PowerSaving for performance issues
 Param (
  [Switch]$Disable
 )
  $NIC_List=@()
 foreach ($NIC in (Get-NetAdapter -Physical)){
  $PowerSaving = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi | Where-Object {
   $_.InstanceName -match [Regex]::Escape($NIC.PnPDeviceID)
  }
  $NIC_List+=[pscustomobject]@{DeviceName=$NIC.Name;Description=$NIC.InterfaceDescription;MacAddress=$NIC.MacAddress;Status=$NIC.Status;PhysicalMediaType=$NIC.PhysicalMediaType;Powersaving=$PowerSaving.Enable}
  if ($Disable) {
   if ($PowerSaving.Enable){
    write-host "Disabling powersaving on device $($NIC.Name)"
    $PowerSaving.Enable = $false
    $PowerSaving | Set-CimInstance
  }
 }
 }
 return $NIC_List
}
Function Get-IniContent { # Convert INI file to a Powershell Object
 Param (
  $filePath
 )
 #Script found here : https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
 $ini = @{}
 switch -regex -file $FilePath {
 # Section
  "^\[(.+)\]" { $section = $matches[1] ; $ini[$section] = @{} ; $CommentCount = 0 }
  # Comment
  "^(;.*)$" { $value = $matches[1] ; $CommentCount = $CommentCount + 1 ; $name = "Comment" + $CommentCount ; $ini[$section][$name] = $value }
  # Key
   "(.+?)\s*=(.*)" { $name,$value = $matches[1..2] ; $ini[$section][$name] = $value }
 }
 return $ini
}
Function Get-WindowsImageInfo { # Get information from a Windows Image
 Param (
  $ImagePath="D:\sources\install.wim"
 )
 $IndexList = (Dism /Get-ImageInfo /ImageFile:$ImagePath | Select-String "Index") -replace "Index : ",""
 $OS_List=@()
 $IndexList | ForEach-Object {
  $CurrentIndexInfo=dism /Get-WimInfo /WimFile:$ImagePath /index:$_
  $OS_List+=New-Object PSObject -Property @{
  Name=($CurrentIndexInfo | select-string "Name :") -Replace("Name : ")
  Description=($CurrentIndexInfo | select-string "Description :") -Replace("Description : ")
  Architecture=($CurrentIndexInfo | select-string "Architecture :") -Replace("Architecture : ")
  Version=($CurrentIndexInfo | select-string "Version :") -Replace("Version : ")
  Edition=($CurrentIndexInfo | select-string "Edition :") -Replace("Edition : ")
  Installation=($CurrentIndexInfo | select-string "Installation :") -Replace("Installation : ")
  ProductType=($CurrentIndexInfo | select-string "ProductType :") -Replace("ProductType : ")
  ProductSuite=($CurrentIndexInfo | select-string "ProductSuite :") -Replace("ProductSuite : ")
  Created=($CurrentIndexInfo | select-string "Created :") -Replace("Created : ")
  Modified=($CurrentIndexInfo | select-string "Modified :") -Replace("Modified : ")
 }
 }
 $OS_List
}
Function Get-TeamviewerSettings { # Get all Teamviewer settings locally or remotely (Includes ID)
 Param (
  $remotecomputer
 )
 #On Winx86 : (get-ItemProperty "HKLM:\SOFTWARE\TeamViewer").ClientID
 try {
  if ($remotecomputer) {
   $returnresult=Invoke-Command -ComputerName $remotecomputer -ErrorAction Stop -ScriptBlock {get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\TeamViewer"}
  } else {
   $returnresult=get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\TeamViewer"
  }
  $returnresult | Select-Object ClientID,Proxy_IP,General_DirectLAN,Version
 }catch {
  write-host -foregroundcolor "Red" $Error[0]
 }
}
Function Get-AntiVirus { # Get Current antivirus used (Only if the antivirus respects Microsoft Implementations)
 Try {
  $AntiVirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
 } Catch {Return}

 Function Format-AntivirusIdToStatus ($AntivirusStatusID) {
  $AntivirusStatusIDHex = [convert]::ToString($AntivirusStatusID, 16).PadLeft(6,'0')

  $RealTimeProtectionStatus = switch ($AntivirusStatusIDHex.Substring(2,2)) {
   "00" {"Off"}
   "01" {"Disabled"}
   "10" {"On"}
   "11" {"On"}
   default {"UNKNOWN"}
  }
  $DefinitionStatus = switch ($AntivirusStatusIDHex.Substring(4,2)) {
   "00" {"Up To Date"}
   "10" {"Out Of Date"}
   default {"UNKNOWN"}
  }
  Return $RealTimeProtectionStatus,$DefinitionStatus
 }

 $ComputerList = @()

 $AntiVirusProducts | ForEach-Object {
  $Status=Format-AntivirusIdToStatus $_.productState
  $ComputerList += New-Object -TypeName PSObject -Property @{
   'Computername'=$computername
   'DisplayName'=$_.displayName
   'Product GUID'=$_.instanceGuid
   'Product Executable'=$_.pathToSignedProductExe
   'Reporting Executable'=$_.pathToSignedReportingExe
   'Definition Status'=$Status[1]
   'Real-time Protection Status'=$Status[0]
   'TimeStamp'=Format-Date $_.timestamp
  }
 }
 Return $ComputerList
}
Function Get-ProcessWithPath { # Shows all process which contains a path
 Get-Process -IncludeUserName  | Select-Object StartTime,Name,Id,UserName,Product,Description,Path | Where-Object Path | Sort-Object StartTime | Format-Table
}
Function Get-WallpaperForAllUsers { # Check the wallpaper applied for all users (can set a wallpaper for all users)
 Param (
  $Wallpaper="C:\Windows\Web\Wallpaper.jpg",
  [switch]$Set
 )
 New-PSDrive -Name 'HKU' -PSProvider Registry -Root 'HKEY_USERS' | Out-Null
 $RegValueToUpdate="Control Panel\Desktop"

 foreach( $User in $((Get-ChildItem HKU:\).PSChildName | Sort-Object )) {
  try {$Value=(Get-ItemProperty -ErrorAction SilentlyContinue -Path "HKU:\$user\$RegValueToUpdate")} catch { Write-Error "Nothing here" }
  if (! $value) {return} else {
   $CurrentUser=Get-UserFromSID $User
   $UserRegPath="HKU:\$user\$RegValueToUpdate"
   $OldValue=(Get-ItemProperty -path $UserRegPath).WallPaper
   write-host -foregroundcolor "Green" "Value for user `'$CurrentUser`' : $OldValue [$UserRegPath]"
   if ($Set) {
    Set-ItemProperty -path $UserRegPath -name 'Wallpaper' -value $Wallpaper
    $NewValue=(Get-ItemProperty -path $UserRegPath).WallPaper
    write-host -foregroundcolor "Green" "Value for user `'$CurrentUser`' : $NewValue [$UserRegPath]"
   }
  }
 }
}
Function Get-DuplicatePSModules { # Check duplicate Powershell modules as the old versions are not automatically removed (by default only checks one module folder)
 Param (
  $ModulePaths=($env:PSModulePath -split ";")[0], # Look only the first one by default, other are usually system ones
  [Switch]$Remove
 )
 #$PSModulePath variable contains too many folder. Specific Apps folders may appear here also.

 $OldModuleList = @()

 $ModulePaths | ForEach-Object {
  Try {
   Get-ChildItem $_ -Directory -ErrorAction Stop | ForEach-Object {
    $CurrentModule = $_.FullName
    $ModuleVersions = Get-ChildItem $CurrentModule -Directory | Select-Object Name,FullName,@{Label='Version';Expression={[Version]$_.Name}} | Sort-Object Version
    if ($ModuleVersions.count -gt 1) {
     $LatestVersion = $($ModuleVersions | Select-Object -Last 1).Name
     $ModuleVersions | Select-Object -Index 0, ($ModuleVersions.Count -2) | ForEach-Object {
      $OldModuleList+=[pscustomobject]@{Name = $_.FullName ; LatestVersion = $LatestVersion}
     }
    }
   }
   If ($Remove) {
    # Remove-Item $OldModuleList.Name -Recurse -Verbose -Force
    $OldModuleList | ForEach-Object {
     Write-Host -ForegroundColor Cyan "Removing $($_.Name)"
     Remove-Item $_.Name -Recurse -Force
    }
   } else {
    $OldModuleList
   }
  } Catch {
   write-host -foregroundcolor "red" $error[0]
  }
 }
}
Function Get-WebSiteCertificate { # Check the certificate from a remote website (Does not work on PS Core)
 Param (
  $URL
 )

 $ErrorActionPreference='Stop'

 Try {
 add-type @"
 using System.Net;
 using System.Security.Cryptography.X509Certificates;
 public class TrustAllCertsPolicy : ICertificatePolicy {
     public bool CheckValidationResult(
         ServicePoint srvPoint, X509Certificate certificate,
         WebRequest request, int certificateProblem) {
         return true;
     }
 }
"@
if ($([System.Net.ServicePointManager]::CertificatePolicy).ToString() -ne "System.Net.DefaultCertPolicy") {
 [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

  # $WebRequest = Invoke-WebRequest $URL -UseBasicParsing -UseDefaultCredentials
  $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint("$URL")

  $CertificateInfoHash = $ServicePoint.Certificate.GetCertHashString()
  $CertificateInfoSerialNumber = $ServicePoint.Certificate.GetSerialNumberString()
  $CertificateInfoEndDate = $ServicePoint.Certificate.GetExpirationDateString()
  $CertificateInfoStartDate = $ServicePoint.Certificate.GetEffectiveDateString()

  [pscustomobject]@{
   URL =  $URL;
   ProtocolVersion = $ServicePoint.ProtocolVersion.ToString();
   Issuer = $ServicePoint.Certificate.Issuer;
   Subject = $ServicePoint.Certificate.Subject;
   StartDate = $CertificateInfoStartDate;
   EndDate = $CertificateInfoEndDate;
   Hash = $CertificateInfoHash;
   Serial = $CertificateInfoSerialNumber;
  }

  } Catch {
   write-host -foregroundcolor "red" $error[0]
  }

}
Function Get-Certificate { # built from here : https://gist.github.com/jstangroome/5945820 - Works on PS Core
 Param (
  [Parameter(Mandatory=$true)][string]$Domain,
  [Int16]$Port=443,
  [Int]$Timeout = 500

 )
 $certificate = $null
 $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
 $TcpClient.ReceiveTimeout = $Timeout
 $TcpClient.SendTimeout = $Timeout

 try {
  $TcpClient.Connect($Domain, $Port)
  $TcpStream = $TcpClient.GetStream()
  $Callback = { param($sendername, $cert, $chain, $errors) return $true }
  $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)
  try {
   $SslStream.AuthenticateAsClient($domain)
   $certificate = $SslStream.RemoteCertificate
  } finally {
   $SslStream.Dispose()
  }
 } catch {
 Write-Host -ForegroundColor Red "Error checking URL `"$Domain`" on port $Port with a timeout of $Timeout`ms ($($Error[0]))"
 } finally {
  $TcpClient.Dispose()
 }
 if ($certificate) {
  if ($certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
   $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificate
  }
 }
 return $certificate
}
Function Get-CertificatStatusFromList { # Check Certificat status from a list
 Param (
  [Parameter(Mandatory=$true)][string]$FileName # Must be a CSV containing the list of site with the important column being 'SiteName'
 )
 import-csv $FileName | ForEach-Object {
   $URL_Called = $_.SiteName
   get-certificate -Domain $URL_Called -Timeout .1 | Select-Object  -ExcludeProperty Thumbprint @{Label='URL_Called';Expression={$URL_Called}},NotBefore,NotAfter,Issuer,Subject
 } | Export-Csv "$FileName`_Result.csv"
}
Function Get-Weather { # Shows weather
 Param (
  $Town = "Bordeaux"
 )
 (Invoke-WebRequest http://wttr.in/$Town -UserAgent "curl").Content
}
Function Install-ModuleRemote { # Install a Module on a remote machine
 Param (
  [Parameter(Mandatory=$true)]$RemoteServer,
  $ModuleName="PSWindowsUpdate",
  $PsModuleRequiredVersion="2.1.1.2",
  $PSMinVersion="5"
 )
 $ErrorActionPreference="Stop"
 try {

  #Check Remote Access
  write-host -foregroundcolor Blue "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - Checking Remote Access"
  $PsRemoteResult=$(Try {Test-WSMAN $RemoteServer -ErrorAction Stop | Out-Null; $true} catch {$false})
  If (! $PsRemoteResult) {Throw "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - WinRM is not accessible"}

  #Open Session
  write-host -foregroundcolor Blue "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - Opening Session"
  $SessionInfo=New-PSSession -ComputerName $RemoteServer -Name "UpdateModule$ModuleName"

  #Check Remote PS Version
  write-host -foregroundcolor Blue "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - Checking PS Version"
  $PSVersion=invoke-command -Session $SessionInfo -Scriptblock {$psversiontable.PSVersion.Major}
  if ($PSVersion -lt $PSMinVersion) {Throw "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - Powershell $PSMinVersion or more is required (Current version : $PSVersion)"}

  #Check existing module
  $RemotePsModuleVersion=invoke-command -ArgumentList $ModuleName -Session $SessionInfo -Scriptblock {
   $ModuleName=$args[0]
   # try {(get-command -Module $Using:ModuleName -ErrorAction Stop -WarningAction silentlyContinue)[0].Version -join "" } catch { "N/A" }
   try {(get-command -Module $ModuleName -ErrorAction Stop -WarningAction silentlyContinue)[0].Version -join "" } catch { "N/A" }
  }
  if ($RemotePsModuleVersion -eq $PsModuleRequiredVersion) {
   write-host -foregroundcolor Yellow "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - PS Module $ModuleName version $PsModuleRequiredVersion is already installed" ; return
  }

  #Remove existing module
  write-host -foregroundcolor Blue "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - Removing existing module $ModuleName"
  invoke-command -Session $SessionInfo -ArgumentList $ModuleName -scriptblock {
   # $ModuleName=$Using:ModuleName
   $ModuleName=$args[0]
   Remove-Module $ModuleName -ErrorAction SilentlyContinue
   # Uninstall-Module $ModuleName -ErrorAction SilentlyContinue
   $ModulePath="C:\Program Files\WindowsPowerShell\Modules\$ModuleName"
   write-host -foregroundcolor Blue "$(get-date -uformat '%Y-%m-%d %T') - Module Path : $ModulePath"
   if ($(Test-Path $ModulePath)) {
    Takeown /r /a /d Y /f $ModulePath | Out-Null
	Remove-Item -Recurse -Force $ModulePath | Out-Null
   }
  }

  #Install new module
  write-host -foregroundcolor Blue "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - Copy new module and import"
  $progressPreference = 'silentlyContinue'
  Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\$ModuleName\" -Force -Recurse -ToSession $SessionInfo -Destination "C:\Program Files\WindowsPowerShell\Modules\"
  invoke-command -Session $SessionInfo -scriptblock {
   Import-Module $ModuleName
  }
 } Catch {
  write-host -foregroundcolor Red "$(get-date -uformat '%Y-%m-%d %T') - $RemoteServer - ERROR : $($Error[0])"
 }
 try { Remove-PSSession $SessionInfo -ErrorAction SilentlyContinue } catch { Write-Error "Nothing here" }
}
Function New-Password { # Generate random password.  Will not start with : @ | and will not use : ' %^,<>"~`
 Param (
  [int]$Length=16,
  [ValidateSet("ASCII","ASCII-Limited","AlphaNum")]$Type="ASCII",
  [Switch]$Clip,
  [Switch]$ScriptCompatible
 )

 Switch ($Type) {
  ASCII {[string[]]$sourcedata=$(For ($a=33;$a -le 126;$a++) {$ascii+=,[char][byte]$a} ; $ascii)} #All ascii characters
  ASCII-Limited {[string[]]$sourcedata=$(For ($a=48;$a -le 122;$a++) {$ascii+=,[char][byte]$a} ; $ascii)} #Different set of ascii
  AlphaNum {[string[]]$sourcedata=For ($a=65;$a -le 90;$a++) {$sourcedata+=,[char][byte]$a} ; For ($a=97;$a -le 122;$a++) {$sourcedata+=,[char][byte]$a} ;For ($a=48;$a -le 57;$a++) {$sourcedata+=,[char][byte]$a}} #AlphaNum
 }

 #[char][byte]32 =
 #[char][byte]34 = "
 #[char][byte]37 = %
 #[char][byte]39 = '
 #[char][byte]44 = ,
 #[char][byte]58 = :
 #[char][byte]59 = ;
 #[char][byte]60 = <
 #[char][byte]61 = =
 #[char][byte]62 = >
 #[char][byte]63 = ?
 #[char][byte]64 = @
 #[char][byte]94 = ^
 #[char][byte]96 = `
 #[char][byte]126 = ~

 $Hashlist = "$([char][byte]39)$([char][byte]32)$([char][byte]37)$([char][byte]94)$([char][byte]44)$([char][byte]60)$([char][byte]62)$([char][byte]63)$([char][byte]34)$([char][byte]126)$([char][byte]96)"
 if ($ScriptCompatible) {
  $Hashlist = $Hashlist + $([char][byte]64) + $([char][byte]61) + $([char][byte]58) + $([char][byte]59)
 }

 $HashlistFirstCharacter = $HashlistFirst + $([char][byte]64)

 For ($loop=1; $loop -le $length; $loop++) {
  $Temp = $($sourcedata | GET-RANDOM)
  if ($loop -eq 1) {
   while ("$HashlistFirstCharacter".Contains($Temp)) {
    $Temp = $($sourcedata | GET-RANDOM)
   }
  } else {
   while ("$Hashlist".Contains($Temp)) {
    $Temp = $($sourcedata | GET-RANDOM)
   }
  }
  $TempPassword+=$Temp
 }

 #To send answer to clipboard
 if ($clip) {$TempPassword | CLIP}
 return $TempPassword
}
Function Optimize-Teams { # Reset Teams entirely
 Param (
  [Switch]$NoConfirm
 )
 $TeamsPath="$env:APPDATA\Microsoft\teams"
 # $TeamsBinaryPath="$env:LOCALAPPDATA\Microsoft\Teams"
 Write-Host "Stopping Teams Process" -ForegroundColor Cyan
 try {
  $TeamsProcess=Get-Process -ProcessName ms-teams -ErrorAction SilentlyContinue
  if ($TeamsProcess) {
   Stop-Process -Force -ErrorAction Stop $TeamsProcess
   Start-Sleep 3
   If ($(Get-Process -ProcessName Teams -ErrorAction SilentlyContinue)) {
    Throw "Error Stopping Teams process"
   }
  }
  Write-Host "Teams Process Sucessfully Stopped" -ForegroundColor Green
 } catch {
  Write-Host "Error Stopping Teams $($Error[0])" -ForegroundColor Red
 }
 Write-Host "Clearing Teams Disk Cache" -ForegroundColor Cyan
 try {
  $FolderList=@(
   "$TeamsPath\application cache\cache",
   "$TeamsPath\blob_storage",
   "$TeamsPath\databases",
   "$TeamsPath\cache",
   "$TeamsPath\gpucache",
   "$TeamsPath\Indexeddb",
   "$TeamsPath\Local Storage",
   "$TeamsPath\tmp"
  )
  $FolderList | ForEach-Object {
   $Folder=Get-ChildItem $_ -ErrorAction SilentlyContinue
   if ($Folder) {
    if ($NoConfirm) {
     Remove-Item -Path $_ -Recurse -Confirm:$false
    } else {
     Remove-Item -Path $_ -Recurse
    }
   }
  }
  Write-Host "Teams Disk Cache Cleaned" -ForegroundColor Green
 } catch {
  Write-Host "Error removing Teams data $($Error[0])"
 }

 Write-Host "Cleanup Complete... Launching Teams" -ForegroundColor Green
 #Start-Process -FilePath $TeamsBinaryPath\Current\Teams.exe -PassThru
}
Function Open-EtcHost { # Opens ETC Host in a notepad
 notepad c:\windows\system32\drivers\etc\hosts
}
Function Remove-SkypeAds { # Remove Skype ADs (may not be usefull anymore)
 $RegKey="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\skype.com\apps"
 New-Item $RegKey -Force | Out-Null
 Set-RegKey -RegKey $RegKey -Name "https" -Value "4" -Type "DWord"

 #not required if done before installing skype
 $SkypeProfileName = read-host "What is your skype username"
 while ( ! (Test-Path $env:APPDATA\skype\$SkypeProfileName\) -or ! $SkypeProfileName) {
  write-Colored -Color "Red" "" "`"$SkypeProfileName`" does not exist or a connexion was not done with this account on this computer"
  $SkypeProfileName = read-host "What is your skype username"
 }
 $configpath= "$env:APPDATA\skype\$SkypeProfileName\config.xml"

 (Get-Content $configpath).Replace("<AdvertPlaceholder>1</AdvertPlaceholder>","<AdvertPlaceholder>0</AdvertPlaceholder>") | Set-Content $configpath
}
Function Remove-LocalOutlookAddressBooks { # Remove local Outlook Offline Address Books
 try {
  remove-item "$($env:LOCALAPPDATA)\Microsoft\Outlook\Offline Address Books\" -recurse -ErrorAction Stop
 } catch {
  write-host -foregroundcolor "Red" $error[0]
 }
}
Function Save-Wallpapers { #Copy Spotlight images (Random Backgrounds) file to a folder
 Param (
  $Destination="$home\Pictures\Wallpapers"
 )
 if ( ! (test-path $Destination) ) { New-Item -type directory "$Destination" 2>&1 | Out-Null}
 Get-ChildItem $home\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\Assets | Where-Object {$_.length -gt 400kb} | ForEach-Object { Copy-Item -force -path $_.FullName -Destination "$Destination\$($_.Name).jpg" }
}
Function Set-LockScreenInfo { # Add information of the lockscreen wallpaper (Machine name etc.). No external software required [Work in progress]
 Param (
  $SourceFilename = "$($env:windir)\Web\Wallpaper.jpg",
  $SupportMail = "toto@toto.com",
  $SupportPhone = "3615"
 )

 #Load Var
 Add-Type -AssemblyName system.drawing

 $DestFilename = "$($env:windir)\system32\oobe\info\backgrounds\backgroundDefault.jpg"

 #If registry key does not exist create it (Requires admin rights)
 if(!(Test-Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background )) {
  New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\" -Name "Background" -Force
 }

 # should use : "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "UseOEMBackground" "1"
 # Check info https://www.howtogeek.com/112110/how-to-set-a-custom-logon-screen-background-on-windows-7/
 # Check info https://gallery.technet.microsoft.com/scriptcenter/LSInfo-BGInfo-for-WIndows-43d58172/view/Discussions#content

 #Force OEM Login
 New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background" -Name "OEMBackground" -Value 1 -PropertyType "DWord" -Force

 #Create required folders (Requires admin rights)
 mkdir "$($env:windir)\system32\oobe\info" -Force
 mkdir "$($env:windir)\system32\oobe\info\backgrounds" -Force

 #Load File
 $SourceFilename=get-item $SourceFilename
 $bmp = [System.Drawing.Image]::Fromfile($SourceFilename);

 #Set default font/colors
 $font = New-Object System.Drawing.Font("Arial",8,[System.Drawing.FontStyle]::Regular)
 $brushfg = [System.Drawing.Brushes]::Black
 $graphics = [System.Drawing.Graphics]::FromImage($bmp)

 #Draw
 $graphics.DrawString("Computername: $($env:COMPUTERNAME)",$font,$brushfg,500,0)
 $boottime = get-date -uformat '%Y-%m-%d %T' $((Get-CimInstance Win32_OperatingSystem).lastbootuptime)
 $graphics.DrawString("Last Boot: $($boottime)",$font,$brushfg,500,32)
 $graphics.DrawString("Support Mail : $SupportMail",$font,[System.Drawing.Brushes]::blue,500,48)
 $graphics.DrawString("Support Phone : $SupportPhone",$font,[System.Drawing.Brushes]::blue,500,64)

 $graphics.Dispose()
 $bmp.Save($DestFilename)
}
Function Set-CurrentUserLang { # Set User locales
 param(
  [ValidateSet("FR","DE","US","Mixed")][String]$Lang='Mixed'
 )

 $Lang_List=@()
 #Settings for Mixed : US Lang + FR KeyBoard
 $Lang_List+=[pscustomobject]@{Lang="Mixed";WinUserLanguageList="en-US";WinSystemLocale="en-US";Culture="fr-FR";WinHomeLocation="84";Input="0409:0000040C"}
 #Settings for FR : FR for all but Unicode
 $Lang_List+=[pscustomobject]@{Lang="FR";WinUserLanguageList="fr-FR";WinSystemLocale="en-US";Culture="fr-FR";WinHomeLocation="84";Input="0409:0000040C"}
 #Settings for US : US for all
 $Lang_List+=[pscustomobject]@{Lang="US";WinUserLanguageList="en-US";WinSystemLocale="en-US";Culture="en-US";WinHomeLocation="244";Input="0409:00000409"}
 #Settings for DE : DE for all but Unicode
 $Lang_List+=[pscustomobject]@{Lang="DE";WinUserLanguageList="de-DE";WinSystemLocale="en-US";Culture="de-DE";WinHomeLocation="94";Input="0407:00000407"}

 $ChosenLang=$Lang_List | Where-Object {$_.Lang -eq $Lang}

 write-host "Setting Language as $($ChosenLang.WinUserLanguageList)"
 #OS/Menu Language ('-Force' removes all other languages)
 set-WinUserLanguageList $($ChosenLang.WinUserLanguageList) -Force

 #Set UI Language
 # Set-WinUILanguageOverride $($ChosenLang.WinUserLanguageList)

 #Language For Non Unicode programs / Default Language
 Set-WinSystemLocale -SystemLocale $ChosenLang.WinSystemLocale

 #Regional Format (date separator etc.)
 Set-Culture $ChosenLang.Culture

 #Region
 Set-WinHomeLocation -GeoId $ChosenLang.WinHomeLocation

 if ($Lang -eq "Mixed") {
  #Keyboard (to have a different keyboard than language keyboard)
  $CurrentLang=Get-WinUserLanguageList
  $CurrentLang[0].InputMethodTips.Clear()
  $CurrentLang[0].InputMethodTips.Add($ChosenLang.Input)
  Set-WinUserLanguageList $CurrentLang -Force
 }
}
Function Set-CurrentUserLangToAllUsers { # Set the current local from current user to all user
 Param (
  [Parameter(Mandatory=$true)]$UserToCopy
 )

 ############ [ Variables ] ############

 $TempLocation='C:\Windows\Temp'
 $DefaultHKEY = "HKU\DEFAULT_USER"
 $DefaultRegPath = "C:\Users\Default\NTUSER.DAT"
 $UserList=@(".DEFAULT","DEFAULT_USER","S-1-5-18")

 #Remove all lang files
 Remove-Object$TempLocation\Lang*.reg

 Write-Colored "Green" -NonColoredText "$(get-date -uformat '%Y-%m-%d %T') - " -ColoredText "Mount REG"
 #Mount NTUSER.DAT in local Registry
 reg load $DefaultHKEY $DefaultRegPath | Out-Null
 #Mount HKU in Registry
 New-PSDrive -Name 'HKU' -PSProvider Registry -Root 'HKEY_USERS' | Out-Null

 $UserSID=Get-SIDFromUser $UserToCopy

 if (! $UserSID) {
  write-Colored -Color "Red" -NonColoredText "$(get-date -uformat '%Y-%m-%d %T') - " -ColoredText "User $UserToCopy does not exist"
  return
 }

 Try {
  get-item "HKU:\$UserSID\Control Panel\Input Method" | Out-Null
 } catch {
  write-Colored -Color "Red" -NonColoredText "$(get-date -uformat '%Y-%m-%d %T') - " -ColoredText "The profile of User $UserToCopy is not accessible (Open Session)"
  return
 }

 Write-Colored "Green" -NonColoredText "$(get-date -uformat '%Y-%m-%d %T') - " -ColoredText "Get Current User Config"

 #Export Required Registry Keys from Chosen user

 $CurrentPath="HKEY_USERS\$UserSID"

 try {
 reg export "$CurrentPath\Control Panel\Input Method" $TempLocation\LangExport_1.reg | Out-Null
 reg export "$CurrentPath\Control Panel\International" $TempLocation\LangExport_2.reg | Out-Null
 reg export "$CurrentPath\Keyboard Layout" $TempLocation\LangExport_3.reg | Out-Null
 } catch {
  write-Colored -Color "Red" -NonColoredText "$(get-date -uformat '%Y-%m-%d %T') - " -ColoredText $Error[0]
  return
 }

 if (! (test-path $TempLocation\LangExport_3.reg)) {
  write-Colored -Color "Red" -NonColoredText "$(get-date -uformat '%Y-%m-%d %T') - " -ColoredText "Error during export"
  Return
 }

 #Merge Files and Remove 'Registry Editor Line Export Line'
 (get-content $TempLocation\LangExport_*.reg).Replace('Windows Registry Editor Version 5.00','') | Out-File -Encoding unicode -FilePath $TempLocation\LangExportFull.Reg

 Write-Colored "Green" -NonColoredText "$(get-date -uformat '%Y-%m-%d %T') - " -ColoredText "Remove Current Info for all users and create New LangFile"

 @('Windows Registry Editor Version 5.00') | Out-File -Encoding unicode -FilePath $TempLocation\LangNew.reg

 #Remove all preloard Layout
 $UserList | ForEach-Object {
  $CurrentUser=$_
  Remove-ItemProperty "HKU:\$CurrentUser\Keyboard Layout\Preload\" -Name *
  (Get-Content $TempLocation\LangExportFull.Reg).replace('[HKEY_CURRENT_USER\', '[HKEY_USERS\'+$CurrentUser+'\') | Out-File -Encoding unicode -FilePath $TempLocation\LangNew.reg -Append
 }

 Write-Colored "Green" -NonColoredText "$(get-date -uformat '%Y-%m-%d %T') - " -ColoredText "Import new lang file"

 reg import $TempLocation\LangNew.Reg 2>&1 | Out-Null

 # write-colored -Color "Green" -ColoredText "Unload NTUSER.DAT"
 # reg unload $DefaultHKEY | Out-Null
}
Function Set-PowershellProfileForAllUsers { # Set a file as the profile for all users
 Param (
  $ProfilePath="$env:OneDrive\Git\PowershellScripts\iClic.ps1"
 )
 $ProfileList=$($PROFILE.AllUsersAllHosts,$PROFILE.CurrentUserAllHosts)
 $ProfileList | ForEach-Object {
  try {
   Remove-Item $_ -ErrorAction silentlycontinue
   new-Item -Path $_ -ItemType SymbolicLink -Value $ProfilePath -ErrorAction Stop -Force
  } catch {
   write-host -foregroundcolor "Red" $Error[0]
  }
 }
}
Function Set-Proxy { # Sets or Unsets the proxy
 Param (
  [Switch]$Set,
  [Switch]$UnSet,
  $Proxy,
  [switch]$System
 )
 $ErrorActionPreference="Stop"
 $ProxyVariables=@("HTTP_PROXY","HTTPS_PROXY")
 $ProxyVariables | ForEach-Object {
  $CurrentProxyVariable=$_
  if ($System) {
   try {
    if ($Set) { [Environment]::SetEnvironmentVariable($CurrentProxyVariable,$Proxy,"Machine") }
    if ($UnSet) { [Environment]::SetEnvironmentVariable($CurrentProxyVariable,$null,"Machine") }
   } Catch {
    write-host -foregroundcolor "Red" $Error[0]
   }
   Write-Host -ForegroundColor "Cyan" "$CurrentProxyVariable : $([Environment]::GetEnvironmentVariable($CurrentProxyVariable,"Machine"))"
  } else {
   if ($Set) {
    [Environment]::SetEnvironmentVariable($CurrentProxyVariable,$Proxy)
    [Environment]::SetEnvironmentVariable($CurrentProxyVariable,$Proxy,[System.EnvironmentVariableTarget]::User)
   }
   if ($UnSet) {
    [Environment]::SetEnvironmentVariable($CurrentProxyVariable,$null,[System.EnvironmentVariableTarget]::User)
    [Environment]::SetEnvironmentVariable($CurrentProxyVariable,$null)
   }
   Write-Host -ForegroundColor "Cyan" "$CurrentProxyVariable current session : $([Environment]::GetEnvironmentVariable($CurrentProxyVariable))"
   Write-Host -ForegroundColor "Cyan" "$CurrentProxyVariable Persistent: $([Environment]::GetEnvironmentVariable($CurrentProxyVariable))"
  }
 }
}
Function Show-ConsoleColors { # Print all the console possible colors
 $colors = [enum]::GetValues([System.ConsoleColor])
 Foreach ($bgcolor in $colors){
  Foreach ($fgcolor in $colors) { Write-Host "$fgcolor|"  -ForegroundColor $fgcolor -BackgroundColor $bgcolor -NoNewLine }
  Write-Host " on $bgcolor"
 }
}
Function Split-FirstAndLastName { # Split a firstname lastname to 2 objects
 Param (
  $FullName
 )
 if ( ! $FullName ) {return}
 #Take All but last space
 $FirstName=$FullName.substring(0,$FullName.lastindexof(" "))
 #Take only what's after last space
 $LastName=$FullName.substring($FullName.lastindexof(" ")+1)
 write-output "$FirstName,$LastName"
}
Function Wait-ProcessTermination { # Script used to wait for the end of a process
 Param (
  [Parameter(Mandatory=$true)]$Process,
  $Message
 )
 $InProgress=1 ; Start-Sleep -s 1
 while ( $InProgress -ne "0" ) {
  $InProgress=(Get-Process | Where-Object { $_.ProcessName -match $Process.split(".")[0] } | Measure-Object).count
  write-host -nonewline "`r$(get-date -uformat "%Y-%m-%d %T") - $Message"
  Start-Sleep -s 1
 }
}
Function MassCheckLinux {
 Param (
  $UserName=$env:USERNAME,
  $CommandLine=" `"hostnamectl | grep 'Operating System' | awk -F':' '{print ```$2}' | xargs`"",
  [Parameter(Mandatory=$true)]$Servers # List of Server Names

 )
 $ServerList=@()
 $Servers | ForEach-Object {
  $CurrentServer=$_
  Progress  -Message "Checking : "  -Value  $CurrentServer
  $PlinkString="plink -no-antispoof -ssh -batch $UserName@$CurrentServer"
  $FullCommandLine=$PlinkString+$CommandLine
  $OsVersionVersion=invoke-expression $FullCommandLine
  $ServerList+=New-Object PSObject -Property @{ServerName=$CurrentServer;Version=$OsVersionVersion}
 }
 $ServerList | Select-Object ServerName,Version
}
Function MassCheckLinuxScript {
 Param (
  $UserName = $env:USERNAME,
  [Parameter(Mandatory=$true)]$ScriptLocation, #Script Path (Full path)
  $ResultLocation = "$iClic_TempPath\LinuxStatus-$(get-date -uformat '%Y-%m-%d').csv",
  [Parameter(Mandatory=$true)]$Servers # List of Server Names
 )
 $FirstRun=$true
 $Servers | ForEach-Object {
  $CurrentServer = $_
  Progress  -Message "Checking : " -Value $CurrentServer
  $RemoteResult = plink -l $UserName -no-antispoof -ssh -batch -m $ScriptLocation $CurrentServer
  $Header="" ; $Content=""
  $RemoteResult -split ";" -replace "^ ","" | ForEach-Object {
   $Header+="$(($_ -split ":")[0]);" ; $Content+="$(($_ -split ":")[1].trim());"
  }
  if ($FirstRun) { $Header > $ResultLocation ;  $FirstRun=$False }
  $Content >> $ResultLocation
 }
}
Function Clear-CBSFolder {
 # For Windows 7 Bug : system queued windows error Reporting taking too much space
 Try {
  Get-Process TrustedInstaller -ErrorAction Stop | Stop-Process -Confirm:$false -Force
 } Catch {
  Write-Error "Nothing here"
 }
 Remove-Item C:\Windows\Logs\CBS\CbsPersist_*.*
 Remove-Item C:\Windows\Logs\CBS\cbs.log
 Start-Service TrustedInstaller
}
# Non standard verbs
Function ScreenOff { # Turns of screen (no additional software required)
 (Add-Type '[DllImport("user32.dll")] public static extern int SendMessage(int hWnd, int hMsg, int wParam, int lParam);' -Name a -Pas)::SendMessage(-1,0x0112,0xF170,2)
}
Function SignPSScript { # Sign Powershell Scripts
 Param (
  [Parameter(Mandatory=$true)]$ScriptName
 )
 $CodeSignCert = (@(Get-ChildItem Cert:\CurrentUser\My -CodeSign) | Sort-Object NotAfter)[-1]
 if ( ! $CodeSignCert ) {write-host -ForegroundColor "Red" "No code signing certificate found" ; return}
 Set-AuthenticodeSignature $ScriptName $CodeSignCert -TimestampServer http://timestamp.digicert.com -HashAlgorithm SHA256
}
Function Update { # Update machine (Windows Update / Chocolatey / Office / Store Apps / PS Modules)
 if ( ! (Assert-IsAdmin) ) {Write-host -ForegroundColor "red" "You must be admin to run this command"; return}

 write-host -foregroundcolor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Updating all apps using WinGet"
 try {
  winget upgrade --all --include-unknown
 } Catch {
  write-host -ForegroundColor "Magenta" "$(get-date -uformat '%Y-%m-%d %T') - $($Error[0])"
 }

 write-host -foregroundcolor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Updating Modules"
 try {
  update-module -ErrorAction Ignore -verbose
 } Catch {
  write-host -ForegroundColor "Magenta" "$(get-date -uformat '%Y-%m-%d %T') - $($Error[0])"
 }
 write-host -foregroundcolor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Checking Windows Updates"
 Get-WU -Install

 write-host -foregroundcolor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Office 365 Update"
 try {
  $OfficeBinary = "$env:CommonProgramFiles\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
  start-process $OfficeBinary -ArgumentList "/update user updatepromptuser=true forceappshutdown=true displaylevel=true" -wait -NoNewWindow
 } Catch {
  write-host -ForegroundColor "Magenta" "$(get-date -uformat '%Y-%m-%d %T') - Error during Office 365 Update"
 }

 write-host -foregroundcolor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Updating store Apps"
 try {
  Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" -ErrorAction Stop | Invoke-CimMethod -MethodName UpdateScanMethod -ErrorAction Stop
 } Catch {
  write-host -ForegroundColor "Magenta" "$(get-date -uformat '%Y-%m-%d %T') - Error during Windows Store Update"
 }

 write-host -foregroundcolor Cyan "$(get-date -uformat '%Y-%m-%d %T') - Upgrading choco packages"
 try {
  get-command "Choco" -ErrorAction Stop | Out-Null
  Choco Upgrade All -r
 } Catch {
  write-host -ForegroundColor "Magenta" "$(get-date -uformat '%Y-%m-%d %T') - Choco Not Present"
 }
}
Function LaunchAsUser { # Launch Script as another user
 Param (
  [Parameter(Mandatory=$true)]$script,
  [Parameter(Mandatory=$true)]$user,
  [Parameter(Mandatory=$true)]$pass
 )
 $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
 $credential = New-Object System.Management.Automation.PSCredential($user, $secpasswd)
 Start-Process -NoNewWindow powershell.exe -Credential $credential $script
}

# Misc Functions (Require Additionnal Tools)
Function Reset-GraphicCard { # Disables/Enables device [Requires Nirsoft DevManView] - On windows 11 can use : Ctrl+Win+Shift+B
 Param (
  $AppPath="C:\Apps\NirSoft",
  $GraphicCardName = "NVIDIA GeForce GTX 1080"
 )
 . "$AppPath\DevManView.exe" /disable_enable $GraphicCardName
}
Function LoginHome { # Open SSH Tunnel using Bitvise
 Param (
  $Path="$($env:OneDriveConsumer)\BitVise\BitVisePerso.tlp"
 )
 if ( ! (test-path $Path)) { write-Colored -Color "Red" -ColoredText "Unavailable path : $Path" ; return }
 # Use Pageant for Certificate Password
 bvssh -profile="$Path" -loginonstartup
}
Function Logcat { # Get Logcat from android device [Requires ADB]
 if ( ! (Assert-IsCommandAvailable adb) ) {return}
 adb logcat $args -T 100 | Format-TypeLogcat
}
Function MenuNmap { # Menu to help with default nmap scans [Requires NMAP]

 Param (
  $Server,
  $Port=443,
  $VLAN,
  [switch]$VPN=$False,
  [switch]$NoPing=$False
 )

 $ExitValue=$true
 Clear-Host

 if ($VPN) {
  $AdditionalCommandLine+='--unprivileged'
  $AdditionalMessage+=' [UnPrivileged]'
 }

 if ($NoPing) {
  $AdditionalCommandLine+=' -Pn'
  $AdditionalMessage+=' [NoPing]'
 }

 while ($ExitValue) {
  $Function_List=@()
  $Function_List+=New-Object PSObject -Property @{Name="Change Destination Server";Function='$Server=Read-host ServerName'}
  $Function_List+=New-Object PSObject -Property @{Name="Change Destination Port";Function='$Port=Read-host Port'}
  $Function_List+=New-Object PSObject -Property @{Name="Change Destination VLAN and MASK";Function='$VLAN=Read-host "VLAN/MASK"'}
  $Function_List+=New-Object PSObject -Property @{Name="Full Vuln Scan (Warning : Heavy load)";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine -v --script vuln $Server;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="Full Scan (Warning : Medium load)";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine -A -T4 $Server;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="Service/Daemon Version (Warning : Medium load)";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine -sV $Server;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="Standard TCP Test";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine -sV $Server;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="Standard UDP Test";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine -sT $Server;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="SSH Checks Auth Methods";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine --script ssh-auth-methods $Server -p $Port;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="SSH Checks Algorithms";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine --script ssh2-enum-algos $Server -p $Port;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="HTTPS/SSL Checks Cipher";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine --script ssl-enum-ciphers $Server -p $Port;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="SMB Protocols";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine --script smb-protocols $Server -p $Port;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="RDP Protocol";
   Function='While (! $Server) {$Server=Read-host ServerName};nmap $AdditionalCommandLine --script rdp-enum-encryption $Server -p $Port;Read-Host'}
  $Function_List+=New-Object PSObject -Property @{Name="Scan VLAN";
   Function='while (! $VLAN) {$VLAN=Read-host "VLAN/MASK"} ; nmap $AdditionalCommandLine -sP $VLAN;Read-Host'}

  Write-StarLine

  write-Centered "NMAP$AdditionalMessage"
  Write-Colored -Color "Green" -NonColoredText "[Current Server " -ColoredText $Server -NoNewLine
  Write-Colored -Color "Green" -NonColoredText "] [Current Port " -ColoredText $Port -NoNewLine
  Write-Colored -Color "Green" -NonColoredText "] [Current VLAN/Mask " -ColoredText $VLAN -NoNewLine
  Write-Colored -Color "Green" -NonColoredText "]"

  Write-StarLine
  $count=0 ; $Function_List | ForEach-Object { $count++ ; write-host -nonewline "[$count] - " ; write-host -foregroundcolor "Cyan" $_.Name }
  Write-StarLine

  #Read Answer
  try { [int]$ExitValue = Read-Host } catch { Write-Error "Nothing here" }

  if ($ExitValue -eq 0) {return}

  #Run Command if different than 0
  try {
   $CommandNumber=$ExitValue - 1
   $Command=$Function_List[$CommandNumber].Function
   write-host -ForegroundColor "Magenta" "[Running function '$($Function_List[$CommandNumber].Name)' ($Command)]"
   write-host
   invoke-expression -ErrorAction Stop $Command
   Clear-Host
  } catch {write-host -foregroundcolor "Red" "No command found ($($Error[0]))"}
 }
}
Function Get-UnapprovedProtocolAndCipher { # Remotely checks unsecure Ciphers [Requires NMAP]
 Param (
  $Computer=$Env:COMPUTERNAME,
  $Port=443
 )
 nmap --script ssl-enum-ciphers --unprivileged -p $Port $Computer | Select-String -NotMatch " - A","Starting Nmap","Host is up","NULL","compressors"
}
Function Add-PasswordToPFX { # Add a password to a PFX File [Requires OpenSSL]
 Param (
  [Parameter(Mandatory=$true)]$InputFile
 )
 if ( ! (Assert-IsCommandAvailable OpenSSL) ) {return}
 if ( ! (Test-Path $InputFile)) {write-host -ForegroundColor "Red" -Object "File $InputFile is not accessible" ; return}
 $TempFile = New-TemporaryFile
 $OutputFile = $InputFile -replace ".pfx","_withPassword.pfx"
 # Export PFX to PEM without a password
 $ResultTMP = openssl pkcs12 -in $InputFile -out $TempFile -nodes -password "pass:" 2>&1
 $ErrorMessage = $ResultTMP | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
 if ($ErrorMessage) { write-host -ForegroundColor "Red" -Object "Error during convertion of PFX to PEM [$ErrorMessage]" }
 # Recreted new PFX with randomly generated password
 $Password = new-password
 openssl pkcs12 -export -in $TempFile -out $OutputFile -password "pass:$Password" 2>&1
 $ErrorMessage = $ResultTMP | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
 if ($ErrorMessage) { write-host -ForegroundColor "Red" -Object "Errpr during convertion of PEM to PFX [$ErrorMessage]" }
 Remove-Item $TempFile
 [pscustomobject]@{Location=$OutputFile;Password=$Password}
}

# Video / Audio Encoding
Function Encode { # Encodes Video using FFMPEG [Requires FFMPEG]
 Param (
  $ffmpegbinary=$(get-command ffmpeg -ErrorAction SilentlyContinue),
  $Source,
  $Destination,
  [int]$QualityLevel=28,
  [Switch]$NoSound,
  [Switch]$Nvidia
 )

 Try {
  if (! $ffmpegbinary) {Throw "FFmpeg Binary not in path"}
  if (! (test-path $Source)) {Throw "Source Path Not Available"}
  # if (! (test-path $Destination)) {Throw "Destination Path Not Available"}

  if ($Nvidia) {
   # . $ffmpegbinary -hwaccel cuda -hwaccel_output_format cuda -i $Source -c:v hevc_nvenc -c:a aac -b:a 128k $Destination
   . $ffmpegbinary -hwaccel cuda -hwaccel_output_format cuda -i $Source -c:v hevc_nvenc -preset slow -c:a aac -b:a 128k $Destination
  }

  if ($NoSound -and (! $Nvidia)) {
   . $ffmpegbinary -i $Source -c:v libx265 -crf $QualityLevel -an $Destination
  } else {
   . $ffmpegbinary -i $Source -c:v libx265 -crf $QualityLevel -c:a aac -b:a 128k $Destination
  }
 } catch {
  Write-Host -ForegroundColor Red $Error[0]
 }
}
Function Get-AudioTracks { # Uses FFMPEG
 Param (
  [Parameter(Mandatory)]$FileName,
  $AnalyzeMaxDuration = '2147483647' # Max INT size
 )
 $AudioTrackListProbed = ffprobe -i $FileName -analyzeduration $AnalyzeMaxDuration -probesize $AnalyzeMaxDuration 2>&1 | select-string "Audio"
 $AudioTrackList = @()
 $ValueNumber = -1
 [Int]$Answer = "-1"
 $AudioTrackListProbed | ForEach-Object {
  $CurrentTrackName = $_.tostring().Trim()
  $AudioTrackList += $CurrentTrackName
  $ValueNumber++
  Write-host "$ValueNumber : $CurrentTrackName"
 }
 While (($Answer -gt $ValueNumber) -or ($Answer -lt 0)) {
  [Int]$Answer = Read-Host "Choose Audio Track (Between 0 & $ValueNumber) - 0 will be default"
 }
 $TrackSelected = $AudioTrackList[$Answer]
 Write-Host "Track Selected : $TrackSelected"
 Return $Answer
}
Function Save-AudioTrack { # Uses FFmpeg
 Param (
  [Parameter(Mandatory)]$FileName,
  $OutputFormat='ac3', # To get Uncompressed use wav / Slow but good use aac
  $AnalyzeMaxDuration = '2147483647' # Max INT size
 )
 $SelectedTrack = Get-AudioTracks -FileName $FileName
 ffmpeg -analyzeduration $AnalyzeMaxDuration -probesize $AnalyzeMaxDuration -i $FileName -map 0:a:$SelectedTrack "$($FileName)_AudioTrack_$($SelectedTrack).$OutputFormat"
}

#Security (Check Admin Mods)
Function Get-LocalGroupMod { # Get Information on the modification of local groups
 try {
  Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-Security-Auditing';ID=$(4732,4733)} -ErrorAction Stop | Select-Object RecordId,
 @{Label='DateTime';Expression={get-date -uformat '%Y-%m-%d %T' $_.TimeCreated -ErrorAction SilentlyContinue}},
 @{Label='Machine';Expression={($_.MachineName -Split ('\.'))[0]}},
 @{Label='User';Expression={try { $sid=$_.Properties[1].value ; $user=[wmi]"Win32_SID.SID='$sid'" ; $user.AccountName } catch { return $sid }}},
 @{Label='Type';Expression={if ($_.ID -eq 4732) {'User Added'} elseif ($_.ID -eq 4733) {'User Removed'} }},
 @{Label='Group';Expression={Get-UserFromSID $_.Properties[2].value}}
 } Catch {
  write-host -foregroundcolor "Red" $Error[0]
 }
}
Function Get-InstalledApps { # List all installed apps with required information
 $PathList = @()
 $PathList += [pscustomobject]@{Name="HKLM_32Bits_Path";Key="HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"}
 $PathList += [pscustomobject]@{Name="HKLM_64Bits_Path";Key="HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"}
 $PathList += [pscustomobject]@{Name="HKCU_32Bits_Path";Key="HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"}
 $PathList += [pscustomobject]@{Name="HKCU_64Bits_Path";Key="HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"}

 $GlobalResult = @()

 $PathList | ForEach-Object {
  $CurrentPath = $_.Name
  $Result = Get-ItemProperty $_.Key -ErrorAction SilentlyContinue | Select-Object *,@{Label='Source';Expression={$CurrentPath}}
  $GlobalResult += $Result
 }

 $GlobalResult | Select-Object  @{Label='Name';Expression={if ($_.DisplayName) {$_.DisplayName} else {$_.PSChildName} }},
  DisplayVersion, Publisher, InstallDate, UninstallString, WindowsInstaller, SystemComponent, InstallSource,
  InstallLocation, Source, @{Label='RegeditSrc';Expression={($_.PSPath -Split "::")[1]}} | Sort-Object Name
}
Function Get-InstalledAppsFromEvents { # Check all installed apps using event logs to see who installed what/when with what account
 Get-WinEvent -FilterHashtable @{ProviderName='MsiInstaller';ID=$(1033,1034,1035,1036,1037)} | Select-Object RecordId,
 @{Label='DateTime';Expression={get-date -uformat '%Y-%m-%d %T' $_.TimeCreated -ErrorAction SilentlyContinue}},
 @{Label='Machine';Expression={($_.MachineName -Split ('\.'))[0]}},
 @{Label='User';Expression={try { $sid=$_.UserId ; $user=[wmi]"Win32_SID.SID='$sid'" ; $user.AccountName } catch { return $sid }}},
 @{Label='Type';Expression={
  if ($_.ID -eq 1033) {'Application Installed'}
  elseif ($_.ID -eq 1034) {'Application Removed'}
  elseif ($_.ID -eq 1035) {'Application Changed'}
  elseif ($_.ID -eq 1036) {'Application Updated'}
  elseif ($_.ID -eq 1036) {'Application Update Removed'}}},
 @{Label='Name';Expression={$_.Properties[0].value}},
 @{Label='Manufacturer';Expression={$_.Properties[4].value}},
 @{Label='Version';Expression={$_.Properties[1].value}},
 @{Label='LanguageCode';Expression={$_.Properties[2].value}}
}
Function Get-LocalAdmin { # Prints local Admins

 $AdminGroupName = ([wmi]"Win32_SID.SID='S-1-5-32-544'").AccountName

 # List Administrator based on CIM
 $Administrators = @(
 ([ADSI]"WinNT://./$AdminGroupName").psbase.Invoke('Members') | ForEach-Object {
  $_.GetType().InvokeMember('AdsPath','GetProperty',$null,$($_),$null)
 }
 ) -match '^WinNT' -replace "WinNT://",""

 $Administrators | ForEach-Object {
  if ($_ -like "S-*") {
   $Result = Convert-SIDToAzureObjectId -Sid $_
   if (Get-Command "Az" -ErrorAction SilentlyContinue) {
    (Get-AzureADObjectInfo -ObjectID $Result).DisplayName
   } else {
    $Result
   }
  } else {
   $_
  }
 }
}

Function Get-LocalSecurityPolicy { # Show local security policies and which users have which local policies applied
 Param (
  $RightName
 )

 #Check Current User LocalSecurityPolicy : whoami /priv
 #Check Current User LocalSecurityPolicy (Full) : whoami /all

 $TempFile="$($env:Temp)\LogOnAsRightsExport.ini"
 $ExportResult=secedit /export /areas USER_RIGHTS /cfg $TempFile
 if ( ! $ExportResult.Contains('The task has completed successfully.') ) {
  Write-Host -Foregroundcolor Red $($ExportResult.Trim())
  Return
 }

 $ExportFileContent=Get-IniContent $TempFile

 if ($RightName) {
  #Filtered rights
  $($ExportFileContent.'Privilege Rights'.$RightName.Trim() -Replace "\*","" -Split "," | ForEach-Object { Get-UserFromSID $_ }) -Join(",")
 } else {
  #Print All Rights
  $ExportFileContent.'Privilege Rights'.GetEnumerator() | ForEach-Object {
   [pscustomobject]@{
    Name=$_.Name
    Rights=$(($_.Value -Replace "\*","" -Split ",").Trim() | ForEach-Object { Get-UserFromSID $_ }) -Join(",")
   }
  }
 }
}
Function MassCheckSecurityPolicy { # Mass Check Local Security Policy on servers
 Param (
  [Parameter(Mandatory=$true)]$ADGroupName
 )
 $ComputerList=try {Get-ADGroupMember $AdGroupName -Recursive} catch {write-colored -Color "Red" -ColoredText $Error[0]}
 $Result=$ComputerList | ForEach-Object {
  Progress -PrintTime -Message "Checking Server : " -Value $_.Name
  $SecPol=$(Send-RemoteCommand -ComputerName $_.Name -CommandLine "Get-LocalSecurityPolicy")
  If ($SecPol) {
   $SecPol | Select-Object @{Label='Server'; Expression={$_.PSComputerName}}, @{Label='SecPol'; Expression={$_.Name}},Rights
  } else {
   [pscustomobject]@{
    Server=$_.Name
    SecPol="Error Checking Rights"
    Rights="Error Checking Rights"
   }
  }
 }
 Return $Result
}

#Certificates
Function Get-LocalCertificate { # Print all local certificates
 Param (
  $CertPath=@('LocalMachine','CurrentUser')
 )
 $CertPath | ForEach-Object {
  $Location=$_
  Get-ChildItem CERT:\$Location\My | Select-Object @{LABEL="Location";EXPRESSION={$Location}},@{LABEL="Name";EXPRESSION={$_.Subject -replace "^CN=|^E=|,.*$"}},
   Thumbprint,HasPrivateKey,
   @{LABEL="KeyUsage";EXPRESSION={($_.EnhancedKeyUsageList -split "," -replace "\(.*\)|{|}","").trim() -join ","}},
   @{Label='ExportableKey';Expression={$_.PrivateKey.Key.ExportPolicy}},
   Issuer,NotAfter,@{N="Template";E={($_.Extensions | Where-Object {$_.oid.Friendlyname -match "Certificate Template Information"}).Format(0) -replace "(.+)?=(.+)\((.+)?", '$2'}}
 }
}
Function Get-EncryptionCertificate { # Retrive certificat that can be used for document encryption
 $Certificate=Get-ChildItem CERT:\CurrentUser\My | Select-Object Thumbprint,HasPrivateKey,Issuer,NotAfter,
 @{Name="Name";Expression={$_.Subject -replace "^CN=|^E=|,.*$"}},
 @{Name="KeyUsage";Expression={($_.EnhancedKeyUsageList -split "," -replace "\(.*\)|{|}","").trim() -join ","}},
 @{Name="Template";Expression={($_.Extensions | Where-Object {$_.oid.Value -match "1.3.6.1.4.1.311.21.7"}).Format(0) -replace "(.+)?=(.+)\((.+)?", '$2'}} `
  | Where-Object {$_.KeyUsage -like '*Document Encryption*'} | Sort-Object NotAfter | Select-Object -Last 1
 return $Certificate
}

# VPN (OnPrem)
Function Get-VPNUserFromIP {
 Param (
  $IP,
  [Parameter(Mandatory)]$VPNServerName
 )
 Invoke-Command -ScriptBlock ${function:Get-EventLogNPSSystem} -ComputerName $VPNServerName | Where-Object {$_.VPN_IP -eq $IP} | Select-Object DateTime,Status,UserUPN,@{Name="UserName";Expression={(Get-ADUserFromUPN $_.UserUPN).Name}},VPN_IP
}
Function Get-VPNIPFromUser {
 Param (
  $SamAccountName=$Env:USERNAME,
  [Parameter(Mandatory)]$VPNServerName
 )
 Try {
  $UPN=(get-aduser $SamAccountName).UserPrincipalName
  Invoke-Command -ScriptBlock ${function:Get-EventLogNPSSystem} -ComputerName $VPNServerName | Where-Object { ($_.UserUPN -eq $UPN ) -and ($_.Status -eq "IP Assignement")} | Select-Object DateTime,UserUPN,VPN_IP
 } Catch {
  Write-Host -ForegroundColor Red $Error[0]
 }
}
Function Get-VPNInfoFromUser {
 Param (
  $SamAccountName=$Env:USERNAME,
  [Parameter(Mandatory)]$VPNServerName,
  $NumberOfDay='7'
 )
 $UPN=(get-aduser $SamAccountName).UserPrincipalName
 write-host -ForegroundColor Cyan "Searching for VPN connection info for user $SamAccountName ($UPN) in the past $NumberOfDay days on server $VPNServerName (Initial search may take some time, please wait)"
 Get-EventLogNPSDetailed -ServerName $VPNServerName -StartTime $(Get-Date).addDays(-$NumberOfDay)  | Where-Object UPN -eq $UPN
}

# Azure
#Azure Connection
Function Connect-AzureCli {
 Param (
  [Parameter(Mandatory)]$AzureLogin
 )
 while (! $Password) {$Password=read-host -AsSecureString "Enter Azure Password `"$AzureLogin`" "}
 $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AzureLogin,$Password
 az login -u $Credential.UserName -p $Credential.GetNetworkCredential().Password
}
Function Connect-Azure {
 Param (
  [Parameter(Mandatory)]$AzureLogin
 )
 Connect-AzAccount
}
Function Open-MgGraphConnection {
 Param (
  $Scopes,
  $ContextScope
 )
 $MgGraphParam = $PSBoundParameters

 if (!(Get-MgContext)) {
  Connect-MgGraph @MgGraphParam | Out-Null
  $CurrentContext = Get-MgContext

  if ( ! $CurrentContext ) {
   write-host -foregroundcolor Red "Unable to connect to MgGraph" ; Return
  } else {
   write-host "Connected to MgGraph with user $($CurrentContext.Account) and $($CurrentContext.scopes.count) scopes"
  }
 }
}
# AzCli Env Management
Function Get-AzureEnvironment { # Get Current Environment used by AzCli
 # az account list --query [?isDefault] | ConvertFrom-Json | Select-Object tenantId,@{Name="SubscriptionID";Expression={$_.id}},@{Name="SubscriptionName";Expression={$_.name}},@{Name="WhoAmI";Expression={$_.user.name}}
 az account show | ConvertFrom-Json | Select-Object tenantId,@{Name="SubscriptionID";Expression={$_.id}},@{Name="SubscriptionName";Expression={$_.name}},@{Name="WhoAmI";Expression={$_.user.name}}
}
# Global Extracts
Function Get-AzureSubscriptions { # Get all subscription of a Tenant, a lot faster than using the Az Graph cmdline to "https://management.azure.com/subscriptions?api-version=2023-07-01"
 [CmdletBinding(DefaultParameterSetName='ShowAll')]
 Param (
  [Switch]$ShowAll,
  [parameter(Mandatory = $false, ParameterSetName="Name")][String]$Name,
  [parameter(Mandatory = $false, ParameterSetName="Id")][GUID]$Id
 )

 # Default Value
 $Arguments = '--output', 'json'

 if ( $ShowAll ) {
  $Arguments += '--all'
 } else {
  $Arguments += '--only-show-errors' # Ignore warnings when not set to Display All, otherwise this will appear each time
 }

 # Add Query
 $Arguments += '--query'

 if ($Name) {
  $Arguments += '"[?name==' + "'" + $Name + "'" + '].{id:id, name:name, state:state}"'
 } elseif ($Id) {
  $Arguments += '"[?id==' + "'" + $Id + "'" + '].{id:id, name:name, state:state}"'
 } else {
  $Arguments += '"[].{id:id, name:name, state:state}"'
 }
 az account list @Arguments | convertfrom-json | select-object id,name,state
}
Function Get-AzureManagementGroups { # Get all subscription and associated Management Groups Using AzCli
 $Query = "resourcecontainers | where type == 'microsoft.resources/subscriptions'"
 (az graph query -q $Query -o json --first 200 | ConvertFrom-Json).data | Select-Object name,SubscriptionID,@{Label="managementgroup";expression={$ManagementGroup=$_.properties.managementGroupAncestorsChain.displayName ; [array]::Reverse($ManagementGroup) ; $ManagementGroup -join "/" }} | Sort-Object managementgroup
}
Function Get-AzureManagementGroups_Other { # Get all subscription and associated Management Groups Using PS Module
 $Query = "resourcecontainers | where type == 'microsoft.resources/subscriptions'"
 $response = Search-AzGraph -Query $Query
 $response | Select-Object name,id,@{Label="managementgroup";expression={$ManagementGroup=$_.properties.managementGroupAncestorsChain.displayName ; [array]::Reverse($ManagementGroup) ; $ManagementGroup -join "/" }} | Sort-Object managementgroup
}
Function Get-AzurePublicIPs { # Get all public IPs in Azure (Only resources of Type : Public IPs)
 Get-AzureSubscriptions | foreach-object {
  $SubscriptionName = $_.Name
  az network public-ip list --subscription $_.id -o json | convertfrom-json | Select-Object @{Name="SubscriptionName";Expression={$SubscriptionName}},location,resourceGroup,ipAddress,linkedPublicIpAddress
 }
}
Function Get-AzureResources { # Get all Azure Resources for all Subscriptions
 Get-AzureSubscriptions | ForEach-Object {
  $subscriptionId = $_.id
  $subscriptionName = $_.name
  Progress -Message "Checking resources of subscription : " -Value $subscriptionName -PrintTime
  az account set --subscription $subscriptionId
  $CurrentSubscriptionResourcesJson = az resource list --output json
  try {
   $CurrentSubscriptionResources = $CurrentSubscriptionResourcesJson | ConvertFrom-Json -ErrorAction Stop
   $CurrentSubscriptionResources | ForEach-Object {
    $_ | Add-Member -NotePropertyName SubscriptionId -NotePropertyValue $subscriptionId
    $_ | Add-Member -NotePropertyName SubscriptionName -NotePropertyValue $subscriptionName
   }
  } Catch {
   Write-host -ForegroundColor Red -Object "Error in Subscription $subscriptionName ($subscriptionId)"
   "$subscriptionName;$subscriptionId;$($Error[0])" | Out-File "$iClic_TempPath\AzureAllResources_Error_$([DateTime]::Now.ToString("yyyyMMdd")).log" -Append
  }
  $CurrentSubscriptionResources | Export-Csv "$iClic_TempPath\AzureAllResources_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 }
 ProgressClear
}
Function Get-AzureResourceGroups { # Get all Azure Resource Groups for all Subscriptions
 Param (
  $ExportFileName = "$iClic_TempPath\AzureAllResourceGroups_$([DateTime]::Now.ToString("yyyyMMdd")).csv"
 )
 Get-AzureSubscriptions | ForEach-Object {
  $subscriptionId = $_.id
  $subscriptionName = $_.name
  Progress -Message "Checking resource groups of subscription : " -Value $subscriptionName -PrintTime
  az account set --subscription $subscriptionId
  $CurrentSubscriptionRG = az group list --output json | ConvertFrom-Json
  $CurrentSubscriptionRG | ForEach-Object {
   $_ | Add-Member -NotePropertyName SubscriptionId -NotePropertyValue $subscriptionId
   $_ | Add-Member -NotePropertyName SubscriptionName -NotePropertyValue $subscriptionName
  }
  $CurrentSubscriptionRG | Export-Csv $ExportFileName -Append
 }
 ProgressClear
 return $ExportFileName
}
Function Get-AzureKeyvaults { # Get all Azure Keyvaults for all Subscriptions (Checks ACLs)
 Param (
  [switch]$ShowAccessPolicies # Will add a huge time on the check
 )
 Get-AzureSubscriptions | ForEach-Object {
  $subscriptionId = $_.id
  $subscriptionName = $_.name
  Progress -Message "Checking Keyvaults of subscription : " -Value $subscriptionName -PrintTime
  az account set --subscription $subscriptionId
  $CurrentSubscriptionResources = az keyvault list --output json | ConvertFrom-Json
  $CurrentSubscriptionResources | ForEach-Object {
   Progress -Message "Checking Keyvaults of subscription : $subscriptionName : " -Value $_.Name -PrintTime
   $KV_Properties = az keyvault show --name $_.name --query '{properties:properties,systemData:systemData}' -o json | ConvertFrom-Json
   $Bypass = $KV_Properties.properties.networkAcls.bypass
   $PublicAccess = $KV_Properties.properties.publicNetworkAccess
   $NetworkACLsDefaultAction = $KV_Properties.properties.networkAcls.defaultAction
   if ($KV_Properties.properties.networkAcls.ipRules.count -eq 0) { $OpenIPs = $False } else { $OpenIPs = $True }
   if ($KV_Properties.properties.networkAcls.virtualNetworkRules.count -eq 0) { $PublicVNET = $False } else { $PublicVNET = $True }
   if ($KV_Properties.properties.privateEndpointConnections.count -eq 0) { $PrivateEndpoint = $False } else { $PrivateEndpoint = $True }
   if ($Bypass) {$BypassText = " with Bypass ($Bypass)"} else {$BypassText = ""}
   if (($PublicAccess -eq "Enabled") -and ($NetworkACLsDefaultAction -eq "Deny")) {$PublicFiltered = $True} else { $PublicFiltered = $False }
   if (($NetworkACLsDefaultAction -eq "Allow") -or (($PublicAccess -eq "Enabled") -and (! $NetworkACLsDefaultAction))) {$Public = $True} else { $Public = $False }
   if (($PublicAccess -eq "Disabled")) {$Private = $True} else { $Private = $True }

   $PublicMode = `
   if ($Public) {
    "Allow public access from all networks"
   } elseif ($PublicFiltered -and $OpenIPs -and $PublicVNET -and $PrivateEndpoint ) {
    "Allow public access from specific virtual networks and IP addresses : Open public IPs, VNETs and Private Endpoint$BypassText"
   } elseif ($PublicFiltered -and $OpenIPs -and $PublicVNET ) {
    "Allow public access from specific virtual networks and IP addresses : Open public IPs and VNETs$BypassText"
   } elseif ($PublicFiltered -and $PublicVNET -and $PrivateEndpoint ) {
    "Allow public access from specific virtual networks and IP addresses : Open public VNETs and Private Endpoint$BypassText"
   } elseif ($PublicFiltered -and $PublicVNET ) {
    "Allow public access from specific virtual networks and IP addresses : Open public VNETs$BypassText"
   } elseif ($PublicFiltered -and $OpenIPs -and $PrivateEndpoint ) {
    "Allow public access from specific virtual networks and IP addresses : Open public IPs and Private Endpoint$BypassText"
   } elseif ($PublicFiltered -and $OpenIPs ) {
    "Allow public access from specific virtual networks and IP addresses : Open public IPs$BypassText"
   } elseif ($PublicFiltered) {
    "Allow public access from specific virtual networks and IP addresses$BypassText"
   } elseif ($Private -and $Bypass -and (!$PrivateEndpoint)) {
    "$Bypass only"
   } elseif ($Private -and $PrivateEndpoint) {
    "Private$BypassText"
   } else {
    "Unmanaged"
   }

   $AccessPolicies_Users = $AccessPolicies_Apps = $AccessPolicies_Other = $AccessPolicies_Groups = @()
   if ($KV_Properties.properties.enableRbacAuthorization) {
    $AccessPolicies_Users = $AccessPolicies_Apps = $AccessPolicies_Other = $AccessPolicies_Groups = "RBAC"
   } else {
    if ($ShowAccessPolicies) {
     $KV_Properties.properties.accessPolicies | ForEach-Object {
      $CurrentPolicyID = Get-AzureADObjectInfo -ObjectID $_.objectId
      if ($CurrentPolicyID.Type -eq "#microsoft.graph.user") {
       $AccessPolicies_Users+=$CurrentPolicyID.DisplayName
      } elseif ($CurrentPolicyID.Type -eq "#microsoft.graph.servicePrincipal") {
       $AccessPolicies_Apps+=$CurrentPolicyID.DisplayName
      } elseif ($CurrentPolicyID.Type -eq "#microsoft.graph.group") {
       $AccessPolicies_Groups+=$CurrentPolicyID.DisplayName
      } else {
       $AccessPolicies_Other+=$CurrentPolicyID.ID
      }
     }
    } else {
     $AccessPolicies_Users = $AccessPolicies_Apps = $AccessPolicies_Other = $AccessPolicies_Groups = "Use_ShowAccessPolicies_For_Details"
    }
   }

   $_ | Add-Member -NotePropertyName RBAC_Enabled -NotePropertyValue $KV_Properties.properties.enableRbacAuthorization
   $_ | Add-Member -NotePropertyName Access_Policies_Count -NotePropertyValue $KV_Properties.properties.accessPolicies.count
   $_ | Add-Member -NotePropertyName SKU -NotePropertyValue $KV_Properties.properties.sku.name
   $_ | Add-Member -NotePropertyName Network_Mode -NotePropertyValue $PublicMode
   $_ | Add-Member -NotePropertyName Network_Public_Access -NotePropertyValue $KV_Properties.properties.publicNetworkAccess
   $_ | Add-Member -NotePropertyName Network_Bypass -NotePropertyValue $KV_Properties.properties.networkAcls.bypass
   $_ | Add-Member -NotePropertyName Network_Public_IP -NotePropertyValue $KV_Properties.properties.networkAcls.ipRules.count
   $_ | Add-Member -NotePropertyName Network_Public_VNET -NotePropertyValue $KV_Properties.properties.networkAcls.virtualNetworkRules.count
   $_ | Add-Member -NotePropertyName Network_Private_Endpoints -NotePropertyValue $KV_Properties.properties.privateEndpointConnections.count
   $_ | Add-Member -NotePropertyName Network_Default_Action -NotePropertyValue $NetworkACLsDefaultAction
   $_ | Add-Member -NotePropertyName SubscriptionId -NotePropertyValue $subscriptionId
   $_ | Add-Member -NotePropertyName SubscriptionName -NotePropertyValue $subscriptionName
   $_ | Add-Member -NotePropertyName AccessPolicies_Users -NotePropertyValue ($AccessPolicies_Users -join ",")
   $_ | Add-Member -NotePropertyName AccessPolicies_Groups -NotePropertyValue ($AccessPolicies_Groups -join ",")
   $_ | Add-Member -NotePropertyName AccessPolicies_Apps -NotePropertyValue ($AccessPolicies_Apps -join ",")
   $_ | Add-Member -NotePropertyName AccessPolicies_Other -NotePropertyValue ($AccessPolicies_Other -join ",")
   $_ | Add-Member -NotePropertyName createdAt -NotePropertyValue  $KV_Properties.systemData.createdAt
   $_ | Add-Member -NotePropertyName createdBy -NotePropertyValue  $KV_Properties.systemData.createdBy
   $_ | Add-Member -NotePropertyName lastModifiedAt -NotePropertyValue  $KV_Properties.systemData.lastModifiedAt
   $_ | Add-Member -NotePropertyName lastModifiedBy -NotePropertyValue  $KV_Properties.systemData.lastModifiedBy
   $_ | Add-Member -NotePropertyName lastModifiedByType -NotePropertyValue  $KV_Properties.systemData.lastModifiedByType
  }
  $CurrentSubscriptionResources | Export-Csv "$iClic_TempPath\AzureAllKeyvaults_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 }
}
Function Get-AzureStorageAccounts { # Get all Azure Storage Accounts for all Subscriptions (Checks ACLs)
 # Filter Example : | select SubscriptionName,resourceGroup,name,AD_Authentication,minimumTlsVersion,enableHttpsTrafficOnly,Network_Public_Mode,Network_Public_Blob_Mode,Network_Bypass,Network_Default_Action,Network_Private_Endpoint_Name | ft
 Get-AzureSubscriptions | ForEach-Object {
  $subscriptionId = $_.id
  $subscriptionName = $_.name
  Progress -Message "Checking Storage Accounts of subscription : " -Value $subscriptionName -PrintTime
  az account set --subscription $subscriptionId
  $CurrentSubscriptionResources = az storage account list -o json | ConvertFrom-Json
  $CurrentSubscriptionResources | ForEach-Object {
   Progress -Message "Checking Storage Account of subscription : $subscriptionName : " -Value $_.Name -PrintTime
   # $PublicMode = if (($_.publicNetworkAccess -eq "Enabled") -or ($_.networkRuleSet.defaultAction -eq "Allow")) {
   #  "Public"
   # } elseif ($_.publicNetworkAccess -eq "Disabled") {
   #  "Private"
   # } else {
   #  "Public Filtered"
   # }

   $Bypass = $_.networkRuleSet.bypass
   $PublicAccess = $_.publicNetworkAccess
   $NetworkACLsDefaultAction = $_.networkRuleSet.defaultAction
   if ($_.networkRuleSet.ipRules.count -eq 0) { $OpenIPs = $False } else { $OpenIPs = $True }
   if ($_.networkRuleSet.virtualNetworkRules.count -eq 0) { $PublicVNET = $False } else { $PublicVNET = $True }
   if ($_.privateEndpointConnections.count -eq 0) { $PrivateEndpoint = $False } else { $PrivateEndpoint = $True }
   if ($Bypass) {$BypassText = " with Bypass ($Bypass)"} else {$BypassText = ""}
   # Public Access is usually empty, when empty it seems the default value is Enabled
   if (($PublicAccess -ne "Disabled") -and ($NetworkACLsDefaultAction -eq "Deny")) {$PublicFiltered = $True} else { $PublicFiltered = $False }
   if (($NetworkACLsDefaultAction -eq "Allow") -or (($PublicAccess -ne "Disabled") -and (! $NetworkACLsDefaultAction))) {$Public = $True} else { $Public = $False }
   if (($PublicAccess -eq "Disabled")) {$Private = $True} else { $Private = $True }

   $PublicMode = `
   if ($Public) {
    "Allow public access from all networks"
   } elseif ($PublicFiltered -and $OpenIPs -and $PublicVNET -and $PrivateEndpoint ) {
    "Allow public access from specific virtual networks and IP addresses : Open public IPs, VNETs and Private Endpoint$BypassText"
   } elseif ($PublicFiltered -and $OpenIPs -and $PublicVNET ) {
    "Allow public access from specific virtual networks and IP addresses : Open public IPs and VNETs$BypassText"
   } elseif ($PublicFiltered -and $PublicVNET -and $PrivateEndpoint ) {
    "Allow public access from specific virtual networks and IP addresses : Open public VNETs and Private Endpoint$BypassText"
   } elseif ($PublicFiltered -and $PublicVNET ) {
    "Allow public access from specific virtual networks and IP addresses : Open public VNETs$BypassText"
   } elseif ($PublicFiltered -and $OpenIPs -and $PrivateEndpoint ) {
    "Allow public access from specific virtual networks and IP addresses : Open public IPs and Private Endpoint$BypassText"
   } elseif ($PublicFiltered -and $OpenIPs ) {
    "Allow public access from specific virtual networks and IP addresses : Open public IPs$BypassText"
   } elseif ($PublicFiltered) {
    "Allow public access from specific virtual networks and IP addresses$BypassText"
   } elseif ($Private -and $Bypass -and (!$PrivateEndpoint)) {
    "$Bypass only"
   } elseif ($Private -and $PrivateEndpoint) {
    "Private$BypassText"
   } else {
    "Unmanaged"
   }

   $_ | Add-Member -NotePropertyName AD_Authentication -NotePropertyValue $_.azureFilesIdentityBasedAuthentication.directoryServiceOptions
   $_ | Add-Member -NotePropertyName requireInfrastructureEncryption -NotePropertyValue $_.encryption.requireInfrastructureEncryption
   # $_ | Add-Member -NotePropertyName Network_Public_Mode -NotePropertyValue $_.publicNetworkAccess
   $_ | Add-Member -NotePropertyName Network_Mode -NotePropertyValue $PublicMode # Check if it's enough
   $_ | Add-Member -NotePropertyName Network_Public_Blob_Mode -NotePropertyValue $_.allowBlobPublicAccess # For Alert : Storage account public access should be disallowed
   $_ | Add-Member -NotePropertyName Network_Bypass -NotePropertyValue $_.networkRuleSet.bypass
   $_ | Add-Member -NotePropertyName Network_Open_IP -NotePropertyValue $_.networkRuleSet.ipRules.count
   $_ | Add-Member -NotePropertyName Network_Open_VNET -NotePropertyValue $_.networkRuleSet.virtualNetworkRules.count
   $_ | Add-Member -NotePropertyName Network_Open_Resources -NotePropertyValue $_.networkRuleSet.resourceAccessRules.count
   $_ | Add-Member -NotePropertyName Network_Default_Action -NotePropertyValue $_.networkRuleSet.defaultAction
   $_ | Add-Member -NotePropertyName Network_Private_Endpoint_Name -NotePropertyValue $_.privateEndpointConnections.Name
   $_ | Add-Member -NotePropertyName Network_Private_Endpoint_ID -NotePropertyValue $_.privateEndpointConnections.ID
   $_ | Add-Member -NotePropertyName SubscriptionId -NotePropertyValue $subscriptionId
   $_ | Add-Member -NotePropertyName SubscriptionName -NotePropertyValue $subscriptionName
  }
  $CurrentSubscriptionResources | Export-Csv "$iClic_TempPath\AzureAllStorageAccounts_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 }
}
Function Get-AzureSQLServers { # Get all Azure SQL Servers for all Subscription (check ACLs and firewall rules)
 Get-AzureSubscriptions | ForEach-Object {
  $subscriptionId = $_.id
  $subscriptionName = $_.name
  Progress -Message "Checking SQL Server of subscription : " -Value $subscriptionName -PrintTime
  az account set --subscription $subscriptionId
  $CurrentSubscriptionResources = az sql server list --output json | ConvertFrom-Json
  $CurrentSubscriptionResources | ForEach-Object {
   Progress -Message "Checking SQL Server of subscription : $subscriptionName : " -Value $_.Name -PrintTime
   $SQL_Properties = az sql server firewall-rule list --id $_.id -o json | ConvertFrom-Json
   $SQL_Vnet_Properties = az sql server vnet-rule list --id $_.id -o json | ConvertFrom-Json
   $SQL_Audit_Properties = az sql server audit-policy show --id $_.id -o json | ConvertFrom-Json
   $PublicMode = if (($_.publicNetworkAccess -eq "Enabled") -and (($SQL_Properties | Where-Object name -ne 'AllowAllWindowsAzureIps').Count -gt 0) ) {
    "Public Filtered"
   } elseif ($_.publicNetworkAccess -eq "Disabled") {
    "Private"
   } elseif (($_.publicNetworkAccess -eq "Enabled") -and (($SQL_Properties | Where-Object name -eq 'AllowAllWindowsAzureIps').Count -eq 1) -and ($SQL_Properties.Count -eq 1) ) {
    "Microsoft IPs Only"
   } elseif (($_.publicNetworkAccess -eq "Enabled") -and (($SQL_Properties | Where-Object name -ne 'AllowAllWindowsAzureIps').Count -eq 0) ) {
    "Public Without Open IPs"
   } else {
    "Other"
   }
   if (($SQL_Properties | Where-Object name -eq 'AllowAllWindowsAzureIps').Count -eq 1) {$Network_Bypass = 'AllowAllWindowsAzureIps'} else {$Network_Bypass = 'None'}

   $_ | Add-Member -NotePropertyName RBAC_Enabled -NotePropertyValue $_.administrators.administratorType
   $_ | Add-Member -NotePropertyName RBAC_Enforced -NotePropertyValue $_.administrators.azureAdOnlyAuthentication
   $_ | Add-Member -NotePropertyName Admin_Login -NotePropertyValue $_.administrators.login
   $_ | Add-Member -NotePropertyName Admin_Type -NotePropertyValue $_.administrators.principalType
   $_ | Add-Member -NotePropertyName Admin_SID -NotePropertyValue $_.administrators.sid
   $_ | Add-Member -NotePropertyName Auditing_Status -NotePropertyValue $SQL_Audit_Properties.state
   $_ | Add-Member -NotePropertyName Network_Mode -NotePropertyValue $PublicMode
   $_ | Add-Member -NotePropertyName Network_Bypass -NotePropertyValue $Network_Bypass
   $_ | Add-Member -NotePropertyName Network_Open_IP -NotePropertyValue ($SQL_Properties | Where-Object name -ne 'AllowAllWindowsAzureIps').Count
   $_ | Add-Member -NotePropertyName Network_Open_VNET -NotePropertyValue $SQL_Vnet_Properties.Count
   $_ | Add-Member -NotePropertyName Network_PrivateEndpoint -NotePropertyValue ($_.privateEndpointConnections.properties.privateEndpoint.id -split("/"))[-1]
   $_ | Add-Member -NotePropertyName SubscriptionId -NotePropertyValue $subscriptionId
   $_ | Add-Member -NotePropertyName SubscriptionName -NotePropertyValue $subscriptionName
  }
  $CurrentSubscriptionResources | Export-Csv "$iClic_TempPath\AzureAllSQLServers_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 }
}
Function Get-AzureVMs { # Get all Azure VM and linked Extensions # TO DO : Add all Tags in separate columns, same for Extensions [See example : Get-MDCConfiguration]
 Get-AzureSubscriptions | ForEach-Object {
  $subscriptionId = $_.id
  $subscriptionName = $_.name
  Progress -Message "Checking VMs of subscription : " -Value $subscriptionName -PrintTime
  az account set --subscription $subscriptionId
  $CurrentSubscriptionResources = az vm list --show-details --output json | ConvertFrom-Json
  $CurrentSubscriptionResources | ForEach-Object {
   Progress -Message "Checking VMs of subscription : $subscriptionName : " -Value $_.Name -PrintTime
   $VM_Extensions = az vm extension list --ids $_.Id -o json | ConvertFrom-Json
   if ($_.privateIps -and $_.publicIps) {
    $Network_Mode = "PublicAndPrivate"
   } elseif ($_.privateIps) {
    $Network_Mode = "Private"
   } elseif ($_.publicIps) {
    $Network_Mode = "Public"
   } else {
    $Network_Mode = "Unknown"
   }

   $_ | Add-Member -NotePropertyName VM_Type -NotePropertyValue $_.hardwareProfile.vmSize
   $_ | Add-Member -NotePropertyName VM_Name -NotePropertyValue $_.Name
   $_ | Add-Member -NotePropertyName LinkedResourcesCount -NotePropertyValue $_.resources.Count
   $_ | Add-Member -NotePropertyName LocalAdmin -NotePropertyValue $_.osProfile.adminUsername
   $_ | Add-Member -NotePropertyName LocalAdminPassword -NotePropertyValue $_.osProfile.adminPassword
   $_ | Add-Member -NotePropertyName OSType -NotePropertyValue $_.storageProfile.osDisk.osType
   $_ | Add-Member -NotePropertyName OSRefImg -NotePropertyValue $_.storageProfile.osDisk.imageReference
   $_ | Add-Member -NotePropertyName Network_Mode -NotePropertyValue $Network_Mode
   $_ | Add-Member -NotePropertyName Owner -NotePropertyValue $_.tags.Owner
   $_ | Add-Member -NotePropertyName GNumber -NotePropertyValue $_.tags.'G-number'
   $_ | Add-Member -NotePropertyName Extensions -NotePropertyValue ($VM_Extensions.typePropertiesType -join ";")
   $_ | Add-Member -NotePropertyName SubscriptionId -NotePropertyValue $subscriptionId
   $_ | Add-Member -NotePropertyName SubscriptionName -NotePropertyValue $subscriptionName
  }
  $CurrentSubscriptionResources | Export-Csv "$iClic_TempPath\AzureAllVMs_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 }
}
Function Get-AzurePolicyExemptions { # Get All Azure Policy Exemptions
 Get-AzureSubscriptions | Where-Object State -eq Enabled | ForEach-Object {
  $CurrentSubscriptionID = $_.id
  $CurrentSubscriptionName = $_.name
  az account set -n $CurrentSubscriptionID
  az policy exemption list -i --only-show-errors | convertfrom-json | Select-Object -ExcludeProperty policyDefinitionReferenceIds,systemData,metadata -Property *,
   @{N="PolicyName";E={Progress -Message "Checking Policy of subscription $CurrentSubscriptionName : " -Value $_.displayName ; ($_.policyAssignmentId -split("/"))[-1]}},
   @{N="Scope";E={($_.id.Split("/providers/Microsoft.Authorization/"))[0]}},
   @{N="Sys_createdAt";E={$_.systemData.createdAt}},
   @{N="Sys_createdBy";E={$_.systemData.createdBy}},
   @{N="Sys_createdByDisplay";E={Get-AzureADUserFromUPN $_.systemData.createdBy -Fast}},
   @{N="Sys_createdByType";E={$_.systemData.createdByType}},
   @{N="Sys_lastModifiedAt";E={$_.systemData.lastModifiedAt}},
   @{N="Sys_lastModifiedBy";E={$_.systemData.lastModifiedBy}},
   @{N="Sys_lastModifiedByType";E={$_.systemData.lastModifiedByType}} | Export-Csv "$iClic_TempPath\AzurePolicyExemptions_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 }
}
Function Get-AzureWebAppSSL { # Get All Azure App Service Certificate in the tenant
 Get-AzureSubscriptions | ForEach-Object {
  $subscriptionId = $_.id
  $subscriptionName = $_.name
  Progress -Message "Checking App Service Certificates of subscription : " -Value $subscriptionName -PrintTime
  az account set --subscription $subscriptionId
  $RG_WithCertificates = ($(az resource list --output json).tolower() | convertfrom-json | Where-Object type -like "*certificate*" | Select-Object resourcegroup -Unique).resourcegroup
  if ($RG_WithCertificates.count -gt 0) { # Skip if no Certificate found in Subscription
   $RG_WithCertificates | ForEach-Object {
    $CurrentSubscriptionResources = az webapp config ssl list -g $_ | convertfrom-json
    $CurrentSubscriptionResources | ForEach-Object {
     $_ | Add-Member -NotePropertyName SubscriptionName -NotePropertyValue $subscriptionName
     $_ | Add-Member -NotePropertyName subscriptionId -NotePropertyValue $subscriptionId
    }
    $CurrentSubscriptionResources | Export-Csv "$iClic_TempPath\WebAppCertificates_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
   }
  }
 }
}
Function Get-AzureCertificates { # Check All Azure Web Certificates -> Check keyVaultId error
 Get-AzureSubscriptions | ForEach-Object {
  $subscriptionId = $_.id
  $subscriptionName = $_.name
  Progress -Message "Checking Certificates of subscription : " -Value $subscriptionName -PrintTime
  $CertificateList = (az rest --method GET --uri "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Web/certificates?api-version=2022-03-01" | convertfrom-json).value
  $CertificateList | Select-Object -ExpandProperty properties -ExcludeProperty tags,properties,keyVaultId *,@{Name="SubscriptionID";Expression={$subscriptionId}},@{Name="SubscriptionName";Expression={$subscriptionName}} `
   | Export-Csv "$iClic_TempPath\AzureCertificates_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 }
}
Function Get-AzureReservation { # Check all Azure Reservation Orders
 Param (
  [Switch]$ShowPermissions
 )
 $Reservationlist = az reservations reservation-order list | convertfrom-json
 if (! $ShowPermissions) { Return $Reservationlist} else {
  $Reservationlist | ForEach-Object {
   az role assignment list --scope $_.id | convertfrom-json
  }
 }
}
Function Get-AzureApplicationGateway {
 Get-AzureSubscriptions | ForEach-Object {
  $SubscriptionID = $_.id
  $SubscriptionName = $_.name
  Progress -Message "Currently processing " -Value $SubscriptionName -PrintTime
  (az rest --method GET --uri "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Network/applicationGateways?api-version=2023-11-01"| ConvertFrom-Json).value `
   | Select-Object -ExcludeProperty properties *,@{Name="Listeners";Expression={($_.properties.httpListeners.properties.hostName + $_.properties.httpListeners.properties.hostNames) -join ";"}}
 }
}
# Convert Methods
Function Get-AzureADUserFromUPN { # Find Azure Ad User info from part of UPN ; Added Token possibility which will be a lot faster
 Param (
  [Parameter(Mandatory=$true)]$UPN,
  [switch]$HideError,
  [switch]$Fast,
  $Token
 )

 if ($Token) {
  Try {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }

   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }

   $GraphURL = "https://graph.microsoft.com/beta/users?`$filter=startswith(userprincipalname,'$UPN')"

   $ResultJSON = Invoke-RestMethod -Method GET -headers $header -Uri $GraphURL
   $Result = $ResultJSON.Value

  } catch {
   $Exception = $($Error[0])
   $StatusCode = ($Exception.ErrorDetails.message | ConvertFrom-json).error.code
   $StatusMessage = ($Exception.ErrorDetails.message | ConvertFrom-json).error.message
   if (! $HideError ) { Write-host -ForegroundColor Red "Error searching for user $UPN ($StatusCode | $StatusMessage))" }
  }
 } else {
  if ($Fast) {
   $Result = az ad user list --output json --filter "userprincipalname  eq '$UPN'" --query '[].{displayName:displayName}' -o tsv
  } else {
   $Result = az ad user list --output json --filter "startswith(userprincipalname, '$UPN')" --query '[].{userPrincipalName:userPrincipalName,displayName:displayName,objectId:id,mail:mail}' | ConvertFrom-Json
  }
 }
 if ($result) {
  return $Result
 } else {
  if (! $HideError ) {write-host -ForegroundColor Red "No user found starting with $UPN" }
 }
}
Function Get-AzureADUserFromDisplayName { # Find Azure Ad User info from part of displayname
 Param (
  [Parameter(Mandatory=$true)]$DisplayName,
  [switch]$Fast
 )
 if ($Fast) {
  $Result = az ad user list --output json --filter "displayName  eq '$DisplayName'" --query '[].{objectId:id}' -o tsv
 } else {
  $Result = az ad user list --output json --filter "startswith(displayName, '$DisplayName')" --query '[].{userPrincipalName:userPrincipalName,displayName:displayName,objectId:id,mail:mail}' | ConvertFrom-Json
 }
 if ($result) { return $Result } else { write-host -ForegroundColor Red "No user found starting with $DisplayName" }
}
Function Get-AzureADUserFromMail { # Find Azure Ad User info from email
 Param (
  [Parameter(Mandatory=$true)]$Mail,
  $Token

 )
 if ($Token) {
  Try {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }

   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }

   $GraphURL = "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$Mail'"

   $ResultJSON = Invoke-RestMethod -Method GET -headers $header -Uri $GraphURL
   $ResultJSON.Value

  } catch {
   $Exception = $($Error[0])
   $StatusCode = ($Exception.ErrorDetails.message | ConvertFrom-json).error.code
   $StatusMessage = ($Exception.ErrorDetails.message | ConvertFrom-json).error.message
   if (! $HideError ) { Write-host -ForegroundColor Red "Error searching for user $UPN ($StatusCode | $StatusMessage))" }
  }
 } else {
  $Result = az ad user list --output json --filter "mail eq '$Mail'" --query '[].{userPrincipalName:userPrincipalName,mail:mail,displayName:displayName,objectId:id}' | ConvertFrom-Json
  if ($result) { return $Result } else { write-host -ForegroundColor Red "No user found with email $Mail" }
 }
}
Function Get-AzureSubscriptionNameFromID { #Retrieve name of Subscription from the ID
 Param (
  [Parameter(Mandatory=$true)]$SubscriptionID
 )
 (Get-AzureSubscriptions | Where-Object id -eq $SubscriptionID).Name
}
Function Convert-Tag { # Convert Tags to a usable value
 Param (
  $TagToSearch,
  $TagVariable # Format : name1=value1 , name2=value2
 )
 # Replace beginning and end
 $TrimmedValue = $TagVariable -replace("@{","") -replace(" *}","") -split("; ")
 (($TrimmedValue | Select-String $TagToSearch) -split"=")[1]
}
Function Convert-GuidToSourceAnchor { # Convert Azure AD Object ID to Source Anchor (used in AAD Connect)
 Param (
  $Guid
 )
 $GUID_Obj = [GUID]$Guid
 [System.Convert]::ToBase64String($GUID_Obj.ToByteArray())
}
Function Convert-SourceAnchorToGUID { # Convert Source Anchor to Azure AD Object ID (used in AAD Connect)
 Param (
  $SourceAnchor
 )
 [Guid]([Convert]::FromBase64String("$SourceAnchor"))
}
Function Convert-AzureAppRegistrationPermissionsGUIDToReadable { #Converts all GUID of Object containing App Registration Permission List with GUID to Readable Names
 Param (
  [Parameter(Mandatory=$true)]$AppRegistrationObjectWithGUIDPermissions,
  $IDConversionTable, #Send Conversion Table for faster treatment
  $Token
 )
 # If no conversion table is passed, it will be generated for the single Object - Will add 2 seconds to the treament of the request - Not recommended for big treatment
 if ( ! $IDConversionTable ) {
  $IDConversionTable = @()
  if ($Token) {
   $AppRegistrationObjectWithGUIDPermissions.PolicyID | Select-Object -Unique | ForEach-Object { $IDConversionTable += Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $_ -Token $Token }
  } else {
   $AppRegistrationObjectWithGUIDPermissions.PolicyID | Select-Object -Unique | ForEach-Object { $IDConversionTable += Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $_ }
  }
 } else {
  $IDConversionTable = $IDConversionTable | select-object -ExcludeProperty ServicePrincipalName,ServicePrincipalID
 }

 $AppRegistrationObjectWithGUIDPermissions | ForEach-Object {
  $CurrentPolicy = $_.PolicyID ;
  $CurrentRule = $_.RuleID  ;
  $Policy = $IDConversionTable | where-object {($_.PolicyID -eq $CurrentPolicy) -and ($_.RuleID -eq $CurrentRule)}
  # Some policies have multiple of the same set of PolicyID and RuleID .... If there are multiple result, will take the admin result or the first result
  if ($Policy.Count -gt 1) {
   Write-Host -Foregroundcolor "Magenta" "WARNING : PolicyID $CurrentPolicy with RuleID $CurrentRule contains multiple result"
   if ($Policy | Where-Object Type -eq "Admin") {$Policy = $Policy | Where-Object Type -eq "Admin" } else {$Policy = $Policy[0]}
  }
  [pscustomobject]@{
   AppRegistrationName=$_.AppRegistrationName
   AppRegistrationID=$_.AppRegistrationID
   PolicyName=$Policy.PolicyName
   PolicyID=$Policy.PolicyID
   Value=$Policy.Value
   ValueID=$Policy.RuleID
   PermissionType=$Policy.PermissionType
   Description=$Policy.Description
   # Type=$Policy.Type => This value is empty
  }
 }
}
Function Convert-AzureServicePrincipalPermissionsGUIDToReadable { #Converts all GUID of Object containing Service Principal Permission List with GUID to Readable Names
 Param (
  [Parameter(Mandatory=$true)]$ServicePrincipalObjectWithGUIDPermissions,
  $IDConversionTable #Send Conversion Table for faster treatment
 )
 # If no conversion table is passed, it will be generated for the single Object - Will add 2 seconds to the treament of the request - Not recommended for big treatment
 if ( ! $IDConversionTable ) {
  $IDConversionTable = @()
  $ServicePrincipalObjectWithGUIDPermissions.PolicyID | Select-Object -Unique | ForEach-Object { $IDConversionTable += Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $_ }
 } else {
  $IDConversionTable = $IDConversionTable | select-object -ExcludeProperty ServicePrincipalName,ServicePrincipalID
 }

 $ServicePrincipalObjectWithGUIDPermissions | ForEach-Object {
  $CurrentPolicy = $_.PolicyID ;
  $CurrentRule = $_.RuleID  ;
  $Policy = $IDConversionTable | where-object {($_.PolicyID -eq $CurrentPolicy) -and ($_.RuleID -eq $CurrentRule)}
  # Some policies have multiple of the same set of PolicyID and RuleID .... If there are multiple result, will take the admin result or the first result
  if ($Policy.Count -gt 1) {
   Write-Host -Foregroundcolor "Magenta" "WARNING : PolicyID $CurrentPolicy with RuleID $CurrentRule contains multiple result"
   if ($Policy | Where-Object Type -eq "Admin") {$Policy = $Policy | Where-Object Type -eq "Admin" } else {$Policy = $Policy[0]}
  }
  [pscustomobject]@{
   ServicePrincipalName=$_.ServicePrincipalName
   ServicePrincipalID=$_.ServicePrincipalID
   PolicyName=$Policy.PolicyName
   PolicyID=$Policy.PolicyID
   Value=$Policy.Value
   ValueID=$Policy.RuleID
   PermissionType=$Policy.PermissionType
   Description=$Policy.Description
   # Type=$Policy.Type => This value is empty
  }
 }
}
Function Convert-KubectlTLSSecretToPSObject { #Convert TLS Secret (found with Kubectl) to a PS Object (Cert + Key)
 Param (
  [Parameter(Mandatory)]$SecretName,
  [Parameter(Mandatory)]$NameSpace
 )
 $SECRETCONTENT = kubectl get secrets $SecretName -n data -o json
 $TLSCERTB64 = (( $SECRETCONTENT | select-string tls.crt) -split("`""))[3]
 $TLSCERT = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($TLSCERTB64))
 $TLSKEYB64 = (( $SECRETCONTENT | select-string tls.key) -split("`""))[3]
 $TLSKEY = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($TLSKEYB64))
 $Secret=@()
 $Secret+=[pscustomobject]@{Cert=$TLSCERT;Key=$TLSKEY}
 $Secret
}
# User Rights Management
Function Get-AzureADRBACRights { # Get all RBAC Rights (Works with Users, Service Principals) - Does not yet work with groups - If no Subscription are defined then it will check all subscriptions
 [CmdletBinding(DefaultParameterSetName='ShowAll')]
 Param (
  [parameter(Mandatory = $true, ParameterSetName="UserAndSubID")]
  [parameter(Mandatory = $true, ParameterSetName="UserAndSubName")]
  [parameter(Mandatory = $true, ParameterSetName="UserPrincipalName")]$UserPrincipalName,
  [parameter(Mandatory = $true, ParameterSetName="DisplayAndSubID")]
  [parameter(Mandatory = $true, ParameterSetName="DisplayAndSubName")]
  [parameter(Mandatory = $true, ParameterSetName="UserDisplayName")]$UserDisplayName,
  [parameter(Mandatory = $true, ParameterSetName="UserAndSubID")]
  [parameter(Mandatory = $true, ParameterSetName="DisplayAndSubID")]
  [parameter(Mandatory = $true, ParameterSetName="GroupAndSubID")]
  [parameter(Mandatory = $true, ParameterSetName="SubscriptionID")]$SubscriptionID,
  [parameter(Mandatory = $true, ParameterSetName="UserAndSubName")]
  [parameter(Mandatory = $true, ParameterSetName="DisplayAndSubName")]
  [parameter(Mandatory = $true, ParameterSetName="GroupAndSubName")]
  [parameter(Mandatory = $true, ParameterSetName="SubscriptionName")]$SubscriptionName,
  [parameter(Mandatory = $true, ParameterSetName="GroupAndSubID")]
  [parameter(Mandatory = $true, ParameterSetName="GroupAndSubName")]
  [parameter(Mandatory = $true, ParameterSetName="GroupName")]$GroupName,
  [Switch]$Advanced, # Will add about 2 seconds per rights
  [Switch]$IncludeInherited,
  [Switch]$HideProgress,
  [Switch]$HideID,
  [Switch]$ShowCondition,
  [parameter(Mandatory = $false, ParameterSetName="ShowAll")][Switch]$ShowAll
 )

 # For the parameters, it's either Subscription Name OR Subscription ID - And - User Name or User DisplayName

 # Get Tenant ID
 $TenantID = az account show --query '"{tenantId:tenantId}"' -o tsv

 # Get all subscriptions information
 if (! $HideProgress ) { Progress -Message "Current step " -Value "Retreiving all subscriptions" -PrintTime }
 $AllSubscription = Get-AzureSubscriptions

 if ($Advanced) { # If it's requested to convert all display names it will add initial time to the request
  Progress -Message "Current step " -Value "Retrieving all Users (remove switch 'Advanced' to ignore this step)" -PrintTime
  $AllUsers = Get-AzureADUsers -Advanced
  Progress -Message "Current step " -Value "Retrieving all Service Principal (remove switch 'Advanced' to ignore this step)" -PrintTime
  $AllServicePrincipals = Get-AzureServicePrincipal -ValuesToShow "id,appId,displayName,servicePrincipalType"
 }

 # If Subscription name is given, find Subscription ID
 if ($SubscriptionName) {
  $SubscriptionID = ($AllSubscription | Where-Object Name -eq $SubscriptionName).ID
 }
 # If Subscription ID is given, find Subscription Name
 if ($SubscriptionID) {
  $SubscriptionName = ($AllSubscription | Where-Object id -eq $SubscriptionID).Name
 }

 if ( ($UserPrincipalName) -and (! $UserDisplayName ) ) {
  $UserDisplayName = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?`$count=true&`$select=displayName&`$filter=userPrincipalName eq '$UserPrincipalName'" --headers Content-Type=application/json | ConvertFrom-Json).Value.displayName
 }
 if ( ($UserDisplayName) -and (! $UserPrincipalName ) ) {
  $UserPrincipalName = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?`$count=true&`$select=userPrincipalName&`$filter=displayName eq '$UserDisplayName'" --headers Content-Type=application/json | ConvertFrom-Json).Value.userPrincipalName
 }
 if ($GroupName) {
  $UserPrincipalName = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/groups?`$count=true&`$select=id&`$filter=displayName eq '$GroupName'" --headers Content-Type=application/json | ConvertFrom-Json).value.id
 }

 # Set default arguments
 $Arguments =
  '--only-show-errors',
  '--all',
  '--include-groups',
  '--query' , '"[].{principalName:principalName, principalId:principalId, principalType:principalType, roleDefinitionName:roleDefinitionName, scope:scope, resourceGroup:resourceGroup, id:id}"',
  '--output', 'json'

 # Add Arguments if value is set
 if ( $UserPrincipalName ) {
  $Arguments += '--assignee' , $UserPrincipalName
 }

 if ( $IncludeInherited ) {
  $Arguments += '--include-inherited'
 }

 if ($ShowCondition) {
  $Arguments = $Arguments -replace ", id:id",", id:id, condition:condition"
 }

 if ( $SubscriptionID ) { # If Subscription ID is found filter on only found subscription, otherwise check all subscriptions
  $SubscriptionToCheck = $AllSubscription | where-object ID -eq $SubscriptionID
 } else {
  $SubscriptionToCheck = $AllSubscription
 }

 $GlobalStatus = @()
 $SubscriptionToCheck | ForEach-Object {

  $CurrentSubscriptionName = $_.Name
  $CurrentSubscriptionID = $_.ID

  $ArgumentsOfCurrentSubscription = $Arguments
  $ArgumentsOfCurrentSubscription += '--subscription' , $CurrentSubscriptionID

  if (! $HideProgress ) {
   Progress -Message "Checking subscription : " -Value $CurrentSubscriptionName -PrintTime
  }

  $CurrentSubscription = az role assignment list @ArgumentsOfCurrentSubscription | ConvertFrom-Json | `
  Select-object `
   @{Name="PrincipalName";Expression={ if (! $_.principalName) { "Identity not found" } else { $_.principalName } }},
   # @{Name="UserUPN";Expression={ if ($UserPrincipalName) { $UserPrincipalName } else { "Only used when filtering by user" } }},
   @{Name="DisplayName";Expression={
    if ($UserDisplayName) {
     $UserDisplayName
    } else {
     if ($Advanced) {
      if ($_.principalType -eq "ServicePrincipal") {
       ($AllServicePrincipals | Where-Object Id -eq $_.principalId).displayName
      } elseif ($_.principalType -eq "Group") {
       $_.PrincipalName
      } else {
       ($AllUsers | Where-Object userPrincipalName -eq $_.principalName).displayName
      }
     } elseif ($_.principalType -eq "Group") {
      "Group"
       # Add here to get info on groups (for example to do a recursive search of users)
     } else {
      "Use Advanced switch"
     }
    }
   }},
   @{Name="UserMail";Expression={
    if ($Advanced) {
     if ($_.principalType -eq "User") { ($AllUsers | Where-Object userPrincipalName -eq $_.principalName).mail } else { "N/A" }
    } else {
     "Use Advanced switch"
    }
   }},
   @{Name="Type";Expression={
    if ($Advanced -and ($_.principalType -eq "ServicePrincipal")) {
     $SPType = ($AllServicePrincipals | Where-Object AppID -eq $_.principalName).servicePrincipalType
     if (! $_.principalName) {return "Unknown"} elseif ($SPType) {Return $SPType} else {return "ServicePrincipal"}
    } else {
     # Use "-Advanced" for more info on Service Principals
     $_.principalType
    }
   }}, roleDefinitionName,
   @{Name="Subscription";Expression={
    $Scope_Split = $_.scope.split("/")
    if ($Scope_Split[-2] -eq "managementGroups") { # Replace Subscription With Management Group or tenant if permission are inherited
     if ($($Scope_Split[-1]) -eq $TenantID) {"Tenant"} else {$Scope_Split[-1]}
    } else {
     $CurrentSubscriptionName
    }
   }},
   resourceGroup,
   @{Name="ResourceName";Expression={
    $Scope_Split = $_.scope.split("/")[-1]
    if ($Scope_Split -eq $CurrentSubscriptionID ) {
     "Subscription"
    } elseif ($Scope_Split -eq $TenantID) {
     "Tenant"
    } elseif ($Scope_Split -eq $_.resourceGroup) {
     "ResourceGroup"
    } else {
     $Scope_Split
    }
   }},
   @{Name="ResourceType";Expression={ $_.scope.split("/")[-2] }},
   @{Name="principalId";Expression={ $_.principalId }},
   @{Name="SubscriptionID";Expression={$CurrentSubscriptionID}}, scope,
   @{Name="AssignmentID";Expression={$_.ID}}, condition # Can be used to remove permissions with az role assignment delete --ids
  $GlobalStatus += $CurrentSubscription
 }
 #Print result
 if (! $HideProgress ) { ProgressClear }
 # $GlobalStatus | Sort-Object -Unique id
 if ($HideID) { $GlobalStatus = $GlobalStatus | Select-Object -ExcludeProperty "*ID" }
 if (! $Advanced) { $GlobalStatus = $GlobalStatus | Select-Object -ExcludeProperty "UserMail" }
 $GlobalStatus
}
Function Get-AzureRBACRightsREST { # In progress to get permissions via Graph only request - Gets all permissions set on a Subscription or Resource Group
 [CmdletBinding(DefaultParameterSetName = 'ManagementGroupScope')]
 Param (
  # == Parameters available in ALL sets ==
  [parameter(Mandatory = $true)]
  $AzureToken,

  [parameter(Mandatory = $true)]
  $UserToken,

  [string]$APIVersion = "2022-04-01",

  [string]$APIVersionEligible = "2020-10-01",

  [Switch]$HideGUID,

  # == SCOPE PARAMETERS (Mutually Exclusive Sets) ==

  # Set 1: Management Group Scope
  [parameter(Mandatory = $true, ParameterSetName = 'ManagementGroupScope')]
  [string]$ManagementGroupID,

  # Set 2: Subscription Scope (also used by other sets)
  [parameter(Mandatory = $true, ParameterSetName = 'SubscriptionScope')]
  [parameter(Mandatory = $true, ParameterSetName = 'ResourceGroupScope')]
  [parameter(Mandatory = $true, ParameterSetName = 'ResourceScope')]
  [string]$Subscription,

  # Set 3: Resource Group Scope (also used by Resource set)
  [parameter(Mandatory = $true, ParameterSetName = 'ResourceGroupScope')]
  [parameter(Mandatory = $true, ParameterSetName = 'ResourceScope')]
  [string]$ResourceGroup,

  # Set 4: Resource Scope
  [parameter(Mandatory = $true, ParameterSetName = 'ResourceScope')]
  [string]$Resource
 )

 # You can check which parameter set was used inside your script
 Write-Host "Parameter Set Used: $($PSCmdlet.ParameterSetName)"


 $BaseURL = "https://management.azure.com"

 # Get Data from Rest
 if ($ResourceGroup) {
  $RequestURL = "/subscriptions/$Subscription/resourceGroups/$ResourceGroup"
 } elseif ($ManagementGroupID) {
  $RequestURL = "/providers/Microsoft.Management/managementGroups/$ManagementGroupID"
 } else {
  $RequestURL = "/subscriptions/$Subscription"
 }

 # Launch Graph Requests
 $PermanentRequestResultWithGUIDS = (Get-AzureGraph -Token $AzureToken -BaseURL $BaseURL -GraphRequest "$RequestURL/providers/Microsoft.Authorization/roleAssignments?api-version=$APIVersion").value.properties
 if ($PermanentRequestResultWithGUIDS) { $PermanentRequestResultWithGUIDS | Add-Member -MemberType NoteProperty -Name AssignementType -Value Permanent }
 $EligibleRequestResultWithGUIDS = (Get-AzureGraph -Token $AzureToken -BaseURL $BaseURL -GraphRequest "$RequestURL/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=$APIVersionEligible").value.properties
 if ($EligibleRequestResultWithGUIDS) { $EligibleRequestResultWithGUIDS | Add-Member -MemberType NoteProperty -Name AssignementType -Value Eligible }
 $RequestResultWithGUIDS = $PermanentRequestResultWithGUIDS + $EligibleRequestResultWithGUIDS

 # Convert Data
 write-verbose "Getting Role Definition Information"
 $RolesConvertedTable = $RequestResultWithGUIDS | Select-Object roleDefinitionId -Unique | ForEach-Object { Get-AzureGraph -Token $AzureToken -BaseURL $BaseURL -GraphRequest "$($_.roleDefinitionId)/?api-version=$APIVersion" }
 $RolesConvertedTableHash = @{} ; $RolesConvertedTable | ForEach-Object { $RolesConvertedTableHash[$_.ID] = $_ }

 write-verbose "Getting User Information"
 $PrincipalConvertedTable = $RequestResultWithGUIDS | Select-Object principalId -Unique | ForEach-Object { Get-AzureADObjectInfo -ObjectID $_.principalId -Token $UserToken }
 $PrincipalConvertedTableHash = @{} ; $PrincipalConvertedTable | ForEach-Object { $PrincipalConvertedTableHash[$_.ID] = $_ }

 $RequestResult = $RequestResultWithGUIDS | Select-Object *,
  @{name="roleDefinitionObjectInfo";expression={($RolesConvertedTableHash[$_.roleDefinitionId]).properties}},
  @{name="principalObjectInfo";expression={($PrincipalConvertedTableHash[$_.principalId])}} | Select-Object -ExcludeProperty roleDefinitionObjectInfo,principalObjectInfo *,
    @{name="principalName";expression={$_.principalObjectInfo.DisplayName}},
    @{name="roleDefinitionName";expression={$_.roleDefinitionObjectInfo.roleName}},
    @{name="roleDefinitionType";expression={$_.roleDefinitionObjectInfo.type}}

 if ($HideGUID) {
  $RequestResult | Select-Object -ExcludeProperty *Id,*On,*By
 } else {
  $RequestResult
 }
}
Function Remove-AzureADUserRBACRightsALL { # Remove all User RBAC Rights on one Subscriptions (Works with Users and Service Principals)
 Param (
  [Parameter(Mandatory=$true)]$UserPrincipalName
 )
 $CurrentRights = Get-AzureADRBACRights -UserPrincipalName $UserPrincipalName
 $CurrentRights | Where-Object Type -eq User | ForEach-Object {
  Progress -Message "Removing permission " -Value "$($_.roleDefinitionName) from user $($UserPrincipalName) from scope $($_.scope)"
  Remove-AzureADRBACRights -AssignmentID $_.AssignmentID
 }
 $CurrentRights | Where-Object Type -ne User | ForEach-Object { "User $($UserPrincipalName) has permission to Scope $($_.scope) because of the Principal $($_.PrincipalName)" }
}
Function Add-AzureADGroupRBACRights { # Add RBAC Rights (Subscription is mandatory - at least name) | Not yet fully tested but works on Subscription
 [CmdletBinding(DefaultParameterSetName='ScopeID')]
 Param (
  [Parameter(Mandatory=$true)]$ObjectID, # Object ID of element that will have the permissions
  [Parameter(Mandatory=$true)]$Role, # Name of the permission to add
  [Parameter(Mandatory=$true, ParameterSetName = 'SubscriptionID')]$SubscriptionID,
  [Parameter(Mandatory=$true, ParameterSetName = 'SubscriptionName')]$SubscriptionName,
  [Parameter(Mandatory=$false, ParameterSetName = 'SubscriptionID')]
  [Parameter(Mandatory=$false, ParameterSetName = 'SubscriptionName')]
  [Parameter(Mandatory=$false, ParameterSetName = 'ResourceRG')]$ResourceGroup,
  [Parameter(Mandatory=$false, ParameterSetName = 'SubscriptionID')]
  [Parameter(Mandatory=$false, ParameterSetName = 'SubscriptionName')]
  [Parameter(Mandatory=$false, ParameterSetName = 'Resource')]$Resource,
  [Parameter(Mandatory=$False, ParameterSetName = "ScopeID")]$ScopeID
 )
 if (! $SubscriptionID) {
  Progress -Message "Current step " -Value "Retreiving all subscriptions" -PrintTime
  $SubscriptionID = (Get-AzureSubscriptions | Where-Object Name -eq $SubscriptionName).ID
 }

 az account set --subscription $subscriptionId

 if ($Resource) {
  $ScopeID = ((az resource list --output json).tolower() | convertfrom-json | Where-Object name -eq $Resource).ID
 } elseif ($ResourceGroup) {
  $ScopeID = (az group show --resource-group $ResourceGroup | ConvertFrom-Json).ID
 } else {
  $ScopeID = "/subscriptions/$SubscriptionID"
 }
 $ResultJson = az role assignment create --assignee $ObjectID --role $Role --scope $ScopeID 2>&1
 $ErrorMessage = $ResultJson | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
 $Result = $ResultJson | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ConvertFrom-Json
 if ($ErrorMessage) {
  write-host -ForegroundColor "Red" -Object "Error adding permission for ObjectID $ObjectID [$ErrorMessage]"
 } else {
  $principalId = $Result.principalId
  $principalType = $Result.principalType
  $scope = $Result.scope
  $roleDefinitionName = $Result.roleDefinitionName
  write-host -ForegroundColor "Green" -Object "Successfully added $roleDefinitionName permission for $principalId [$principalType] on scope $scope"
 }
}
Function Add-AzureADRBACRights { # Add rights to a resource using UserName or Object ID (for types other than users) - Requires Exact Scope
 Param (
  [parameter(Mandatory = $true, ParameterSetName="UserName")]$UserName,
  [parameter(Mandatory = $true, ParameterSetName="ID")][GUID]$Id,
  [parameter(Mandatory = $true, ParameterSetName="ID")][ValidateSet("Group","ServicePrincipal","User","ForeignGroup")]$ID_Type,
  [Parameter(Mandatory=$true)]$Role,
  [Parameter(Mandatory=$true)]$Scope
 )
 if ($ID) {
  az role assignment create --assignee-object-id $ID --role $Role --scope $Scope --assignee-principal-type $ID_Type
 } else {
  az role assignment create --assignee $UserName --role $Role --scope $Scope
 }
}
Function Remove-AzureADRBACRights { # Remove rights to a resource using UserName or Object ID (for types other than users) - Requires Exact Scope
 Param (
  [parameter(Mandatory = $true, ParameterSetName="UserRoleScope")]$UserName,
  [parameter(Mandatory = $true, ParameterSetName="UserRoleScope")]$Role,
  [parameter(Mandatory = $true, ParameterSetName="UserRoleScope")]$Scope,
  [parameter(Mandatory = $true, ParameterSetName="ID")]$AssignmentID,
  [switch]$ShowProgress
 )
  if ($ShowProgress) {Progress -Message "Removing permission from " -Value $AssignmentID}
  if (! $AssignmentID) {
   az role assignment delete --assignee $UserName --role $Role --scope $Scope
  } else {
   az role assignment delete --ids $AssignmentID
  }
}
# App Registration / Service Principal creation
Function Remove-AppRegistrationOAuth2Permissions { # Remove Oauth2 Permissions from App Registration
 Param (
  [Parameter(Mandatory=$true)]$AppID,
  $TempFile = "$($env:TEMP)\Oauth2Permission.json"
 )
  #Generate a Json file containing the current permission, to be able to disable it (can't remove before disabling)

  #Step 1 : Get current permission in PS Object
  $CurrentOAuthPerm = (az ad app show --id $AppID --only-show-errors -o json | ConvertFrom-Json).oauth2Permissions

  if ($CurrentOAuthPerm) {
   #Step 2 : Disable Permission in PS Object
   $CurrentOAuthPerm[0].isEnabled = "False"
   #Step 3 : Convert back to Json and send to file
   ConvertTo-Json -InputObject @($CurrentOAuthPerm) | Out-File -FilePath $TempFile

   #Set the permission to the defined disabled permissions
   az ad app update --only-show-errors --id $AppID --set oauth2Permissions=$TempFile

   #Remove permissions
   az ad app update --only-show-errors --id $appId --set oauth2Permissions='[]'

   #Cleanup
   Remove-Item $TempFile
   Write-Host -ForegroundColor Magenta "OAuth2Permissions remove from App Registration $AppID"
  } else {
   Write-Host -ForegroundColor Green "No OAuth2Permissions found on App Registration $AppID"
  }
}
Function New-AzureAppRegistrationBlank { # Create a single App Registration completely blank (No rights) - Can associate/create a SP for RBAC rights
 Param (
  [Parameter(Mandatory=$true)]$AppRegistrationName,
  [Switch]$CreateAssociatedServicePrincipal
 )
 Try {
  $AppID = (Get-AzureAppRegistration -DisplayName $AppRegistrationName).AppID
  if ($AppID) {
   Write-Host -ForegroundColor Green "App Registration with name `"$AppRegistrationName`" already exists with ID : $AppID"
  } else {
   #Create App Registration
   $AppReg = az ad app create --only-show-errors --display-name $AppRegistrationName --sign-in-audience 'AzureADMyOrg'
   #Get App Registration ID
   $AppID = ($AppReg |ConvertFrom-json).AppID
   #Remove default Oauth2 Permissions if any
   Remove-AppRegistrationOAuth2Permissions -AppID $AppID
   #Print Result
   Write-Host -ForegroundColor Green "Created clean AppRegistration `"$AppRegistrationName`" with ID : $AppID"
  }
 } Catch {
  Write-Host -ForegroundColor Red "Error creating App Registration $AppRegistrationName : $($Error[0])"
 }
 Try {
  if ($CreateAssociatedServicePrincipal) {
   Write-Host -ForegroundColor Green "Creating associated Service Principal for `"$AppRegistrationName`" with ID : $AppID"
   $ServicePrincipalCreation = az ad sp create --id $AppID --only-show-errors
   Write-Host -ForegroundColor Green "Created associated Service Principal with Object ID $(($ServicePrincipalCreation | ConvertFrom-JSON).ID)"
  }
 } Catch {
  Write-Host -ForegroundColor Red "Error creating Associated Service Principal $AppRegistrationName : $($Error[0])"
 }
 return $AppID
}
Function New-AzureServicePrincipal { # Create an Enterprise App linked to existing App Registration
 Param (
  [Parameter(Mandatory=$true)]$AppRegistrationName
 )
 New-AzureAppRegistrationBlank -CreateAssociatedServicePrincipal -AppRegistrationName $AppRegistrationName
}
Function New-AzureAppSP_NONSSO { # Create App Registration with all required info : Associated SP, Permission, Owners etc. (Check function for more info)
 Param (
  [Parameter(Mandatory=$true)]$ObjectsToCreate
 )

 #Object Example
 # $SP_ToCreate = @()
 # $SP_ToCreate += [pscustomobject]@{
 #  Name="App_Name";
 #  CreateServicePrincipal=$True;
 #  AppRegistrationOwner=$True;
 #  ServicePrincipalOwner=$True;
 #  BackendAPI_ID=""; # Object ID of the Enterprise App containing the Rights to Add (seen in the App Roles of the App Reg)
 #  RightsToAdd=""; # Name of Right to add [AppRole] : User.Read for example
 #  OwnersID="" # List of Owner object IDs
 # }

 $ObjectsToCreate | ForEach-Object {
  $AppRegistrationName = $_.Name
  if ($_.CreateServicePrincipal) {
   $App_AppID = New-AzureAppRegistrationBlank -AppRegistrationName $AppRegistrationName -CreateAssociatedServicePrincipal
   $SP_AppID = (Get-AzureServicePrincipalInfo -DisplayName $AppRegistrationName).ID
  } else {
   $App_AppID = New-AzureAppRegistrationBlank -AppRegistrationName $AppRegistrationName
  }
  $AppRegistrationOwner = $_.AppRegistrationOwner
  $ServicePrincipalOwner = $_.ServicePrincipalOwner
  $BackendAPI_ID = $_.BackendAPI_ID
  # Owner Management
  $_.OwnersID | ForEach-Object {
   if ($AppRegistrationOwner) {
    Add-AzureAppRegistrationOwner -OwnerObjectID $_ -AppRegistrationID $App_AppID
   }
   if ($SP_AppID -and $ServicePrincipalOwner) {
    Add-AzureServicePrincipalOwner -OwnerObjectID $_ -ServicePrincipalID $SP_AppID
   }
  }
  # Permission Management
  $_.RightsToAdd | ForEach-Object {
   if (! $BackendAPI_ID) {Return}
   Add-AzureAppRegistrationPermission -AppID $App_AppID -ServicePrincipalID $BackendAPI_ID -RightName $_
   Progress -Message "Check API Permissions on " -Value $App_AppID -PrintTime
  }

  Progress -Message "Waiting 30 Seconds after commit to be able to Grant Admin Consent on " -Value $App_AppID -PrintTime
  Start-Sleep -Seconds 30

  # Grant Admin Consent
  Progress -Message "Grant API Permissions on $App_AppID : " -Value $RightName -PrintTime
  az ad app permission admin-consent --id $App_AppID

  #Check Rights :
  Get-AzureAppRegistrationPermissions -AppRegistrationID $App_AppID -Readable
 }
}
# App Registration [Only]
Function Get-AzureAppRegistration { # Find App Registration Info using REST | Using AZ AD Cmdlet are 5 times slower than Az Rest | Usefull to Find 'App Roles' : (Get-AzureAppRegistration -AppID $AppID).appRoles | select id,value
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppID")][String]$AppID,
  [parameter(Mandatory=$true,ParameterSetName="ID")][String]$ID,
  [parameter(Mandatory=$true,ParameterSetName="NAME")][String]$DisplayName,
  [Switch]$ShowOwner,
  $ValuesToShow = "createdDateTime,displayName,appId,id,description,notes,tags,signInAudience,appRoles,defaultRedirectUri,identifierUris,optionalClaims,publisherDomain,implicitGrantSettings,spa,web,publicClient,isFallbackPublicClient",
  $Token
 )
 if ($AppID) {             $FilterValue = 'AppID'       ; $ValueToCheck = $AppID
 } elseif ($ID) {          $FilterValue = 'ID'          ; $ValueToCheck = $ID
 } elseif ($DisplayName) { $FilterValue = 'DisplayName' ; $ValueToCheck = $DisplayName
 }
 $GraphURI = "https://graph.microsoft.com/v1.0/applications?`$count=true&`$select=$ValuesToShow&`$filter=$FilterValue eq '$ValueToCheck'"
 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
  $headers = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
  (Invoke-RestMethod -Method GET -headers $headers -Uri $GraphURI).value
 } else {
  (az rest --method GET --uri $GraphURI --headers Content-Type=application/json | ConvertFrom-Json).value
 }
}
Function Get-AzureAppRegistrationFromAppID { # Get the App Registration information from AppID | Uses Token
 Param (
  [Parameter(Mandatory)]$AppID,
  $Value = "displayName", # or UserPrincipalName
  [Parameter(Mandatory)]$Token
 )
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
 $headers = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }
 $Result = (Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/applications?`$count=true&`$select=$Value&`$filter=AppID eq '$AppID'").Value.$Value
 if ($Result) {
  $Result
 } else {
  "$AppID ($Value not found)"
 }
}
Function Get-AzureAppRegistrations { # Get all App Registration of a Tenant # SPA = SinglePage Authentication ; WEB = Web ; Public Client =  Client
 Param (
  [Switch]$ShowAllColumns,
  [Switch]$ShowOwners,
  [Switch]$Fast,
  $NameFilter,
  $URLFilter,
  [switch]$Verbose,
  $Token
 )

 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
  $headers = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
 }

 $FastColumns = "DisplayName,appId,id"
 $DefaultColumns = "DisplayName,AppID,id,appRoles,createdDateTime,defaultRedirectUri,groupMembershipClaims,identifierUris,keyCredentials,
  passwordCredentials,publisherDomain,signInAudience,tags,publicClient,spa,web"
 if ($Fast) {
  $Columns = $FastColumns
 } else {
  $Columns = $DefaultColumns
 }

 if ($token) {
  $CmdLine = "https://graph.microsoft.com/beta/applications?`$top=999"
  if (! $ShowAllColumns) { $CmdLine += "&`$select=$Columns" }
 } else {
  $CmdLine = '"https://graph.microsoft.com/beta/applications?$top=999'
  if ($ShowAllColumns) { $CmdLine += "`"" } else { $CmdLine += '&$select='+$Columns+'"' }
 }

 $Count=0
 $GlobalResult = @()
 $ContinueRunning = $True
 $FirstRun=$True
 While ($ContinueRunning -eq $True) {
  if ($Verbose) { Progress -Message "Getting all Application Loop (Sleep $SleepDurationInS`s | Current Count $($GlobalResult.Count)) : " -Value $Count -PrintTime }
  if ($FirstRun) {
   if ($token) {
    $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri $CmdLine
    $NextRequest = $CurrentResult.'@odata.nextLink'
   } else {
    $CurrentResult = az rest --method get --uri $CmdLine --header Content-Type="application/json" -o json | convertfrom-json
    $NextRequest = "`""+$CurrentResult.'@odata.nextLink'+"`""
   }
   $FirstRun=$False
  } else {
   if ($Token) {
    $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri $NextRequest
    $NextRequest = $CurrentResult.'@odata.nextLink'
   } else {
    $ResultJson = az rest --method get --uri $NextRequest --header Content-Type="application/json" -o json 2>&1
    $ErrorMessage = $ResultJson | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
    If (($ErrorMessage -and ($ErrorMessage -notlike "*Unable to encode the output with cp1252 encoding*"))) {
     Write-Host -ForegroundColor "Red" -Object "Detected Error ($ErrorMessage) ; Restart Current Loop after a 5s sleep"
     Start-Sleep 5
     Continue
    }
    $CurrentResult = $ResultJson | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | convertfrom-json
    $NextRequest = "`""+$CurrentResult.'@odata.nextLink'+"`""
   }
  }
  $Count++
  if ($CurrentResult.'@odata.nextLink') {$ContinueRunning = $True} else {$ContinueRunning = $False}
  $GlobalResult += $CurrentResult.Value
 }

 $Result = $GlobalResult | Sort-Object displayName | Select-Object *,@{Name="URLs";Expression={($_.publicClient.redirectUris -join ",") + ($_.sap.redirectUris -join ",") + ($_.web.redirectUris -join ",")}}

 # Convert Tag to proper format :
 $Result = $Result | Select-Object -ExcludeProperty Tags *,@{Name="Tags";Expression={
  $TagList = [PSCustomObject]@{}
  $_.Tags | ForEach-Object {
    $TagList | Add-Member -MemberType NoteProperty -Name ($_ -split ":")[0] -Value ($_ -split ":")[1]
   }
   $TagList
 }}

 if ($URLFilter -and (! $Fast)) { $Result = $Result | Where-Object URLs -like "*$URLFilter*" }
 if ($NameFilter) { $Result = $Result | Where-Object displayName -like "*$NameFilter*" }
 if ($ShowOwners) { $Result = $Result | Select-Object *,@{Name="Owner";Expression={
  Progress -Message "Check Owner of App : " -Value $_.DisplayName -PrintTime ; Get-AzureAppRegistrationOwner -AppRegistrationObjectID $_.ID }}
 }
 if ($Verbose) { ProgressClear }
 $Result
}
Function Get-AzureAppRegistrationOwner { # Get owner(s) of an App Registration
 Param (
  [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationID,
  [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationObjectID,
  [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationName,
  [switch]$SearchAppInfo,
  $Token
 )
 if ($AppRegistrationID -and (! $AppRegistrationObjectID)) {
  $AppInfo = Get-AzureAppRegistration -AppID $AppRegistrationID
 }
 if ($AppRegistrationName -and (! $AppRegistrationObjectID)) {
  $AppInfo = Get-AzureAppRegistration -DisplayName $AppRegistrationName
 }

 if ((! $AppInfo.ID) -and (! $AppRegistrationObjectID)) {
  Write-host -ForegroundColor Red -Object "Application not found with AppID : $AppRegistrationID, Object ID : $AppRegistrationObjectID and AppName : $AppRegistrationName"
  return
 }

 if (! $AppRegistrationObjectID) {
  $AppRegistrationObjectID = $AppInfo.ID
 }

 if (($SearchAppInfo -and (! $AppInfo)) -and ((! $AppRegistrationID) -or (! $AppRegistrationName)) ) {
  $AppInfo = Get-AzureAppRegistration -ID $AppRegistrationObjectID
 }

 if (! $AppRegistrationID) { $AppRegistrationID = $AppInfo.appId}
 if (! $AppRegistrationName) { $AppRegistrationName = $AppInfo.displayName}

 if ($Token) {
  $Result = (Get-AzureGraph -Token $Token -GraphRequest /applications/$AppRegistrationObjectID/owners).value
 } else {
  $Result = (az rest --method get --uri https://graph.microsoft.com/beta/applications/$AppRegistrationObjectID/owners | convertfrom-json).value
  # az ad app owner list --id $AppRegistrationID -o json --only-show-errors | ConvertFrom-Json | Select-Object @{Name="AppID";Expression={$AppRegistrationID}},ID,userPrincipalName,displayName
 }
 $Result | Select-Object @{Name="AppObjectID";Expression={$AppRegistrationObjectID}},
 @{Name="AppID";Expression={$AppRegistrationID}},
 @{Name="AppName";Expression={$AppRegistrationName}},id,userPrincipalName,displayName
}
Function Get-AzureAppRegistrationOwnerForAllApps { # Get Owner(s) of all App Registration
 Param (
  $Token
 )
 Get-AzureAppRegistrations -Fast | ForEach-Object {
  Progress -Message "Checking current App : " -Value $_.DisplayName
  if ($Token) {
   Get-AzureAppRegistrationOwner -AppRegistrationID $_.AppID -AppRegistrationObjectID $_.id -AppRegistrationName $_.DisplayName -Token $Token
  } else {
   Get-AzureAppRegistrationOwner -AppRegistrationID $_.AppID -AppRegistrationObjectID $_.id -AppRegistrationName $_.DisplayName
  }
 } | Export-Csv "$iClic_TempPath\AzureAppRegistrationOwnerForAllApps_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 ProgressClear
}
Function Add-AzureAppRegistrationOwner { # Add an owner to an App Registration
 Param (
  [parameter(Mandatory=$true,ParameterSetName="UPN")][String]$OwnerUPN,
  [parameter(Mandatory=$true,ParameterSetName="ObjectID")][String]$OwnerObjectID,
  [Parameter(Mandatory=$true,ParameterSetName='UPN')]
  [Parameter(Mandatory=$true,ParameterSetName='ObjectID')]$AppRegistrationID  #Owner or App Registration ID is required, both param cannot be set, UPN will be slower
 )
 if ($OwnerUPN) { $UserObjectID = (Get-AzureADUserInfo $OwnerUPN).ID } else { $UserObjectID = $OwnerObjectID }
 Write-Host -ForegroundColor "Cyan" "Adding owner for user $UserObjectID on App Registration $AppRegistrationID"
 Try {
  az ad app owner add --id $AppRegistrationID --owner-object-id $UserObjectID --only-show-errors
 } Catch {
  Write-Host -ForegroundColor "Red" "Error adding owner for user $OwnerUPN on AppID $AppRegistrationID : $($Error[0])"
 }
}
Function Remove-AzureAppRegistrationOwner { # remove an owner to an App Registration
 Param (
  [Parameter(Mandatory=$true)]$OwnerUPN,
  [Parameter(Mandatory=$true)]$AppRegistrationID
 )
 $Verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
 Try {
  $UserObjectID = (Get-AzureADUserInfo $OwnerUPN).ID
  if ($Verbose) {
   Write-Host -ForegroundColor "Cyan" "Removing user $OwnerUPN as owner of AppID $AppRegistrationID"
  }
  az ad app owner remove --id $AppRegistrationID --owner-object-id $UserObjectID --only-show-errors
  if ($Verbose) {
   Write-Host -ForegroundColor "Green" "Removed user $OwnerUPN as owner of AppID $AppRegistrationID"
  }
 } Catch {
  Write-Host -ForegroundColor "Red" "Error adding owner for user $OwnerUPN on AppID $AppRegistrationID : $($Error[0])"
 }
}
Function Remove-AzureAppRegistrationOwners { # remove all owner to an App Registration
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppID")]$AppRegistrationID,
  [parameter(Mandatory=$true,ParameterSetName="ObjectID")]$AppRegistrationObjectID,
  [parameter(Mandatory=$true,ParameterSetName="Name")]$AppRegistrationName
 )

 if ($AppRegistrationID) { $AppRegistrationObjectID = (Get-AzureAppRegistration -AppID $AppRegistrationID).ID }
 if ($AppRegistrationName) { $AppRegistrationObjectID = (Get-AzureAppRegistration -DisplayName $AppRegistrationName).ID }

 Get-AzureAppRegistrationOwner -AppRegistrationObjectID $AppRegistrationObjectID | ForEach-Object {
  Write-Host "Removing Owners from App Registration $AppRegistrationObjectID : $($_.displayName)"
  az ad app owner remove --id $AppRegistrationObjectID --owner-object-id $_.id
 }
}
Function Get-AzureAppRegistrationRBACRights { # Get ALL App Registration RBAC Rights of ONE or Multiple Subscriptions
 Param (
  [Parameter(Mandatory)]$AppRegistration, # Must be an object containing ID and Name of App Registration
  [Parameter(Mandatory)]$Subscription # Must be an object containing  ID and Name of subscription
 )
 $Subscription | ForEach-Object {
  $CurrentSubscriptionID = $_.id
  $CurrentSubscriptionName = $_.name
  $AppRegistration | ForEach-Object {
   Progress -Message "Currently checking App Registration " -Value "`'$($_.appDisplayName)`' on subscription `'$CurrentSubscriptionName`'" -PrintTime
   Get-AzureADRBACRights -SubscriptionID $CurrentSubscriptionID -SubscriptionName $CurrentSubscriptionName -UserPrincipalName $_.appId -UserDisplayName $_.appDisplayName
  }
 }
}
Function Get-AzureAppRegistrationRBAC { # Get Single App Registration RBAC Rights on a single App Registration
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppID")]$AppRegistrationID,
  [parameter(Mandatory=$true,ParameterSetName="Name")]$AppRegistrationName,
  [parameter(Mandatory=$true)]$SubscriptionName
 )
 if ($AppRegistrationName) { $AppRegistrationID = (Get-AzureAppRegistration -DisplayName $AppRegistrationName).AppID }

 Get-AzureADRBACRights -UserPrincipalName $AppRegistrationID -SubscriptionName $SubscriptionName -IncludeInherited -HideProgress | Select-Object `
  @{Name="PrincipalName";Expression={
   if (Assert-IsGUID $_.PrincipalName) {
    (Get-AzureServicePrincipalInfo -AppID $_.PrincipalName).DisplayName
   } else {
    $_.PrincipalName
   }
  }},Type,roleDefinitionName,Subscription,resourceGroup,ResourceName,ResourceType
}
Function Get-AzureAppRegistrationPermissions { # Retrieves all permissions of App Registration with GUID Only (faster) | Uses AzCli or Token
 Param (
  [parameter(Mandatory=$True,ParameterSetName="AppID")]$AppRegistrationID,
  [parameter(Mandatory=$True,ParameterSetName="AppName")]$AppRegistrationName,
  [switch]$Readable,
  [switch]$HideGUID,
  $Token
 )

 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { write-error "Token is invalid, provide a valid token" ; Return }
  $headers = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
  if ($AppRegistrationName) {
   $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$AppRegistrationName'&`$select=id,appId,displayName,requiredResourceAccess" | Select-Object * -ExpandProperty value -ExcludeProperty Value
  } else {
   $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/applications(appId='$AppRegistrationID')?`$select=id,appId,displayName,requiredResourceAccess"
  }
  $AppRegistrationName = $CurrentResult.displayName
  $AppRegistrationID = $CurrentResult.appId
  $PermissionListJson = $CurrentResult.requiredResourceAccess
 } else {
  if (!$AppRegistrationName) {$AppRegistrationName = (Get-AzureAppRegistration -AppID $AppRegistrationID).displayName}
  if (!$AppRegistrationID) {$AppRegistrationID = (Get-AzureAppRegistration -DisplayName $AppRegistrationName).AppID}
  $PermissionListJson = az ad app permission list --id $AppRegistrationID --only-show-errors -o json | convertfrom-json
 }

 $Result = $PermissionListJson | Select-Object @{name="Rules";expression={
   $Rules_List=@()
   $PolicyID = $_.resourceAppId
   # $PolicyExpiration = $_.expiryTime
   $_.resourceAccess | ForEach-Object {
    $Rules_List+=[pscustomobject]@{
     AppRegistrationName=$AppRegistrationName;
     AppRegistrationID=$AppRegistrationID;
     PolicyID=$PolicyID;
     RuleID=$_.ID;
     RuleType=$_.Type}
   }
   $Rules_List
  }
 }
 If ($Readable -and $Result.Rules) {
  if ($Token) {
   $ReadablePermissionList = Convert-AzureAppRegistrationPermissionsGUIDToReadable -AppRegistrationObjectWithGUIDPermissions $Result.rules -Token $Token
  } else {
   $ReadablePermissionList = Convert-AzureAppRegistrationPermissionsGUIDToReadable -AppRegistrationObjectWithGUIDPermissions $Result.rules
  }
  if ($HideGUID) {
   $ReadablePermissionList | Select-Object -ExcludeProperty *ID
  } else {
   $ReadablePermissionList
  }
 } else {
  $Result.Rules
 }
}
Function Get-AzureAppRegistrationAPIPermissions { # Check Permission for All App Registration of a Tenant | Uses Get-AzureAppRegistrationPermissions
 Param (
  $ExportFile = "$iClic_TempPath\AppRegistrationPermissionsGUIDOnly_$([DateTime]::Now.ToString("yyyyMMdd")).csv",
  $FinalFile = "$iClic_TempPath\AppRegistrationPermissions_$([DateTime]::Now.ToString("yyyyMMdd")).csv",
  $LogFile = "$iClic_TempPath\AppRegistrationPermissions_$([DateTime]::Now.ToString("yyyyMMdd")).log",
  [Switch]$Verbose,
  $Token
 )

 #Extract all App Registration Permission with only GUID (Faster)
 Write-Colored -FilePath $LogFile -PrintDate -NonColoredText "| Step 1 | " -ColoredText "Retrieving App Registrations"
 if ($Token) {
  $AppRegistrationList = Get-AzureAppRegistrations -Token $Token
 } else {
  $AppRegistrationList = Get-AzureAppRegistrations
 }

 Write-Colored -FilePath $LogFile -PrintDate -NonColoredText "| Step 2 | " -ColoredText "Found $($AppRegistrationList.Count) App Registrations"

 Write-Colored -FilePath $LogFile -PrintDate -NonColoredText "| Step 3 | " -ColoredText "Retrieving App Registration Permission with GUID Only (Will take about 2 seconds per app Registration) : File used : $ExportFile"
 $AppRegistrationListCount = 0
 $AppRegistrationList | Sort-Object DisplayName | ForEach-Object {
  $AppRegistrationListCount++
  Write-Colored -Color "Cyan" -FilePath $LogFile -NonColoredText "Checking App Registration $AppRegistrationListCount/$($AppRegistrationList.count) : " -ColoredText $_.DisplayName
  Try {
   if ($Token) {
    $Permission = Get-AzureAppRegistrationPermissions -AppRegistrationID $_.AppID -AppRegistrationName $_.DisplayName -Token $Token
   } else {
    $Permission = Get-AzureAppRegistrationPermissions -AppRegistrationID $_.AppID -AppRegistrationName $_.DisplayName
   }

   #Added this otherwise Export-CSV sends an error if the app registration has no rights
   if ($Permission) {
    $Permission | Export-CSV $ExportFile -Append
   } else {
    if ($Verbose) {
     Write-Colored -Color "Green" -FilePath $LogFile -ColoredText "No permission found for $($_.DisplayName)"
    }
   }
  } catch {
   Write-Colored -Color "Red" -FilePath $LogFile -ColoredText "Error checking permission of $($_.DisplayName) ($($_.AppID)) : $($Error[0])"
  }
 }

 #Convert File to PS Object
 Write-Colored -FilePath $LogFile -PrintDate -NonColoredText "| Step 4 | " -ColoredText "Convert File to PS Object"
 $AzureAppRegistrationPermissionGUID = import-csv $ExportFile

 # [Stats]
 $UniqueAppRegistrationWithPermissions = ($AzureAppRegistrationPermissionGUID | Select-Object ServicePrincipalID -Unique).Count
 Write-Colored -FilePath $LogFile -PrintDate -NonColoredText "| Step 5 | " -ColoredText "Found $UniqueAppRegistrationWithPermissions unique App Registration with permissions (Total permissions $($AzureAppRegistrationPermissionGUID.count))"

 # Generate conversion Table (Takes a minute or 2)
 Write-Colored -FilePath $LogFile -PrintDate -NonColoredText "| Step 6 | " -ColoredText "Generate conversion Table - Will take a couple minutes"
 $IDConversionTable = @()
 $AzureAppRegistrationPermissionGUID | Select-Object -Unique PolicyID | ForEach-Object {
  Write-host "Checking Policy $($_.PolicyID)"
  $IDConversionTable += Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $_.PolicyID
 }

 # Convert GUID To READABLE (Takes a couple seconds)
 Write-Colored -FilePath $LogFile -PrintDate -NonColoredText "| Step 7 | " -ColoredText "Convert GUID to Readable and export to file $FinalFile - Will take a couple seconds"
 Convert-AzureAppRegistrationPermissionsGUIDToReadable -AppRegistrationObjectWithGUIDPermissions $AzureAppRegistrationPermissionGUID -IDConversionTable $IDConversionTable | Export-CSV -Path $FinalFile
}
Function Add-AzureAppRegistrationPermission { # Add rights on App Registration (Requires Grant to be fully working) - Remove Automated Consent, need to manually consent when all permissions are added
 Param (
  [parameter(Mandatory=$true,ParameterSetName="SP_Name_App_ID")]
  [parameter(Mandatory=$true,ParameterSetName="SP_ID_App_ID")]
  [parameter(Mandatory=$true,ParameterSetName="App_ID")]$AppID,
  [parameter(Mandatory=$true,ParameterSetName="SP_Name_App_Name")]
  [parameter(Mandatory=$true,ParameterSetName="SP_ID_App_Name")]
  [parameter(Mandatory=$true,ParameterSetName="App_Name")]$AppName,
  [parameter(Mandatory=$true,ParameterSetName="SP_ID_App_ID")]
  [parameter(Mandatory=$true,ParameterSetName="SP_ID_App_Name")]
  [parameter(Mandatory=$true,ParameterSetName="SP_ID")]$ServicePrincipalID, # Service Principal Object ID that holds the Permission
  [parameter(Mandatory=$true,ParameterSetName="SP_Name_App_ID")]
  [parameter(Mandatory=$true,ParameterSetName="SP_Name_App_Name")]
  [parameter(Mandatory=$true,ParameterSetName="SP_Name")]$ServicePrincipalName, # App Name that holds the Permission - Example : 'Microsoft Graph'
  [Parameter(Mandatory=$true)]$RightName,
  [ValidateSet("Application","Delegated")]$PermissionType
 )
 # Find Rights ID depending on backend_API_ID
 if ($AppName) { $AppID = (Get-AzureAppRegistration -DisplayName $AppName).AppID }
 if ($ServicePrincipalName) { $ServicePrincipalID = Get-AzureServicePrincipalIDFromAppName -AppRegistrationName $ServicePrincipalName }
 if (! $ServicePrincipalID) {
  write-host -ForegroundColor Red "Service Principal `'$ServicePrincipalName`' was not found"
  return
 }
 if ($PermissionType) {
  $RightsToAdd = Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $ServicePrincipalID | Where-Object {($_.Value -eq $RightName) -and ($_.PermissionType -eq $PermissionType) }
 } else {
  $RightsToAdd = Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $ServicePrincipalID | Where-Object "Value" -eq $RightName
 }

 if (! $RightsToAdd) {
  Write-Host -Foregroundcolor "Red" "$RightName ($PermissionType) was not found in API $ServicePrincipalID, please check"
  return
 } elseif ($RightsToAdd.Count -gt 1) {
  Write-Host -Foregroundcolor "Red" "$RightName contains multiple values in API $ServicePrincipalID, please check or force the permission type"
  return
 } else {
  $RuleID = $RightsToAdd.RuleID
  $PolicyID = $RightsToAdd.PolicyID
  if ($RightsToAdd.PermissionType -eq 'Delegated') { # For Application Permission : Role, For Delegated : Scope
   $RightsToAdd_ID = $RuleID + "=Scope"
  } else {
   $RightsToAdd_ID = $RuleID + "=Role"
  }
 }

 # Add Rights
 Progress -Message "Adding API Permissions on $AppID $($RightsToAdd.PermissionType): " -Value $RightName -PrintTime
 az ad app permission add --id $AppID --api $PolicyID --api-permissions $RightsToAdd_ID --only-show-errors

 # Commit Rights
 Progress -Message "Commit API Permissions on $AppID : " -Value $RightName -PrintTime
 az ad app permission grant --id $AppID --api $PolicyID --scope $RightsToAdd_ID --only-show-errors
}
Function Get-AzureAppRegistrationExpiration { # Get All App Registration Secret - Does not see Federated Credential, as the data is not seen in the JSON
 Param (
  $Expiration = 30,
  $MaxExpiration = 730,
  $Token
 )

 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Write-Error "Token is invalid, provide a valid token"
   return
  }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
  $ContinueRunning = $True
  $FirstRun=$True
  While ($ContinueRunning -eq $True) {
   if ($Verbose) { Progress -Message "Getting all Application Loop (Sleep $SleepDurationInS`s | Current Count $($AppList.Count)) : " -Value $Count -PrintTime }
   if ($FirstRun) {
    $CurrentResult = (Invoke-RestMethod -Method GET -headers $Header -Uri "https://graph.microsoft.com/v1.0/applications?`$select=DisplayName,Notes,Tags,AppID,createdDateTime,signInAudience,passwordCredentials,keyCredentials")
    $FirstRun=$False
   } else {
    $CurrentResult = (Invoke-RestMethod -Method GET -headers $Header -Uri $NextRequest )
   }
   $Count++
   $NextRequest = $CurrentResult.'@odata.nextLink'
   if ($CurrentResult.'@odata.nextLink') {$ContinueRunning = $True} else {$ContinueRunning = $False}
   $AppList += $CurrentResult.Value
  }
 } else {
  $AppList = az ad app list --all -o json --query "[].{DisplayName:displayName,Notes:notes,Tags:tags,AppID:appId,createdDateTime:createdDateTime,signInAudience:signInAudience,passwordCredentials:passwordCredentials,keyCredentials:keyCredentials}" | ConvertFrom-Json
 }
 $Date_Today = Get-Date
 $KeyList = $AppList | Where-Object passwordCredentials | Select-Object `
 @{Name="AppName";Expression={$_.DisplayName}},AppID,
 @{Name="AppNotes";Expression={$_.notes}},
 @{Name="AppCreatedOn";Expression={$_.createdDateTime}},
 @{Name="AppTags";Expression={
  $TagList = [PSCustomObject]@{}
  $_.Tags | ForEach-Object {
    $TagList | Add-Member -MemberType NoteProperty -Name ($_ -split ":")[0] -Value ($_ -split ":")[1]
   }
   $TagList
 }}, @{Name="AppAudience";Expression={$_.signInAudience}} -ExpandProperty passwordCredentials | Select-Object -Property `
  @{Name="SecretDescription";Expression={$_.DisplayName}},
  @{Name="SecretCreatedOn";Expression={$_.startDateTime}},
  @{Name="SecretExpiration";Expression={$_.endDateTime}},
  @{Name="SecretType";Expression={"Key"}},
  @{Name="KeyCount";Expression={($AppList | Where-Object AppID -eq $_.AppID).passwordCredentials.Count}},*

 $CertificateList = $AppList | Where-Object keyCredentials | Select-Object `
 @{Name="AppName";Expression={$_.DisplayName}},AppID,
 @{Name="AppNotes";Expression={$_.notes}},
 @{Name="AppCreatedOn";Expression={$_.createdDateTime}},
 @{Name="AppTags";Expression={
  $TagList = [PSCustomObject]@{} # Example to add all Members to an Object without knowing the name first
  $_.Tags | ForEach-Object {
    $TagList | Add-Member -MemberType NoteProperty -Name ($_ -split ":")[0] -Value ($_ -split ":")[1]
   }
   $TagList
 }},
 @{Name="AppAudience";Expression={$_.signInAudience}} -ExpandProperty keyCredentials | Select-Object -Property `
   @{Name="SecretDescription";Expression={$_.DisplayName}},
   @{Name="SecretCreatedOn";Expression={$_.startDateTime}},
   @{Name="SecretExpiration";Expression={$_.endDateTime}},
   @{Name="SecretType";Expression={"Certificate"}},
   @{Name="CertificateCount";Expression={($AppList | Where-Object AppID -eq $_.AppID).keyCredentials.Count}},*

  $KeyList + $CertificateList | Select-Object `
   AppName,AppNotes,AppTags,AppId,AppCreatedOn,AppAudience,SecretDescription,SecretCreatedOn,SecretExpiration,KeyCount,CertificateCount,SecretType,hint,
   @{Name="TimeUntilExpiration";Expression={(NEW-TIMESPAN -Start $Date_Today -End $_.SecretExpiration).Days}} | Select-Object *,
   @{Name="Status";Expression={
    If ($_.TimeUntilExpiration -gt $MaxExpiration) {
     "Infinite"
    } elseif ($_.TimeUntilExpiration -ge $Expiration) {
     "OK for at least $Expiration days"
    } elseif (($_.TimeUntilExpiration -le $Expiration) -and ($_.TimeUntilExpiration -gt 0)) {
     "Expiring in $($_.TimeUntilExpiration) days"
    } elseif ($_.TimeUntilExpiration -eq 0) {
     "Expires today"
    } elseif ($_.TimeUntilExpiration -lt 0) {
     "Expired"
    } else {
     $_.TimeUntilExpiration
    }
   }},
   @{Name="SecretCount";Expression={$_.KeyCount + $_.CertificateCount}}
}
Function Get-AzureAppRegistrationAudience { # Check All App registration Audiences : this can be added to filter wrong configured ones | ? AppAudience -ne "AzureADMyOrg"
 az ad app list --all -o json --query "[].{DisplayName:displayName,AppID:appId,createdDateTime:createdDateTime,signInAudience:signInAudience}" | ConvertFrom-Json | Select-Object `
 @{Name="AppName";Expression={$_.DisplayName}},AppId,
 @{Name="AppCreatedOn";Expression={$_.createdDateTime}},
 @{Name="AppAudience";Expression={$_.signInAudience}}
}
Function Set-AzureAppRegistrationTags { # Set Tag on App Registration, can add or overwrite existing (add no tags to list current tags)
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppID")][String]$AppID,
  [parameter(Mandatory=$true,ParameterSetName="ID")][String]$ID,
  [parameter(Mandatory=$true,ParameterSetName="NAME")][String]$DisplayName,
  $Tags,
  [switch]$Overwrite,
  [switch]$ShowResult
 )

 Try {

  # Get current params to send to other function
  $FunctionParams = $PSBoundParameters
  # Remove Unneeded Tags
  $FunctionParams.Remove('Tags') | Out-Null
  $FunctionParams.Remove('Overwrite') | Out-Null
  $FunctionParams.Remove('ShowResult') | Out-Null

  # Get Current Tags
  $SP_Info = Get-AzureAppRegistration @FunctionParams

  write-colored -Color Cyan -PrintDate -NonColoredText "Current Tags on App Registration `'$($SP_Info.displayName)`' : " $($SP_Info.Tags -join ",")

  if (! $Tags ) { Return }

  # Add all Tags to a new array
  $TagsToAdd = @()
  $Tags | Foreach-Object { $TagsToAdd += $_ }

  # Add existing tags to object, if any, except if overwrite
  if (! $Overwrite) {
   If ($SP_Info.Tags) { $TagsToAdd += $SP_Info.Tags }
  }

  # Remove duplicates
  $TagsToAddUnique = $TagsToAdd | Select-Object -Unique

  if ($SP_Info.Tags -eq $TagsToAddUnique) {
   write-colored -Color Magenta -PrintDate -ColoredText "Tag to add and current tags are the same : $($TagsToAddUnique -Join ",")"
   return
  }

  # Change format for required format
  $TagsToAddUnique | Foreach-Object {
   $TagsToAd_Converted_tmp += "\`"$($_)\`","
  }

  write-colored -Color Cyan -PrintDate -NonColoredText "Tags that will be added to App Registration `'$($SP_Info.displayName)`' : " $($TagsToAddUnique -Join ",")

  # Generate Body
  $TagsToAdd_Converted_prefix = '{"tags":['
  $TagsToAdd_Converted_suffix = ']}'
  $Body = ($TagsToAdd_Converted_prefix + $TagsToAd_Converted_tmp + $TagsToAdd_Converted_suffix) -replace ",]}","]}"

  write-colored -Color Cyan -PrintDate -NonColoredText "Body sent to Graph API : " $Body

  az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$($SP_Info.ID)" `
   --headers "Content-Type=application/json" `
   --body $body

  If ($ShowResult) {
   $SP_Info = Get-AzureServicePrincipalInfo @FunctionParams
   write-colored -Color Cyan -PrintDate -NonColoredText "New Tags on App Registration `'$($SP_Info.displayName)`' : " $TagsToAd_Converted_tmp
  }
 } catch {
  write-host -foregroundcolor "Red" -Object $Error[0]
 }

}
Function Get-AzureAppRegistrationSecrets { # Get Azure App Registration Secret
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationID")]$AppRegistrationID,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationName")]$AppRegistrationName,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationObjectID")]$AppRegistrationObjectID,
  [switch]$Count,
  $Token
 )
 try {
  if ($Token) {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }
   $headers = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }
   if ($AppRegistrationID) {$AppRegistrationInfo = Get-AzureAppRegistration -AppID $AppRegistrationID -ValuesToShow "id,appId,displayName" -Token $Token }
   elseif ($AppRegistrationName) {$AppRegistrationInfo = Get-AzureAppRegistration -DisplayName $AppRegistrationName -ValuesToShow "id,appId,displayName" -Token $Token }
   else {$AppRegistrationInfo = Get-AzureAppRegistration -ID $AppRegistrationObjectID -ValuesToShow "id,appId,displayName" -Token $Token}
  } else {
   if ($AppRegistrationID) {$AppRegistrationInfo = Get-AzureAppRegistration -AppID $AppRegistrationID -ValuesToShow "id,appId,displayName" }
   elseif ($AppRegistrationName) {$AppRegistrationInfo = Get-AzureAppRegistration -DisplayName $AppRegistrationName -ValuesToShow "id,appId,displayName" }
   else {$AppRegistrationInfo = Get-AzureAppRegistration -ID $AppRegistrationObjectID -ValuesToShow "id,appId,displayName"}
  }

  $SecretRequest = "https://graph.microsoft.com/beta/applications/$($AppRegistrationInfo.ID)"
  $FederatedCredRequest = "https://graph.microsoft.com/beta/applications/$($AppRegistrationInfo.ID)/federatedIdentityCredentials"

  if ($Token) {
   $AppInfoFull = Invoke-RestMethod -Method GET -headers $headers -Uri $SecretRequest
   $FederatedCredentialFull = Invoke-RestMethod -Method GET -headers $headers -Uri $FederatedCredRequest
  } else {
   # Get Secret and Certificate
   $AppInfoJSON = az rest --method get --url $SecretRequest --headers 'Content-Type=application/json' 2>&1 | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }
   $AppInfoFull = $AppInfoJSON | ConvertFrom-Json
   # Get Federated Credential
   $FederatedCredentialJSON = az rest --method get --url $FederatedCredRequest --headers 'Content-Type=application/json' 2>&1 | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }
   $FederatedCredentialFull = $FederatedCredentialJSON | ConvertFrom-Json
  }

  $FederatedCredential = $FederatedCredentialFull.Value
  $AppInfo = $AppInfoFull | Select-Object AppId,ID,displayName,passwordCredentials,keyCredentials
  # Merge Data
  $AppInfo | Add-Member -Name FederatedCredential -Value $FederatedCredential -MemberType NoteProperty

  if ($Count) {
   $KeyCount = $AppInfo.keyCredentials.Count + $AppInfo.passwordCredentials.Count + $AppInfo.FederatedCredential.Count
   return $KeyCount
  } else {
   Return $AppInfo
  }
 } catch {
  write-host -foregroundcolor "Red" -Object "Error getting secret from $AppRegistrationID$AppRegistrationName$AppRegistrationObjectID : $($Error[0])"
 }
}
Function Add-AzureAppRegistrationSecret { # Add Secret to App (uses AzCli or Token)
 [CmdletBinding(DefaultParameterSetName = 'AppRegistrationID')]
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationID")]$AppRegistrationID,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationName")]$AppRegistrationName,
  $SecretDescription= "Automatically Generated by $env:username",
  $AppMonths = "6",
  $ShowObjectID,
  [switch]$Force,
  $Token
 )
 try {
  if ($Token) {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Write-Error "Token is invalid, provide a valid token"
    return
   }
   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }
   if ($AppRegistrationName) {
    $AppInfo = Get-AzureAppRegistration -DisplayName $AppRegistrationName -Token $Token
   } else {
    $AppInfo = Get-AzureAppRegistration -AppID $AppRegistrationID -Token $Token
   }
   if ($(Get-AzureAppRegistrationSecrets -AppRegistrationID $AppInfo.AppID -Count -Token $Token) -gt 1) {
    write-host -ForegroundColor "Red" -Object "There is already more than 1 Key for this App $AppRegistrationName ($AppRegistrationID), remove existing keys to have maximum 1 before renewing"
    if (! $Force) { return }
   }
  } else { # If not using Token
   if ($AppRegistrationName) {
    $AppInfo = Get-AzureAppRegistration -DisplayName $AppRegistrationName
   } else {
    $AppInfo = Get-AzureAppRegistration -AppID $AppRegistrationID
   }
   if ($(Get-AzureAppRegistrationSecrets -AppRegistrationID $AppInfo.AppID -Count) -gt 1) {
    write-host -ForegroundColor "Red" -Object "There is already more than 1 Key for this App $AppRegistrationName ($AppRegistrationID), remove existing keys to have maximum 1 before renewing"
    if (! $Force) { return }
   }
  }

  # Parameters
  $AppObjectId = $AppInfo.ID
  $AppName = $AppInfo.displayName

  $GraphURL = "https://graph.microsoft.com/v1.0/applications/$AppObjectId/addPassword"

  if ($Token) {
   $params = @{
    passwordCredential = @{
     "displayName" = $SecretDescription
     "endDateTime" = Format-Date($((Get-Date).AddMonths($AppMonths)))
    }
   }
   $ParamJson = $params | ConvertTo-Json
   $Result = Invoke-RestMethod -Method POST -headers $header -Uri $GraphURL -Body $ParamJson
  } else {
   $body = '"{\"passwordCredential\": {\"displayName\": \"' + $SecretDescription + '\",\"endDateTime\": \"' + $((Get-Date).AddMonths($AppMonths)) + '\"}}"'
   $ResultJson = az rest --method POST --uri $GraphURL --headers "Content-Type=application/json" --body $body
   $Result = $ResultJson | ConvertFrom-Json
  }

  $Result | Add-Member -Name ApplicationID -Value $AppInfo.AppID -MemberType NoteProperty
  $Result | Add-Member -Name ApplicationObjectID -Value $AppObjectId -MemberType NoteProperty
  $Result | Add-Member -Name ApplicationDisplayName -Value $AppName -MemberType NoteProperty

  if ($ShowObjectID) {
   $Result | Select-Object ApplicationDisplayName,ApplicationID,ApplicationObjectID,displayName,secretText,startDateTime,endDateTime
  } else {
   $Result | Select-Object ApplicationDisplayName,ApplicationID,displayName,secretText,startDateTime,endDateTime
  }
 } catch {
  write-host -foregroundcolor "Red" -Object "Error adding secret |$AppRegistrationID|$AppRegistrationName| : $($Error[0])"
 }
}
Function Remove-AzureAppRegistrationSecret { # Remove Secret to App (uses Rest API / Removal) - Not working for Certificate because of requirement for 'Proof'
 Param (
  [parameter(Mandatory=$true)]$Token,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationID")]$AppRegistrationID,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationName")]$AppRegistrationName,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationObjectID")]$AppRegistrationObjectID,
  [parameter(Mandatory=$true)]$KeyID,
  [ValidateSet("Secret","Certificate")]$KeyType = "Secret"
 )
 if (! $AppRegistrationObjectID) {
  if (!$AppRegistrationID) {$AppRegistrationID = (Get-AzureAppRegistration -DisplayName $AppRegistrationName -Token $Token).AppID}
  # Parameters
  $AppRegistrationObjectID = Get-AzureAppRegistrationFromAppID -AppID $AppRegistrationID -Token $token -Value id
 }

 if ($KeyType -eq  "Secret") {
  $RemovalFunction = "removePassword"
 } else {
  $RemovalFunction = "removeKey"
 }

 $Body = (@{
  "keyId" = "$KeyID"
 })

 $BodyJSON = $Body | ConvertTo-JSON -Depth 6

 Get-AzureGraph -GraphRequest "/applications/$AppRegistrationObjectID/$RemovalFunction" -Method 'POST' -Body $BodyJSON -Token $Token

}
Function Remove-AzureAppregistrationSecretAllButOne { # Removes all but last secret on app registration (only works with Secrets, not certificates)
 Param (
  [parameter(Mandatory=$true)]$Token,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationID")]$AppRegistrationID,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationName")]$AppRegistrationName,
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationObjectID")]$AppRegistrationObjectID,
  [switch]$NoConfirm
  )

 try {

  # Check Token status
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { Throw "Token is invalid, provide a valid token" }

  # Get Param to send them to sub functions
  $AppInfoParam = $PSBoundParameters
  $AppInfoParam.Remove('KeyType') | Out-Null
  $AppInfoParam.Remove('KeyType') | Out-Null
  $AppInfo = Get-AzureAppRegistrationSecrets @AppInfoParam
  $SecretInfo = $AppInfo.passwordCredentials

  # Check current secret count
  if ($SecretInfo.count -eq "1") { Throw "Only one secret is available on Application $($AppInfo.displayName) ($($AppInfo.AppID))" }

  # Create list of Secret excluding the newest one
  $LatestSecret = ($SecretInfo | Sort-Object endDateTime)[-1]
  $OldSecrets = $SecretInfo | Where-Object keyId -ne $LatestSecret.keyid

  # Loop through all values and ask for confirmation
  $OldSecrets | ForEach-Object {
   # Print status
   Write-host -ForegroundColor "Red" -Object "Will remove the secret $($_.KeyID) [$($_.displayName)] from App $($AppInfo.displayName) that will expire on $($_.endDateTime)"
   # If confirmation is required ask for confirmation
   if (! $NoConfirm ) {
    $Answer = Question "Please confirm removal" -defaultChoice "1"
    if (! $Answer) {write-host -foregroundcolor "Yellow" "Cancelled" ; return}
   }
   # Remove secret one by one
   Remove-AzureAppRegistrationSecret -Token $Token -AppRegistrationID $AppInfo.AppID -KeyID $_.KeyID
  }
 } Catch {
  write-host -foregroundcolor "Red" -Object $Error[0]
 }
}
Function Set-AzureAppRegistrationConsent { # Consent on permission (Warning : It consents all permissions on an App, you cannot select what permission to consent, so check before)
 Param (
  [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationID,
  [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationName
 )
 if (!$AppRegistrationID) {$AppRegistrationID = (Get-AzureAppRegistration -DisplayName $AppRegistrationName).AppID}
 az ad app permission admin-consent --id $AppRegistrationID
}
Function Get-AzureAppRegistrationAPIExposed { # List Service Principal Exposed API (Equivalent of portal 'Expose an API' values)
Param (
 [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationID,
 [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationName,
 [switch]$HideGUID
)
 if (!$AppRegistrationID) {$AppRegistrationID = (Get-AzureAppRegistration -DisplayName $AppRegistrationName).AppID}
 if (!$AppRegistrationName) {$AppRegistrationName = (Get-AzureAppRegistration -AppID $AppRegistrationID).DisplayName}

 $Result = (az ad app show --id $AppRegistrationID --query '{Exposed:api.oauth2PermissionScopes}'  | ConvertFrom-Json).Exposed

 $Result | Add-Member -MemberType NoteProperty -Name AppName -Value $AppRegistrationName
 $Result | Add-Member -MemberType NoteProperty -Name AppID -Value $AppRegistrationID

 if ($HideGUID) { $Result = $Result | Select-Object -ExcludeProperty *ID }
 $Result
}
Function Get-AzureAppRegistrationAppRoles { # List App Roles defined on an App Registration
 Param (
 [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationID,
 [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$AppRegistrationName,
 [switch]$HideGUID
)
 if (!$AppRegistrationID) {$AppRegistrationID = (Get-AzureAppRegistration -DisplayName $AppRegistrationName).AppID}
 if (!$AppRegistrationName) {$AppRegistrationName = (Get-AzureAppRegistration -AppID $AppRegistrationID).DisplayName}

 $Result = Get-AzureAppRegistration -AppID $AppRegistrationID | Select-Object @{Name="AppName";Expression={$_.DisplayName}},@{Name="AppID";Expression={$_.id}} -ExpandProperty appRoles

 $Result | Add-Member -MemberType NoteProperty -Name AppName -Value $AppRegistrationName
 $Result | Add-Member -MemberType NoteProperty -Name AppID -Value $AppRegistrationID

 if ($HideGUID) { $Result = $Result | Select-Object -ExcludeProperty *ID }
 $Result
}
Function Add-AzureAppRegistrationAppRoles {
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppRegistrationID")]$AppRegistrationID,
  [parameter(Mandatory=$true)]$Description,
  [parameter(Mandatory=$true)]$DisplayName,
  [parameter(Mandatory=$true)]$Value,
  $AppRoleList,
  [parameter(Mandatory=$true)]$Token,
  [ValidateSet("User","Application","Both")]$allowedMemberTypes
 )
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
  Write-Error "Token is invalid, provide a valid token"
  return
 }

 if ($allowedMemberTypes -eq 'Both') {
  $allowedMemberTypes = "User","Application"
 }

 $header = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }

if ($AppRoleList) {
 $body = @{
  appRoles = @(
     $AppRoleList
  )
  }| ConvertTo-Json -Depth 10

} else {
 $body = @{
  appRoles = @(
    @{
      allowedMemberTypes = @($allowedMemberTypes)
      description         = $Description
      displayName         = $DisplayName
      id                  = [guid]::NewGuid()
      isEnabled           = $true
      value               = $Value
    }
  )
} | ConvertTo-Json -Depth 10

}

Invoke-RestMethod -Method Patch `
  -Uri "https://graph.microsoft.com/v1.0/applications/$AppRegistrationID" `
  -Headers $header `
  -Body $body
}
# Service Principal (Enterprise Applications) [Only]
Function Get-AzureServicePrincipalInfo { # Find Service Principal Info using REST | Using AzCli AzAD Cmdlet are 5 times slower than AzRest
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppID")][String]$AppID,
  [parameter(Mandatory=$true,ParameterSetName="ID")][String]$ID,
  [parameter(Mandatory=$true,ParameterSetName="NAME")][String]$DisplayName,
  $ValuesToShow = "*" # Format is : value1,value2
 )
 if ($AppID) {
  (az rest --method GET --uri "https://graph.microsoft.com/v1.0/ServicePrincipals?`$count=true&`$select=$ValuesToShow&`$filter=appID eq '$AppID'" --headers Content-Type=application/json | ConvertFrom-Json).value
 } elseif ($ID) {
  (az rest --method GET --uri "https://graph.microsoft.com/v1.0/ServicePrincipals?`$count=true&`$select=$ValuesToShow&`$filter=ID eq '$ID'" --headers Content-Type=application/json | ConvertFrom-Json).Value
 } elseif ($DisplayName) {
 (az rest --method GET --uri "https://graph.microsoft.com/v1.0/ServicePrincipals?`$count=true&`$select=$ValuesToShow&`$filter=displayName eq '$DisplayName'" --headers Content-Type=application/json | ConvertFrom-Json).Value
 }
}
Function Get-AzureServicePrincipal { # Get all Service Principal of a Tenant
 [CmdletBinding(DefaultParameterSetName = 'Filter')]
 Param (
  # These parameters are part of all sets
  [Parameter(Mandatory = $false, HelpMessage = 'A security token is required.')]
  $Token,

  # --- Specific Get by AppID Set ---
  [Parameter(ParameterSetName = 'GetByAppID', Mandatory = $true, HelpMessage = 'Specify the Application ID.')]
  [string]$AppID,

  # --- Specific Get by ID Set ---
  [Parameter(ParameterSetName = 'GetByID', Mandatory = $true, HelpMessage = 'Specify the Object ID.')]
  [string]$ID,

  # --- Specific Get by DisplayName Set ---
  [Parameter(ParameterSetName = 'GetByDisplayName', Mandatory = $true, HelpMessage = 'Specify the Display Name.')]
  [string]$DisplayName,

  # --- Filter Parameter Set ---
  [Parameter(ParameterSetName = 'Filter', HelpMessage = 'Filter on URL of Service Principals.')]
  $URLFilter,

  [Parameter(ParameterSetName = 'Filter', HelpMessage = 'Filter on Name of Service Principals.')]
  $NameFilter,

  [Parameter(Mandatory = $false, HelpMessage = 'A comma-separated list of properties to display.')]
  $ValuesToShow = "*"
 )

 try {
  # --- Script Body ---
  # You can determine which parameter set was used and branch your logic accordingly.
  Write-Verbose "The active parameter set is: $($PSCmdlet.ParameterSetName)"

  if ($Token) {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { throw "Token is invalid, provide a valid token" }
   $headers = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }
  } else {
   $headers = "Content-Type=application/json"
  }

  switch ($PSCmdlet.ParameterSetName) {
   'Filter' {
     Write-Verbose "Running in Filter mode."
     if ($URLFilter) { Write-Verbose "URLFilter: $URLFilter" }
     if ($NameFilter) { Write-Verbose "NameFilter: $NameFilter" }
     Write-Verbose "ValuesToShow: $ValuesToShow"
     if ($Token) {
      # Colums to select # For fast : id,appId,displayName,servicePrincipalType
      $Arguments += "?`$select=$ValuesToShow"

      if ($NameFilter) {
       $Arguments += "&`$count=true&`$search=`"displayName:$NameFilter`""
       $headers.Add("ConsistencyLevel","eventual")
      } else {
       $Arguments += "&`$top=999"
      }
      $Result = @()
      $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/ServicePrincipals$Arguments"
      $Result += $CurrentResult.value
      While ($CurrentResult.'@odata.nextLink') {
       $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri $CurrentResult.'@odata.nextLink' -MaximumRetryCount 3
       $Result += $CurrentResult.value
      }
     } else { # If using Az Cli
      $Arguments = '--output', 'json', '--all', '--only-show-errors'
      $Arguments += '--query'
      if ($Fast) {
       $Arguments += '"[].{id:id,appId:appId,displayName:displayName,servicePrincipalType:servicePrincipalType}"'
      } else {
       $Arguments += '"[].{id:id,objectType:objectType,servicePrincipalType:servicePrincipalType,appId:appId,publisherName:publisherName,appDisplayName:appDisplayName,displayName:displayName,accountEnabled:accountEnabled,appRoleAssignmentRequired:appRoleAssignmentRequired,notificationEmailAddresses:notificationEmailAddresses,createdDateTime:createdDateTime,preferredSingleSignOnMode:preferredSingleSignOnMode,loginUrl:loginUrl,replyUrls:replyUrls, signInAudience:signInAudience, passwordCredentials:passwordCredentials}"'
      }
      $Result = az ad sp list @Arguments | ConvertFrom-Json
     }
     # Common conversion
     $ReplyURLColumn = $Result | get-member -MemberType NoteProperty -Name replyUrls
     if ($ReplyURLColumn) { $Result = $Result | Select-Object *,@{Name="URLs";Expression={$_.replyUrls -join ","}} }
     if ($URLFilter) { $Result = $Result | Where-Object URLs -like "*$URLFilter*" }

     $Result
   }
   'GetByAppID' {
     Write-Verbose "Running in GetByAppID mode."
     Write-Verbose "AppID: $AppID"
     $URI = "https://graph.microsoft.com/v1.0/ServicePrincipals?`$count=true&`$select=$ValuesToShow&`$filter=appID eq '$AppID'"
     if ($Token) {
      $RestResultObj = Invoke-RestMethod -Method GET -headers $headers -Uri $URI
     } else {
      $RestResultObj = az rest --method GET --uri $URI --headers $headers | ConvertFrom-Json
     }
     if (! $RestResultObj) { Throw "$AppID Not found"}
     $RestResultObj.value
   }
   'GetByID' {
     Write-Verbose "Running in GetByID mode."
     Write-Verbose "ID: $ID"
     $URI = "https://graph.microsoft.com/v1.0/ServicePrincipals?`$count=true&`$select=$ValuesToShow&`$filter=ID eq '$ID'"
     if ($Token) {
      $RestResultObj = Invoke-RestMethod -Method GET -headers $headers -Uri $URI
     } else {
      $RestResultObj = az rest --method GET --uri $URI --headers $headers | ConvertFrom-Json
     }
     if (! $RestResultObj) { Throw "$AppID Not found"}
     $RestResultObj.value
   }
   'GetByDisplayName' {
     Write-Verbose "Running in GetByDisplayName mode."
     Write-Verbose "DisplayName: $DisplayName"
     $URI = "https://graph.microsoft.com/v1.0/ServicePrincipals?`$count=true&`$select=$ValuesToShow&`$filter=displayName eq '$DisplayName'"
     if ($Token) {
      $RestResultObj = Invoke-RestMethod -Method GET -headers $headers -Uri $URI
     } else {
      $RestResultObj = az rest --method GET --uri $URI --headers $headers | ConvertFrom-Json
     }
     if (! $RestResultObj) { Throw "$AppID Not found"}
     $RestResultObj.value
   }
  } # End Switch
 } catch {
   if ($Error[0].ErrorDetails.message) {
    $ErrorMessage = ($Error[0].ErrorDetails.message | ConvertFrom-Json).error.message
   } else {
    $ErrorMessage = $Error[0]
   }
   Write-Error "Error during lookup : $ErrorMessage"
 }
}
Function Get-AzureServicePrincipalIDFromAppID { # Get Azure Service Principal (Enterprise App) information from APP ID (Not SP ObjectID)
 Param (
  [Parameter(Mandatory=$true)]$AppRegistrationID
 )
 ((az ad sp show --id $AppRegistrationID --query "{id:id}") | convertfrom-json).ID
}
Function Get-AzureServicePrincipalIDFromAppName { # Get Azure Service Principal (Enterprise App) information from APP Name (Not SP ObjectID)
 Param (
  [Parameter(Mandatory=$true)]$AppRegistrationName
 )
 ((az ad sp list --filter "displayName eq '$AppRegistrationName'") | convertfrom-json).ID
}
Function Get-AzureServicePrincipalNameFromID { # Get Azure Service Principal Name from Object ID
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppID")][String]$AppID,
  [parameter(Mandatory=$true,ParameterSetName="ID")][String]$ID,
  $Value = "displayName", # or UserPrincipalName
  $Token
 )

 try {
 if ($ID) {
  $RequestURL = "https://graph.microsoft.com/v1.0/ServicePrincipals/$ID`?`$select=$Value"
 } else {
  $RequestURL = "https://graph.microsoft.com/v1.0/ServicePrincipals?`$count=true&`$select=$Value&`$filter=AppID eq '$AppID'"
 }
 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
  $headers = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
  $Result = (Invoke-RestMethod -Method GET -headers $headers -Uri $RequestURL)
 } else {
  $Result = (az rest --method GET --uri $RequestURL --headers Content-Type=application/json | ConvertFrom-Json)
 }

 if (! $Result ) {
  Return "$AppID$ID"
 }

 # Result format is different depending on the request
 if ($ID) {
  $Result.$Value
 } else {
  $Result.value.$Value
 }
 } catch {
  Write-Verbose "Application $AppID$ID not found"
  return "$AppID$ID"
 }
}
Function Get-AzureServicePrincipalOwner { # Get owner(s) of a Service Principal
 Param (
  [Parameter(Mandatory=$true)]$ServicePrincipalID
 )
 $Result = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalID/owners/`$ref" --header Content-Type=application/json | ConvertFrom-Json).Value
 $Result | ForEach-Object {
  $OwnerType = ($_.'@odata.id' -split('/'))[-1]
  $OwnerID = ($_.'@odata.id' -split('/'))[-2]
  if ($OwnerType -eq 'Microsoft.DirectoryServices.ServicePrincipal') {
   Get-AzureServicePrincipalInfo -ID $OwnerID | Select-Object @{name="ServicePrincipalID";expression={$ServicePrincipalID}},
   @{name="OwnerType";expression={$OwnerType}},
   @{name="OwnerID";expression={$OwnerID}},
   @{name="OwnerName";expression={$_.displayName}},
   @{name="OwnerUPN";expression={""}}
  } elseif ($OwnerType -eq 'Microsoft.DirectoryServices.User') {
   Get-azureaduserinfo -UPNorID $OwnerID | Select-Object @{name="ServicePrincipalID";expression={$ServicePrincipalID}},
   @{name="OwnerType";expression={$OwnerType}},
   @{name="OwnerID";expression={$OwnerID}},
   @{name="OwnerName";expression={$_.displayName}},
   @{name="OwnerUPN";expression={$_.userPrincipalName}}
  } else {
   [pscustomobject]@{ServicePrincipalID="$ServicePrincipalID";OwnerType="$OwnerType";OwnerID="$OwnerID";OwnerName="Not Implemented";OwnerUPN="Not Implemented"}
  }
 }
}
Function Get-AzureServicePrincipalOwnerForAllApps { # Get Owner(s) of all Service Principals
 Get-AzureServicePrincipal | ForEach-Object {
  Progress -Message "Checking current Service Principal : " -Value $_.DisplayName
  Get-AzureServicePrincipalOwner -ServicePrincipalID $_.id
 } | Export-Csv "$iClic_TempPath\AzureServicePrincipalOwnerForAllApps_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
 ProgressClear
}
Function Add-AzureServicePrincipalOwner { # Add a Owner to a Service Principal (it is different than App Registration Owners) - The ID must be the ObjectID of the 'Enterprise App'
 Param (
  [parameter(Mandatory=$true,ParameterSetName="UPN")][String]$OwnerUPN,
  [parameter(Mandatory=$true,ParameterSetName="ObjectID")][String]$OwnerObjectID,
  [Parameter(Mandatory = $true,ParameterSetName = 'UPN')]
  [Parameter(Mandatory = $true,ParameterSetName = 'ObjectID')]$ServicePrincipalID  #Owner or Object ID is required, both param cannot be set, UPN will be slower
 )

 if ($OwnerUPN) { $UserObjectID = (Get-AzureADUserInfo $OwnerUPN).ID } else { $UserObjectID = $OwnerObjectID }
 Write-Host -ForegroundColor "Cyan" "Adding owner for user $UserObjectID on Service Principal $ServicePrincipalID"

 $Body = '{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/'+$UserObjectID+'\"}'

 az rest --method POST `
   --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalID/owners/`$ref" `
   --headers Content-Type=application/json `
   --body $Body
}
Function Get-AzureServicePrincipalPolicyPermissions { # Used to convert ID to names of Service Principal Permission (Can be used to get ID of Role of a backend API for example). Uses AzCli or Graph
 Param (
  [Parameter(Mandatory=$true)]$ServicePrincipalAppID, # Service Principal App ID
  $Token
 )
 Try {
  if ($Token) {
   $PolicyListJson = Get-AzureServicePrincipal -Token $Token -AppID $ServicePrincipalAppID
  } else {
   $PolicyListJson = az ad sp show --id $ServicePrincipalAppID --only-show-errors -o json | ConvertFrom-Json
  }

  $PolicyName = $PolicyListJson.displayName

  $PolicyContent = $PolicyListJson | Select-Object @{name="oauth2Permissions";expression={
   $oauth2Permissions_List=@()
   $AppID = $_.appId
   $_.oauth2PermissionScopes | ForEach-Object {
    $oauth2Permissions_List+=[pscustomobject]@{
     PolicyName = $PolicyName
     PolicyID = $AppID;
     RuleID = $_.id
     PermissionType = "Delegated"
     Type = $_.type;
     Value = $_.value
     Description = $_.adminConsentDisplayName
    }
   }
   $oauth2Permissions_List
 }},@{name="appRoles";expression={
  $appRoles_List=@()
  $AppID = $_.appId
  $_.appRoles | ForEach-Object {
   if ($_.DisplayName -eq $_.Value) {$Description = $_.Description} else {$Description = $_.DisplayName}
   $appRoles_List+=[pscustomobject]@{
    PolicyName = $PolicyName
    PolicyID=$AppID
    RuleID=$_.id
    PermissionType = "Application"
    Type = $_.allowedMemberTypes
    Value = $_.value
    Description = $Description
   }
  }
  $appRoles_List
 }}

  if ($PolicyContent.oauth2Permissions -and $PolicyContent.appRoles) {
   @($PolicyContent.appRoles) + @($PolicyContent.oauth2Permissions)
  } elseif ($PolicyContent.oauth2Permissions) { $PolicyContent.oauth2Permissions
  } elseif ($PolicyContent.appRoles) { $PolicyContent.appRoles
  }
 } catch {
  if ($Error[0].ErrorDetails.message) {
   $ErrorMessage = ($Error[0].ErrorDetails.message | ConvertFrom-Json).error.message
  } else {
   $ErrorMessage = $Error[0]
  }
  Write-Error "Error during lookup : $ErrorMessage"
}
}
Function Set-AzureServicePrincipalTags { # Set Tag on Service Principal, can add or overwrite existing (add no tags to list current tags)
 Param (
  [parameter(Mandatory=$true,ParameterSetName="AppID")][String]$AppID,
  [parameter(Mandatory=$true,ParameterSetName="ID")][String]$ID,
  [parameter(Mandatory=$true,ParameterSetName="NAME")][String]$DisplayName,
  $Tags,
  [switch]$Overwrite,
  [switch]$ShowResult
 )
 Try {

  # Get current params to send to other function
  $FunctionParams = $PSBoundParameters
  $FunctionParams.Remove('Tags') | Out-Null
  $FunctionParams.Remove('Overwrite') | Out-Null
  $FunctionParams.Remove('ShowResult') | Out-Null

  # Get Current Tags
  $SP_Info = Get-AzureServicePrincipalInfo @FunctionParams

  write-colored -Color Cyan -PrintDate -NonColoredText "Current Tags on Service Principal `'$($SP_Info.displayName)`' : " $($SP_Info.Tags -join ",")

  if (! $Tags ) { Return }

  # Add all Tags to a new array
  $TagsToAdd = @()
  $Tags | Foreach-Object { $TagsToAdd += $_ }

  # Add existing tags to object, if any, except if overwrite
  if (! $Overwrite) {
   If ($SP_Info.Tags) { $TagsToAdd += $SP_Info.Tags }
  }

  # Remove duplicates
  $TagsToAddUnique = $TagsToAdd | Select-Object -Unique

  if ($SP_Info.Tags -eq $TagsToAddUnique) {
   write-colored -Color Magenta -PrintDate -ColoredText "Tag to add and current tags are the same : $($TagsToAddUnique -Join ",")"
   return
  }

  # Change format for required format
  $TagsToAddUnique | Foreach-Object {
   $TagsToAd_Converted_tmp += "\`"$($_)\`","
  }

  write-colored -Color Cyan -PrintDate -NonColoredText "Tags that will be added to Service Principal `'$($SP_Info.displayName)`' : " $($TagsToAddUnique -Join ",")

  # Generate Body
  $TagsToAdd_Converted_prefix = '{"tags":['
  $TagsToAdd_Converted_suffix = ']}'
  $Body = ($TagsToAdd_Converted_prefix + $TagsToAd_Converted_tmp + $TagsToAdd_Converted_suffix) -replace ",]}","]}"

  write-colored -Color Cyan -PrintDate -NonColoredText "Body sent to Graph API : " $Body

  az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($SP_Info.ID)" `
   --headers "Content-Type=application/json" `
   --body $body

  If ($ShowResult) {
   $SP_Info = Get-AzureServicePrincipalInfo @FunctionParams
   write-colored -Color Cyan -PrintDate -NonColoredText "New Tags on Service Principal `'$($SP_Info.displayName)`' : " $($SP_Info.Tags -join ",")
  }
 } catch {
  write-host -foregroundcolor "Red" -Object $Error[0]
 }
}
Function Get-AzureServicePrincipalAssignments { # Get Service Principal Assigned Users and Groups
 Param (
  [parameter(Mandatory=$true,ParameterSetName="SP_ID")]$ServicePrincipalID,
  [parameter(Mandatory=$true,ParameterSetName="SP_Name")]$ServicePrincipalName,
  [switch]$ShowAppRole,
  [switch]$Readable
 )
 if ($ServicePrincipalName) {
  $ServicePrincipalID = Get-AzureServicePrincipalIDFromAppName -AppRegistrationName $ServicePrincipalName
 }
 $AppAssigments = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalID/appRoleAssignedTo" --header Content-Type=application/json | ConvertFrom-Json).Value | Select-Object -ExcludeProperty deletedDateTime
 If ($ShowAppRole) {
  $AppRole = Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $ServicePrincipalID
  $AppAssigments | ForEach-Object {
   if ($AppRole) { $CurrentRole = $AppRole[$AppRole.RuleID.indexof($_.appRoleId)] }
   $_ | Add-Member -MemberType NoteProperty -Name RoleName -Value $CurrentRole.value
   $_ | Add-Member -MemberType NoteProperty -Name RoleDescription -Value $CurrentRole.Description
  }
 }
 If ($Readable) {
  $AppAssigments | Select-Object -ExcludeProperty appRoleId,id,principalId,resourceId
 } else {
  $AppAssigments
 }
}
Function Remove-AzureServicePrincipalAssignments { # Remove Assignements, Assignement IDs are recommended, but UserName is possible but will be a lot slower
 Param (
  [Parameter(Mandatory=$true)]$ServicePrincipalID,
  [Parameter(Mandatory=$true, ParameterSetName="Direct")]$AssignmentID, # Strongly Recommended and a lot faster
  [Parameter(Mandatory=$true, ParameterSetName="Search")]$UserDisplayName
 )
 if ( ! $AssignmentID) {
  $PermissionInfo = Get-AzureServicePrincipalAssignments -ServicePrincipalID $ServicePrincipalID | Where-Object principalDisplayName -eq $UserDisplayName
  if ( ! $PermissionInfo) {
   Write-Host -ForegroundColor Red -Object "$UserDisplayName was not found"
   Return
  } else {
   $AssignmentID = $PermissionInfo.id
  }
 }
 az rest --method DELETE --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalID/appRoleAssignedTo/$AssignmentID"
}
Function Get-AzureServicePrincipalPermissions { # Get Assigned API Permission. Uses AzCli
 Param (
  [Parameter(Mandatory=$false,ParameterSetName="AppInfo")]$principalId, # ID of the App to be changed
  [parameter(Mandatory=$false,ParameterSetName="AppInfo")]$principalName, # Display Name of App Registration
  [switch]$Readable, # Slower but adds readable Role definition
  [switch]$HideGUID,
  [switch]$HideDate
 )
 if (!$principalId) {$principalId = (Get-AzureServicePrincipalIDFromAppName -AppRegistrationName $principalName)}
 if (!$principalName) {$principalName = $(Get-AzureServicePrincipalNameFromID -ID $principalId)}

 $ResultAppRole = (az rest --method get --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments" --headers 'Content-Type=application/json' | ConvertFrom-Json).Value

 $ResultAppRole | ForEach-Object {
   $_ | Add-Member -MemberType NoteProperty -Name PermissionType -Value "appRoleAssignments"
 }

 $ResultPermissionGrantTMP = (az rest --method get --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/oauth2PermissionGrants" --headers 'Content-Type=application/json' | ConvertFrom-Json).Value

 $ResultPermissionGrantTMP | ForEach-Object {
   $_ | Add-Member -MemberType NoteProperty -Name "appRoleId" -Value $_.clientId
   $_ | Add-Member -MemberType NoteProperty -Name "createdDateTime" -Value ""
   $_ | Add-Member -MemberType NoteProperty -Name "deletedDateTime" -Value ""
   $_ | Add-Member -MemberType NoteProperty -Name "principalDisplayName" -Value "$principalName"
   $_ | Add-Member -MemberType NoteProperty -Name "principalType" -Value "ServicePrincipal"
   $_ | Add-Member -MemberType NoteProperty -Name "appRoleValue" -Value ""
   $_ | Add-Member -MemberType NoteProperty -Name "resourceDisplayName" -Value $(Get-AzureServicePrincipalNameFromID -ID $_.resourceId)
   $_ | Add-Member -MemberType NoteProperty -Name "PermissionType" -Value "oauth2PermissionGrants"
 }

 $ResultPermissionGrant = $ResultPermissionGrantTMP | ForEach-Object {
  $CurrentObject = $_
  ($_.scope -split " ") | ForEach-Object {
   $Scope = $_
   if (! $Scope ) { Return }
   $CurrentObject | Select-Object -ExcludeProperty scope,appRoleDisplayName,clientId,consentType *,@{name="appRoleDisplayName";expression={$Scope}}
   }
 }

 $Result = $ResultAppRole + $ResultPermissionGrant

 If ($Readable) {
   $Result | ForEach-Object {
    if ($_.PermissionType -eq "oauth2PermissionGrants") {return}
    $AppRoleDisplayName = (Get-AzureServicePrincipalInfo -ID $_.resourceId -ValuesToShow appRoles).appRoles | Where-Object id -eq $_.appRoleId
    $_ | Add-Member -MemberType NoteProperty -Name appRoleDisplayName -Value $AppRoleDisplayName.displayName
    $_ | Add-Member -MemberType NoteProperty -Name appRoleValue -Value $AppRoleDisplayName.value
   }
 }
 if ($HideGUID) { $Result = $Result | Select-Object -ExcludeProperty *ID }
 if ($HideDate) { $Result = $Result | Select-Object -ExcludeProperty *DateTime }
 $Result
}
Function Add-AzureServicePrincipalPermission { # Add rights on Service Principal - Does not require an App Registration (Works on Managed Identity) - CHECK, A ISSUE SEEMS TO EXIST. Uses AzCli
 Param (
  [parameter(Mandatory=$true,ParameterSetName="SP_ID")]
  [parameter(Mandatory=$true,ParameterSetName="SP_ID_RoleName")]
  [parameter(Mandatory=$true,ParameterSetName="SP_ID_RoleID")]$principalId, # ID of the Service Principal to change
  [parameter(Mandatory=$true,ParameterSetName="SP_NAME")]
  [parameter(Mandatory=$true,ParameterSetName="SP_NAME_RoleName")]
  [parameter(Mandatory=$true,ParameterSetName="SP_NAME_RoleID")]$principalName, # Name of the Service Principal to change
  [parameter(Mandatory=$true,ParameterSetName="SP_ID_RoleID")]
  [parameter(Mandatory=$true,ParameterSetName="SP_NAME_RoleID")]$appRoleId, # ID of the Role to use : Example : 6a46f64d-3c21-4dbd-a9af-1ff8f2f8ab14
  [parameter(Mandatory=$true,ParameterSetName="SP_NAME_RoleName")]
  [parameter(Mandatory=$true,ParameterSetName="SP_ID_RoleName")]$appRoleName, # Name of the Role to use : Example : User.Read.All
  [Parameter(Mandatory=$true)]$resourceDisplayName, # DisplayName of the API to use : example : Microsoft Graph
  $resourceId, # (Application) ID of the API to use : Example : df021288-bdef-4463-88db-98f22de89214
  [ValidateSet("Application","Delegated")]$PermissionType
 )

 # If Principal Name is given, get the Service Principal ID for the App
 if ($principalName) {
  $principalId = Get-AzureServicePrincipalIDFromAppName -AppRegistrationName $principalName
 }

 # If the resource ID is not given or the permission is not given specifically retrieve app Info of resource containing the permission
 if ((! $resourceId) -or ($appRoleName)) {
  $AppInfo = (Get-AzureServicePrincipalInfo -DisplayName $resourceDisplayName)
 }

 # If resource ID is still empty set it as the Appinfo ID
 If (! $resourceId) {
  $resourceId = $AppInfo.Id
 }

 # Find full information about permission to Add
 if ($PermissionType) {
  $RightsToAdd = Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $resourceId | Where-Object {($_.Value -eq $appRoleName) -and ($_.PermissionType -eq $PermissionType) }
 } else {
  $RightsToAdd = Get-AzureServicePrincipalPolicyPermissions -ServicePrincipalAppID $resourceId | Where-Object "Value" -eq $appRoleName
 }

 # Final Check
 if ((! $RightsToAdd) -and (! $appRoleId)) {
  Write-Host -Foregroundcolor "Red" "$appRoleName ($PermissionType) was not found in API $resourceId, please check"
  return
 } elseif ($RightsToAdd.Count -gt 1) {
  Write-Host -Foregroundcolor "Red" "$appRoleName contains multiple values in API $resourceId, please check or force the permission type"
  return
 } else {
  $appRoleId = $RightsToAdd.RuleID
 }

 # appRoleAssignments = Application Permission
 # oauth2PermissionGrants = Delegated Permission

 if ($PermissionType -ne "Delegated") {

  # APPLICATION

 $EndPointURL = "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/appRoleAssignments"
 $Body = '{\"appRoleId\": \"'+$appRoleId+'\",\"principalId\": \"'+$principalId+'\",\"resourceDisplayName\": \"'+$resourceDisplayName+'\",\"resourceId\": \"'+$resourceId+'\"}'

 # Launch request
 az rest --method POST --uri $EndPointURL --headers 'Content-Type=application/json' --body $Body
 } else {

  # DELEGATED

  # Get oAuth2PermissionGrantinfo if the Principal already has an entry
  $oAuth2PermissionGrantInfo = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId/oauth2PermissionGrants" | convertfrom-json).value `
   | Where-Object { ($_.consentType -eq "AllPrincipals") -and ($_.resourceId -eq "$resourceId") }

  # if principal never had an entry then it must be created
  if (! $oAuth2PermissionGrantInfo) {
   # clientId is the Service Principal that we need to update
   # resourceId is the Service Principal containing the permission we need to add
   $EndPointURL = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/"
   $Body = '{\"clientId\": \"'+$principalId+'\",\"consentType\": \"AllPrincipals\",\"scope\": \"'+$appRoleName+'\",\"resourceId\": \"'+$resourceId+'\"}'

   az rest --method POST --uri $EndPointURL --headers 'Content-Type=application/json' --body $Body

  } else { # If an entry already exists it MUST be updated and not overwrote
  # Get Grant ID to be used in the Endpoint URL
  $oAuth2PermissionGrantId = $oAuth2PermissionGrantInfo.id
  $EndPointURL = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$oAuth2PermissionGrantId"

  # Update Scope (if you do not do this, then the scope will be overwrote - DO NOT FORGET THE SPACE)
  $NewScope = $oAuth2PermissionGrantInfo.scope + " " + $appRoleName
  $Body = '{\"Scope\": \"'+$NewScope+'\"}'

  az rest --method PATCH --uri $EndPointURL --headers 'Content-Type=application/json' --body $Body
  }
 }

}
Function Remove-AzureServicePrincipalPermissions { # Remove rights on Service Principal - Uses Rest API with Token
 Param (
  [Parameter(Mandatory=$true)]$PermissionID,
  [parameter(Mandatory = $true)]$Token
 )
 Try {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { Throw "Token is invalid, provide a valid token" }
  $headers = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
  Invoke-RestMethod -Method DELETE -headers $headers -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$PermissionID"
 } Catch {
  write-host -foregroundcolor "Red" -Object "Error removing permissions $PermissionID : $($Error[0])"
 }
}
Function Get-AzureServicePrincipalRoleAssignment { # Get all Service Principal and group them by type and Role Assignement Status
 Param (
  [Switch]$ShowAssignements # Slow
 )
 $AllApps = Get-AzureServicePrincipal

 if ($ShowAssignements) {
  $AllApps | ForEach-Object {
   Get-AzureServicePrincipalAssignments -ServicePrincipalID $_.id
  }
 } else {
  $AllApps | Select-Object appdisplayname,servicePrincipalType,accountEnabled,appRoleAssignmentRequired | Group-Object signInAudience,servicePrincipalType,appRoleAssignmentRequired
 }
}
Function Set-AzureServicePrincipalAssignementRequired { # Set the Checkbox on enterprise app to ensure Assignement is required
 Param (
  [Parameter(Mandatory=$true)]$ServicePrincipalID,
  $Token
 )
 if ($Token) {
  Try {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }

   $ContentType = "application/json"

   $headers = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = $ContentType
   }

   $URI = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalID"

   $CurrentValue = Invoke-RestMethod -Headers $headers -Method 'GET' -ContentType $ContentType -Uri $URI

   if ( ! $CurrentValue.AppID ) { Throw "Service Principal not found" }

   $Body = (@{
    "appRoleAssignmentRequired" = 'true'
   })
   $BodyJSON = $Body | ConvertTo-JSON -Depth 6

   $CMDParams = @{
    "URI"         = $URI
    "Headers"     = $Headers
    "Method"      = "PATCH"
    "ContentType" = $ContentType
    "Body" = $BodyJSON
   }
   # $CMDParams ;  return
   Invoke-RestMethod @CMDParams
  } catch {
   if ($Error[0].ErrorDetails.message) {
    $ErrorMessage = ($Error[0].ErrorDetails.message | ConvertFrom-Json).error.message
   } else {
    $ErrorMessage = $Error[0]
   }
   Write-Error "Failed to set Assignement required value on $ServicePrincipalID ($ErrorMessage)"
   if ($_.Exception.InnerException) {
    Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
   }
   return $null
  }
 } else {
  az ad sp update --id $ServicePrincipalID --set appRoleAssignmentRequired=True
 }
}
Function Get-AzureServicePrincipalExpiration { # Get All Service Principal Secrets (Copied function from App Registration) - Used to get SAML certificate Expiration
 Param (
  [switch]$PrintOnly,
  [switch]$ShowAll,
  [switch]$ShowOnlySAML,
  [switch]$ExcludeLegacy,
  $NameFilterInclusion,
  $NameFilterExclusion,
  $Expiration = 30,
  $Token
 )


 # Get Data
 if ($Token) {
  $AppList = Get-AzureServicePrincipal -Token $Token
 } else {
  $AppList = Get-AzureServicePrincipal
 }

 $Date_Today = Get-Date

 # Format data
 $Result = $AppList | Where-Object passwordCredentials | Select-Object `
  @{Name="Name";Expression={$_.DisplayName}},AppID,id,appRoleAssignmentRequired,
  @{Name="Mode";Expression={$_.preferredSingleSignOnMode}},
  @{Name="Type";Expression={$_.servicePrincipalType}},
  @{Name="Contacts";Expression={$_.notificationEmailAddresses -join ","}},
  @{Name="AppCreatedOn";Expression={$_.createdDateTime}},
  @{Name="URLs";Expression={$_.replyUrls -join ","}},
  @{Name="Audience";Expression={$_.signInAudience}} -ExpandProperty passwordCredentials | `
   Select-Object -Property `
   @{Name="SecretDescription";Expression={$_.DisplayName}},
   @{Name="SecretCreatedOn";Expression={$_.startDateTime}},
   @{Name="SecretExpiration";Expression={$_.endDateTime}},
   @{Name="SecretType";Expression={$_.preferredSingleSignOnMode}},
   @{Name="ExpiresIn";Expression={(NEW-TIMESPAN -Start $Date_Today -End $_.endDateTime).Days}},* | `
    Select-Object  -ExcludeProperty displayName,createdDateTime,customKeyIdentifier,hint,keyId,secretText,startDateTime,endDateTime *,
    @{Name="Count";Expression={$AppList[$AppList.AppID.indexof($_.AppId)].passwordCredentials.Count}} # A lot Faster than Where cmdlet

 # Filter Data
 if ($NameFilterInclusion) { $Result = $Result | Where-Object Name -like $NameFilterInclusion }
 if ($NameFilterExclusion) { $Result = $Result | Where-Object Name -notlike $NameFilterExclusion }
 if ($ExcludeLegacy) { $Result = $Result | Where-Object Type -ne "Legacy" }
 if ($ShowOnlySAML) { $Result = $Result | Where-Object Mode -eq "saml" }
 if (! $ShowAll) { $Result = $Result | Where-Object ExpiresIn -lt $Expiration }

 # Print Data
 $Result | Sort-Object ExpiresIn | Select-Object Name,Type,Audience,Mode,appRoleAssignmentRequired,ExpiresIn,Count,AppCreatedOn,SecretExpiration,Contacts,URLs,AppID,ID,SecretDescription,SecretCreatedOn,SecretType
}
Function Add-AzureServicePrincipalRBACPermission { # Add RBAC Permissions for Service Principals
 [CmdletBinding(DefaultParameterSetName = 'SPName_SubName')] # Optional: sets a default if no unique set is determined
 Param (
   # --- Parameter Set: ServicePrincipalName and SubscriptionName ---
  [Parameter(Mandatory = $true, ParameterSetName = 'SPName_SubName', HelpMessage = "The name of the Azure AD service principal.")]
  [Parameter(Mandatory = $true, ParameterSetName = 'SPName_SubID', HelpMessage = "The name of the Azure AD service principal.")]
  [string]$ServicePrincipalName,

  [Parameter(Mandatory = $true, ParameterSetName = 'SPID_SubName', HelpMessage = "The Object ID or Application ID of the Azure AD service principal.")]
  [Parameter(Mandatory = $true, ParameterSetName = 'SPID_SubID', HelpMessage = "The Object ID or Application ID of the Azure AD service principal.")]
  [string]$ServicePrincipalID,

  [Parameter(Mandatory = $true, ParameterSetName = 'SPName_SubName', HelpMessage = "The name of the Azure subscription.")]
  [Parameter(Mandatory = $true, ParameterSetName = 'SPID_SubName', HelpMessage = "The name of the Azure subscription.")]
  [string]$SubscriptionName,

  [Parameter(Mandatory = $true, ParameterSetName = 'SPName_SubID', HelpMessage = "The ID of the Azure subscription.")]
  [Parameter(Mandatory = $true, ParameterSetName = 'SPID_SubID', HelpMessage = "The ID of the Azure subscription.")]
  [string]$SubscriptionID,

  # --- Common Parameters ---
  [Parameter(Mandatory = $true, HelpMessage = "The permission level to assign (e.g., Reader, Contributor).")]
  [string]$Permission,

  [Parameter(Mandatory = $false, HelpMessage = "Optional. The name of the resource group to scope the permission. If not provided, permission is usually applied at the subscription scope.")]
  [string]$ResourceGroupName
)
 if (! $SubscriptionID ) { $SubscriptionID = $((Get-AzureSubscriptions -Name $SubscriptionName).id) }
 if (! $SubscriptionID ) { write-host -ForegroundColor Red "Subscription $SubscriptionName not found" ; Return}

 if (! $ServicePrincipalID) { $ServicePrincipalID = Get-AzureServicePrincipalIDFromAppName -AppRegistrationName $ServicePrincipalName }
 if (! $ServicePrincipalID ) { write-host -ForegroundColor Red "Service Principal $ServicePrincipalName not found" ; Return}

 if ($ResourceGroupName) {
  Add-AzureADRBACRights -ID_Type ServicePrincipal -Id $ServicePrincipalID -Role $Permission -Scope "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName"
 } else {
  Add-AzureADRBACRights -ID_Type ServicePrincipal -Id $ServicePrincipalID -Role $Permission -Scope "/subscriptions/$SubscriptionID"
 }
}
Function Add-AzureServicePrincipalAssignments {
 Param (
  [parameter(Mandatory = $true)]$ServicePrincipalID, # Service Principal To Update
  [parameter(Mandatory = $true)]$ObjectToAddID, # User or group or object to add
  $AppRole, # AppRole to add (default : User)
  [parameter(Mandatory = $true)]$Token
 )
 Try {
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { Throw "Token is invalid, provide a valid token" }
 $headers = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }

 if ($AppRole) {
  if (Assert-IsGUID $AppRole) {
   $AppRoleID = $AppRole
  } else {
  $AppID = (Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalID`?`$select=AppID").appId
  $AppRoleID = ((Get-AzureAppRegistration -AppID $AppID -Token $Token).appRoles | Where-Object displayName -eq "$AppRole").id
  }
 }

 $Body = (@{
  "principalId" = "$ObjectToAddID"
  "resourceId" =  "$ServicePrincipalID"
 })

 # App role is not a mandatory value
 if ($AppRole) {
  $Body.add("appRoleId" , "$AppRoleID")
 }

 $BodyJSON = $Body | ConvertTo-JSON -Depth 6

 $CMDParams = @{
  "URI"         = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalID/appRoleAssignedTo"
  "Headers"     = $Headers
  "Method"      = "POST"
  "ContentType" = 'application/json'
  "Body" = $BodyJSON
 }

 # $CMDParams ;  return
 Invoke-RestMethod @CMDParams
 } catch {
  # write-host -foregroundcolor "Red" -Object "Error adding permissions $ObjectToAddID to app $ServicePrincipalID : $(($Error[0].ErrorDetails.message | ConvertFrom-Json).error.message)"
  write-host -foregroundcolor "Red" -Object "Error adding permissions $ObjectToAddID to app $ServicePrincipalID : $($Error[0])"
 }
}
# User Role Assignement (Not RBAC)
Function Get-AzureADRoleAssignements { # With GRAPH [Shows ALL Azure Roles assignements, unlike the other cmdline that misses some information] - But right now does not allow Eligible check
 Param (
  [parameter(Mandatory = $true)]$Token,
  [switch]$Convert,
  [Switch]$HideGUID
 )

 # Eligible value available here https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances, but does not work with AzCli with User Authentication. Missing Consent
 # Would work with App registration login with the following value : RoleEligibilitySchedule.Read.Directory

 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
  write-host -foregroundcolor "Red" "Token is invalid, provide a valid token"
  return
 }

 # Get all role definitions
 Progress -Message "Current Step : " -Value "Get all role definitions" -PrintTime
 $RoleDefinitionList = Get-AzureRoleDefinitions -Token $token

 # Get all Administrative Unit
 Progress -Message "Current Step : " -Value "Get all Administrative Unit" -PrintTime
 $AdminUnitList = Get-AzureAdministrativeUnit -Token $token

 # Get all Permanent Assignement
 Progress -Message "Current Step : " -Value "Get all Permanent Assignement" -PrintTime
 $DirectMembersGUID = Get-AzureRoleAssignements -Token $Token

 # Get all Eligible Assignement
 Progress -Message "Current Step : " -Value "Get all Permanent Assignement" -PrintTime
 $DirectMembersEligibleGUID = Get-AzureRoleAssignementsEligible -Token $Token

 # Convert all user ID
 Progress -Message "Current Step : " -Value "Convert all user ID" -PrintTime
 $PrincipalInfo = $DirectMembersGUID.principalId + $DirectMembersEligibleGUID.PrincipalID | Select-Object -Unique | ForEach-Object { Get-AzureADObjectInfo -ObjectID $_ -Token $Token }

 Progress -Message "Current Step : " -Value "Check Roles" -PrintTime
 $Result = $DirectMembersGUID + $DirectMembersEligibleGUID | Select-Object *,
  @{name="roleDefinitionName";expression={
   if ($RoleDefinitionList.id.contains($_.roleDefinitionId)) {
    ($RoleDefinitionList[$RoleDefinitionList.id.indexof($_.roleDefinitionId)]).displayName
   } else {
    (Get-AzureADObjectInfo -ObjectID $_.roleDefinitionId -Token $token).displayName
   }
  }},
  @{name="directoryScopeInfo";expression={
   if ($_.directoryScopeID -like "/administrativeUnits/*" ) {
    $DirectoryScopeID = (($_.directoryScopeID).split('/'))[-1]
    [pscustomobject]@{Name=$(($AdminUnitList[$AdminUnitList.id.indexof($DirectoryScopeID)]).displayName);Type="Administrative Unit"}
   } elseif ($_.directoryScopeID -eq "/") {
    [pscustomobject]@{Name="Directory";Type="Directory"}
   } else {
    $ObjectInfo = Get-AzureADObjectInfo -ObjectID (($_.directoryScopeID).split('/'))[-1] -Token $Token
    if (! $ObjectInfo) {
     [pscustomobject]@{Name="NOT FOUND Role $($_.roleDefinitionId) | Scope $($_.directoryScopeID) | principalId $($_.principalId) ";Type="NOT FOUND"}
    } else {
     [pscustomobject]@{Name=$($ObjectInfo.DisplayName);Type=$($ObjectInfo.Type)}
    }
   }
  }},
  @{name="PrincipalInfo";expression={($PrincipalInfo[$PrincipalInfo.id.indexof($_.principalId)])} } | Select-Object -ExcludeProperty directoryScopeInfo,PrincipalInfo *,
  @{name="directoryScopeName";expression={$_.directoryScopeInfo.Name}},
  @{name="directoryScopeType";expression={$_.directoryScopeInfo.Type}},
  @{name="principalName";expression={$_.PrincipalInfo.DisplayName}},
  @{name="principalType";expression={$_.PrincipalInfo.Type}},
  @{name="Type";expression={
   if ($_.SourceID -eq "roleEligibilityScheduleInstances") {
    'Eligible'
   } elseif ($_.assignmentType -eq 'Activated') {
    'Permanent Activated'
   } elseif (($_.SourceID -eq "roleAssignmentScheduleInstances") -and $_.endDateTime) {
    'Time Limited Permanent'
   } else {
    'Permanent'
   }
  }
 }

 if ($HideGUID) {
  $Result = $Result | Select-Object -ExcludeProperty *ID
 }
 $Result
}
Function Get-AzureADUserAssignedRole { # Get Role Assignement from ObjectID - Missing Eligible
 Param (
  $UserObjectID
 )
 # If object is empty return nothing (does not work if the param is set to mandatory)
 if (! $UserObjectID) {return}
 (az rest --method GET --uri "https://graph.microsoft.com/v1.0/rolemanagement/directory/roleAssignments?`$filter=principalId eq '$UserObjectID'" --header Content-Type=application/json | ConvertFrom-Json).value | Select-Object directoryScopeId,principalId,roleDefinitionId
}
Function Get-AzureRoleDefinitions { # Get all data but requires Service Principal with proper rights to get the values
 Param (
  [parameter(Mandatory = $true)]$Token
 )
 $Result = Get-AzureGraph -Token $Token -GraphRequest "/roleManagement/directory/roleDefinitions"
 $Result.value | select-object id, displayName,description,templateId,isBuiltIn,isEnabled
}
Function Get-AzureRoleAssignements { # Get all Azure Roles Assignements
 Param (
  [parameter(Mandatory = $true)]$Token
 )

 $headers = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }

 $FullResult = @()
 $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$top=999"
 $FullResult += $CurrentResult.value
 While ($CurrentResult.'@odata.nextLink') {
  $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri $CurrentResult.'@odata.nextLink'
  $FullResult += $CurrentResult.value
 }
 $FullResult | Select-Object *,@{name="SourceID";expression={"roleAssignmentScheduleInstances"}}
}
Function Get-AzureRoleAssignementsEligible { # Get all Azure Eligible Roles
 Param (
  [parameter(Mandatory = $true)]$Token
 )

 $headers = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }

 $FullResult = @()
 $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$top=999"
 $FullResult += $CurrentResult.value
 While ($CurrentResult.'@odata.nextLink') {
  $CurrentResult = Invoke-RestMethod -Method GET -headers $headers -Uri $CurrentResult.'@odata.nextLink'
  $FullResult += $CurrentResult.value
 }
 $FullResult | Select-Object *,@{name="SourceID";expression={"roleEligibilityScheduleInstances"}}
}
Function Get-AzureAdministrativeUnit {
 Param (
  [parameter(Mandatory = $true)]$Token
 )
 $Result = Get-AzureGraph -Token $Token -GraphRequest "/directory/administrativeUnits?`$top=999"
 $Result.value | select-object * -ExcludeProperty deletedDateTime,isMemberManagementRestricted,visibility
}
Function Add-AzureRole {
 Param (
  [parameter(Mandatory = $true)]$Token,
  [Parameter(Mandatory=$true,ParameterSetName="ID")]$GroupID,
  [Parameter(Mandatory=$true,ParameterSetName="ID")]$RoleTemplateID,
  [Parameter(Mandatory=$true,ParameterSetName="ID")]$DirectoryScope,
  [Parameter(Mandatory=$true,ParameterSetName="Name")]$GroupName,
  [Parameter(Mandatory=$true,ParameterSetName="Name")]$RoleName,
  [Parameter(Mandatory=$true,ParameterSetName="Name")]$AdminUnitName

 )

 try {

 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { throw "Token is invalid, provide a valid token" }

 $BearerToken = $Token.access_token

 $Header = @{
  'Content-Type'  = "application\json"
  'Authorization' = "Bearer $BearerToken"
 }

 if ($GroupName) {
  # Get Group ID
  $GroupIDRequest = Invoke-RestMethod -Method GET -headers $Header -Uri "https://graph.microsoft.com/v1.0/Groups?`$count=true&`$select=id&`$filter=displayName eq '$GroupName'"
  $GroupID = $GroupIDRequest.Value.ID

  # Get Role ID
  $RoleTemplateIDRequest = (Invoke-RestMethod -Method GET -headers $Header -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$RoleName'")
  $RoleTemplateID = $RoleTemplateIDRequest.Value.templateId
 }

 if (($AdminUnitName -eq "/") -or ($DirectoryScope -eq "/") ) {
  $DirectoryScope = '/'
 } else {
  if ($AdminUnitName) {
   # Get Scope
   $DirectoryScopeRequest = Invoke-RestMethod -Method GET -headers $Header -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$filter=displayName eq '$AdminUnitName'"
   $DirectoryScope = '/administrativeUnits/' +  $DirectoryScopeRequest.value.id
  }
 }

 if (! $GroupID) { throw "Group ID not found"}
 if (! $DirectoryScope) { throw "Incorrect DirectoryScope"}
 if (! $RoleTemplateID) { throw "Role not found"}

 $CMDParams = @{
   "URI"         = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
   "Headers"     = $Header
   "Method"      = "POST"
   "ContentType" = 'application/json'
   "Body" = (@{
    'odata.type' = "#microsoft.graph.unifiedRoleAssignment"
    "principalId" = "$GroupID"
    "roleDefinitionId" =  "$RoleTemplateID"
    "directoryScopeId" = "$DirectoryScope"
   }) | ConvertTo-JSON -Depth 6
  }
  # $CMDParams ;  return
  $Result = Invoke-RestMethod @CMDParams
  $Result.Value | select-object id, displayName,description,templateId,isBuiltIn,isEnabled
 } catch {
  Write-host -ForegroundColor Red "Error Adding Role ($($Error[0]))"
 }
}
# Devices
Function Get-AzureDeviceObjectIDFromName {
 param(
  [parameter(Mandatory=$true)][String]$DeviceName,
  [parameter(Mandatory=$true)]$Token
 )
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
 $headers = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }
 $RequestURL = "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$DeviceName'&`$select=id,deviceId,displayName"
 $Result = (Invoke-RestMethod -Method GET -headers $headers -Uri $RequestURL)
 if ($Result.Value) {
  return $Result.Value
 } else {
  Write-host -ForegroundColor Red "Device $DeviceName not found"
 }
}

# Administrative Unit Management
Function Get-AzureADAdministrativeUnit { # Get all Administrative Units with associated Data
 Param (
  $Filter,
  $Token
 )
 if ($Token) {
  (get-AzureGraph -Token $token -GraphRequest "/directory/administrativeUnits$Filter" -Method GET).value
 } else {
  (az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits$Filter" --header Content-Type=application/json | ConvertFrom-Json).value | Select-Object displayName,id,description,membershipType,membershipRule | Sort-Object DisplayName
 }
}
# Schema Extensions
Function Get-AzureADExtension { # Extract all schema extension of Azure AD
 #How to filter by Type :
 # ($result | ? targetTypes -Contains "user").count
 # ($result | ? targetTypes -Contains "Group").count
 # ($result | ? targetTypes -Contains "Message").count
 # $CurrentResult = az rest --method GET --uri "https://graph.microsoft.com/v1.0/schemaExtensions" --header Content-Type="application/json" -o json | convertfrom-json
 $CurrentResult = az rest --method GET --uri '"https://graph.microsoft.com/v1.0/schemaExtensions?$top=999"' --header Content-Type="application/json" -o json | convertfrom-json
 $CurrentResult.Value | Select-Object ID,description,targettypes,status,owner
 While ($CurrentResult.'@odata.nextLink') {
  $NextRequest = "`""+$CurrentResult.'@odata.nextLink'+"`""
  $CurrentResult = az rest --method GET --uri $NextRequest --header Content-Type="application/json" -o json | convertfrom-json
  $CurrentResult.Value | Select-Object ID,description,targettypes,status,owner
 }
}
# Defender for Cloud (MDC)
Function Get-MDCConfiguration { # Retrieve Microsoft Defender For Cloud (MDC) configuration for all Subscriptions of current Tenant (uses AzCli rest API Access) | EXAMPLE FOR UNKNOWN NUMBER OF VALUES IN TABLE
 $APIVersion = "2024-01-01"
 $GlobalResult = $()
 $Subscriptions = Get-AzureSubscriptions
 #Variable to follow up the columns without having to rebuild the entire object (Otherwise export-csv only export columns depending on the first object created)
 $MemberList = $('id','name','SubscriptionName','SubscriptionID','pricingTier','EnabledOn')
 $Subscriptions | ForEach-Object {
  $SubscriptionName = $_.Name
  $SubscriptionID = $_.ID
  Progress -PrintTime -Message "Checking subscription " -Value "$($_.ID) ($($_.Name))"

  # Export all information of MDC in current subscription
  $Result = (az rest --method GET --uri "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Security/pricings?api-version=$APIVersion"  `
   --headers "Content-Type=application/json" | ConvertFrom-Json).Value `
   | Select-Object id,Name,
   @{Name="SubscriptionName";Expression={$SubscriptionName}},
   @{Name="SubscriptionID";Expression={$SubscriptionID}},
   @{Name="pricingTier";Expression={$_.properties.pricingTier}},
   @{Name="subPlan";Expression={$_.properties.subPlan}},
   @{Name="EnabledOn";Expression={$_.properties.enablementTime}},
   @{Name="Extensions";Expression={$_.properties.Extensions}},
   @{Name="additionalExtensionProperties";Expression={$_.properties.Extensions.additionalExtensionProperties}}

   # Convert Extension and Additional Extension content to additional columns built from the current Extension being used
   $Result | ForEach-Object {
   for ($ExtensionCount = 0; $ExtensionCount -le $($_.Extensions.count-1); $ExtensionCount++) {
    $ExtensionName = "EXT_" + $_.Extensions.Name[$ExtensionCount]
    $ExtensionValue = $_.Extensions.IsEnabled[$ExtensionCount]
    $ExtensionAdditionalProperties = $_.additionalExtensionProperties[$ExtensionCount]
    $MemberList+=$ExtensionName
    $_ | Add-Member -NotePropertyName $ExtensionName -NotePropertyValue $ExtensionValue
    if ($ExtensionAdditionalProperties) {
     $AdditionalPropertiesName = ($ExtensionAdditionalProperties | get-member -MemberType NoteProperty).Name
     $AdditionalPropertiesValue = $ExtensionAdditionalProperties.$AdditionalPropertiesName
     $_ | Add-Member -NotePropertyName $($ExtensionName+$AdditionalPropertiesName) -NotePropertyValue $AdditionalPropertiesValue
     $MemberList+=$($ExtensionName+$AdditionalPropertiesName)
    }
   }
  }
  $GlobalResult+=$Result
 }
 # Remove duplicate values
 $MemberList = $MemberList | Select-Object -Unique
 ProgressClear
 $GlobalResult | Select-Object $MemberList | Export-Csv "$iClic_TempPath\MDCConfiguration_$([DateTime]::Now.ToString("yyyyMMdd")).csv"
}
Function Enable-MDCDefaults { # Enable Microsoft Defender for Cloud (MDC)
 Param (
  [Parameter(Mandatory=$true)]$SubscriptionID,
  [Switch]$EnableVMProtection, # Does not set it by default until we have a clear view of the impact
  $APIVersion = "2024-01-01"
 )
 $BaseURL = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Security/pricings"
 if ($EnableVMProtection) {
 # VirtualMachines
  $Body = '{\"properties\":{\"extensions\":[{\"isEnabled\":\"False\",\"name\":\"MdeDesignatedSubscription\"},{\"additionalExtensionProperties\":{\"ExclusionTags\":\"[]\"},\"isEnabled\":\"True\",\"name\":\"AgentlessVmScanning\"}],\"pricingTier\":\"Standard\",\"subPlan\":\"P2\"}"}'
  az rest --method PUT --uri "$BaseURL/VirtualMachines?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 }
 # SqlServers
 $Body = '{\"properties\":{\"pricingTier\":\"Standard\"}}'
 az rest --method PUT --uri "$BaseURL/SqlServers?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # AppServices
 $Body = '{\"properties\":{\"pricingTier\":\"Standard\"}}'
 az rest --method PUT --uri "$BaseURL/AppServices?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # StorageAccounts
 $Body = '{\"properties\":{\"extensions\":[{\"name\":\"OnUploadMalwareScanning\",\"isEnabled\":\"False\",},{\"name\":\"SensitiveDataDiscovery\",\"isEnabled\":\"True\"}],\"subPlan\":\"DefenderForStorageV2\",\"pricingTier\":\"Standard\"}}'
 az rest --method PUT --uri "$BaseURL/StorageAccounts?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # SqlServerVirtualMachines
 $Body = '{\"properties\":{\"pricingTier\":\"Standard\"}}'
 az rest --method PUT --uri "$BaseURL/SqlServerVirtualMachines?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # KubernetesService
 $Body = '{\"properties\":{\"pricingTier\":\"Free\",\"isEnabled\":\"False\"}}'
 az rest --method PUT --uri "$BaseURL/KubernetesService?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # ContainerRegistry
 $Body = '{\"properties\":{\"pricingTier\":\"Free\",\"isEnabled\":\"False\"}}'
 az rest --method PUT --uri "$BaseURL/ContainerRegistry?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # Keyvaults
 $body = '{\"name\":\"KeyVaults\",\"properties\":{\"pricingTier\":\"Standard\",\"subPlan\":\"PerKeyVault\"} }'
 az rest --method PUT --uri "$BaseURL/Keyvaults?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # Dns
 $Body = '{\"properties\":{\"pricingTier\":\"Free\",\"isEnabled\":\"False\"}}'
 az rest --method PUT --uri "$BaseURL/Dns?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # Arm
 $Body='{\"properties\":{\"pricingTier\":\"Standard\",\"subPlan\":\"PerSubscription\"}}'
 az rest --method PUT --uri "$BaseURL/Arm?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # OpenSourceRelationalDatabases
 $Body = '{\"properties\":{\"pricingTier\":\"Standard\"}}'
 az rest --method PUT --uri "$BaseURL/OpenSourceRelationalDatabases/?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # CosmosDbs
 $Body = '{\"properties\":{\"pricingTier\":\"Standard\"}}'
 az rest --method PUT --uri "$BaseURL/CosmosDbs?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # Containers (Updated on 2025-04-01)
 $Body='{\"name\":\"Containers\",\"properties\":{\"extensions\":[{\"isEnabled\":\"True\",\"name\":\"ContainerRegistriesVulnerabilityAssessments\"},{ \"isEnabled\": \"True\", \"name\": \"ContainerSensor\"},{\"isEnabled\": \"True\",\"name\": \"ContainerIntegrityContribution\"}],\"pricingTier\":\"Standard\"},\"type\":\"Microsoft.Security/pricings\"}}'
 az rest --method PUT --uri "$BaseURL/Containers?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # CloudPosture (CSPM) (Updated on 2025-04-01)
 $Body='{\"properties\":{\"extensions\":[{\"isEnabled\":\"True\",\"name\":\"SensitiveDataDiscovery\"},{\"isEnabled\":\"True\",\"name\":\"ContainerRegistriesVulnerabilityAssessments\"},{\"isEnabled\":\"True\",\"name\":\"AgentlessDiscoveryForKubernetes\"},{\"additionalExtensionProperties\":{\"ExclusionTags\":\"[]\"},\"isEnabled\":\"True\",\"name\":\"AgentlessVmScanning\"},{ \"isEnabled\": \"True\",\"name\": \"ApiPosture\"}],\"pricingTier\":\"Standard\"}}'
 az rest --method PUT --uri "$BaseURL/CloudPosture?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
 # Api
 $Body = '{\"properties\":{\"pricingTier\":\"Free\"}}'
 az rest --method PUT --uri "$BaseURL/Api?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
# AI (Updated on 2025-04-01)
 $Body = '{\"properties\":{\"extensions\": [ {\"isEnabled\": \"True\", \"name\": \"AIPromptEvidence\" }, { \"isEnabled\": \"False\", \"name\": \"AIPromptSharingWithPurview\" }],\"freeTrialRemainingTime\": \"P29DT22H11M\",\"pricingTier\": \"Standard\", \"resourcesCoverageStatus\": \"FullyCovered\"}}'
 az rest --method PUT --uri "$BaseURL/AI?api-version=$APIVersion" --headers "Content-Type=application/json" --body $body
}
# DevOps
Function Get-ADOUsers { # Get All Azure DevOps Users
 # This needs to be setup first : az devops configure -d organization=ORG_URL
 (az devops user list --top 1000 -o json | convertfrom-json).Members | Select-Object dateCreated,lastAccessedDate,
  @{Name="DisplayName";Expression={$_.User.displayName}},
  @{Name="principalName";Expression={$_.User.principalName}},
  @{Name="mailAddress";Expression={$_.User.mailAddress}},
  @{Name="Origin";Expression={$_.User.Origin}},
  @{Name="UserType";Expression={$_.User.metaType}},
  @{Name="License";Expression={$_.accessLevel.licenseDisplayName}},
  @{Name="LicenseSource";Expression={$_.accessLevel.licensingSource}},
  @{Name="LicenseAssignementSource";Expression={$_.accessLevel.assignmentSource}},
  @{Name="LicenseStatus";Expression={$_.accessLevel.status}},
  @{Name="DescriptorID";Expression={$_.User.Descriptor}} | Export-Csv "$iClic_TempPath\AzureDevOpsUsers_$([DateTime]::Now.ToString("yyyyMMdd")).csv" -Append
}
Function Get-ADOPermissions_Groups { # Project Level Permission Only
 Param (
  $ProjectName
 )
 # Get all project list
 if ($ProjectName) {
  $AzureDevopsProjectList = (az devops project show -p "$ProjectName" | convertfrom-json).Name
 } else {
  $AzureDevopsProjectList = ((az devops project list -o json | convertfrom-json).value).Name | Sort-Object
 }
 # Get all permission name and ID
 $AzureDevopsProjectList | ForEach-Object {
  $ProjectRealName = $_
  $ProjectName = $ProjectRealName -replace " - ","-" -replace "- ","_" -replace "--","-" -replace " ","_"
  $GroupList = (az devops security group list --project $_ -o json | convertfrom-json).graphGroups
  $GroupList | Select-Object `
   @{Name="ProjectRealName";Expression={Progress -Message "Checking Project : " -Value $ProjectRealName -PrintTime ; $ProjectRealName}},
   @{Name="ProjectName";Expression={$ProjectName}},
   @{Name="PermissionName";Expression={$_.displayName}},
   @{Name="PermissionID";Expression={$_.descriptor}},origin,isCrossProject,subjectKind,
   @{Name="AADGroupCount";Expression={($GroupList | Where-Object origin -eq "aad").Count}}
 }
}
Function Get-ADOProjectMembers { # Get all members of a Project (it lists only Groups AAD & ADO)
 Param (
  [Parameter(Mandatory)]$ProjectName,
  $Filter,
  [Switch]$ShowAll
 )
 $Result = (az devops security group list --project $ProjectName | convertfrom-json).graphGroups  | Sort-Object displayName
 if ($Filter) {
  $Result = $Result | Where-Object displayname -like "$Filter"
 }
 if ($ShowAll) {
  $Result
 } else {
  $Result | Select-Object displayName,principalName,origin,subjectKind,originId,descriptor
 }
}
Function Get-ADOGroupMembers { # Get all members of a Azure DevOps Group (Requires Group Descriptor in Azure DevOps)
 Param (
  [Parameter(Mandatory)]$GroupDescriptor,
  [Switch]$ShowAll
 )
 # az devops security group membership list --id $GroupDescriptor --relationship members
 $Result = (az devops security group membership list --id $GroupDescriptor --relationship members | ConvertFrom-Json -AsHashtable).values | ConvertTo-Json | convertfrom-json | Sort-Object displayName
 if ($ShowAll) {
  $Result
 } else {
  $Result | Select-Object displayName,principalName,origin,subjectKind,originId,descriptor
 }
}
Function Get-ADO_AuthenticationHeader { # Convert Azure DevOps PAT Token to usable Header Object
 Param (
  [Parameter(Mandatory)]$PersonalAccessToken
 )
 $token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($PersonalAccessToken)"))
 $header = @{authorization = "Basic $token"}
 return $header
}
Function Get-ADO_Request { # Check documentation of API here : https://learn.microsoft.com/en-us/rest/api/azure/devops
 Param (
  [Parameter(Mandatory)]$RequestURI, # Example : projects
  $BaseURI="https://dev.azure.com/", # For DevOps Graph the URL is : https://vssps.dev.azure.com/
  [Parameter(Mandatory)]$Header,
  [Parameter(Mandatory)]$Organization,
  $AmountOfReturnValues = '1000' # Max 1000
 )

# Examples :
# Users on Organization Level :
# $Users = (Get-ADO_Request -RequestURI "graph/users" -Header $header -Organization 'OrgName' -BaseURI "https://vssps.dev.azure.com/")
# Groups on Organization level :
# $Groups = (Get-ADO_Request -RequestURI "graph/groups" -Header $header -Organization 'OrgName' -BaseURI "https://vssps.dev.azure.com/")


 $FullResult = @()
 $URI = $BaseURI + $Organization + "/_apis/" + $RequestURI
 $Result = Invoke-WebRequest -Uri $Uri -Method Get -ContentType "application/json" -Headers $header
 $FullResult += ($Result.Content | ConvertFrom-Json).Value
 $ContinuationToken = $Result.headers.'x-ms-continuationtoken'
 while ($ContinuationToken) {
  $ContinuationUri = $URI + "?continuationToken=" + $ContinuationToken
  $Result = Invoke-WebRequest -Uri $ContinuationUri -Method Get -ContentType "application/json" -Headers $header
  $FullResult += ($Result.Content | ConvertFrom-Json).Value
  $ContinuationToken = $Result.headers.'x-ms-continuationtoken'
 }
 $FullResult
}
Function Get-ADOProjectList {
 ((az devops project list -o json | convertfrom-json).value).Name | Sort-Object
}
Function Get-ADORepositoryList {
 Param (
  [Parameter(Mandatory)]$ProjectName
 )
 az repos list --project "Cloud Team" -o json | convertfrom-json | Sort-Object Name | Select-Object name,@{N="Size";E={Format-Filesize $_.Size}},remoteUrl
}
# MFA
Function Get-AzureADUserMFA { # Extract all MFA Data for all users (Graph Loop - Fast) - seems to give about 1000 response per loop - Added a Restart on Throttle/Fail
 Param (
  $Throttle = 10, # Time in Seconds to wait in case of throttle
  $ExportFileName = "$iClic_TempPath\Global_AzureAD_MFA_Status_$([DateTime]::Now.ToString("yyyyMMdd")).csv",
  [Parameter(Mandatory)]$Token
 )

 # Doc here : https://learn.microsoft.com/en-us/graph/api/resources/userRegistrationDetails?view=graph-rest-1.0&preserve-view=true

 # Init Variables
 $Count=0
 $GlobalResult = @()
 $ContinueRunning = $True
 $FirstRun=$True

 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }

 $header = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }

 While ($ContinueRunning) {
  Progress -Message "Getting all MFA Status of Users Loop $Count : " -Value $GlobalResult.Count -PrintTime
  Try {
   if ($FirstRun) {
    $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails" -MaximumRetryCount 2
    $FirstRun=$False
   } else {
     $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri $NextRequest -MaximumRetryCount 2
   }
   $NextRequest = $CurrentResult.'@odata.nextLink'
   if ($NextRequest) {$ContinueRunning = $True} else {$ContinueRunning = $False}
   $Count++
   $GlobalResult += $CurrentResult.Value | Select-Object *,
    @{Name="MFA_Method_softwareOneTimePasscode";Expression={$_.methodsRegistered -contains 'softwareOneTimePasscode'}},
    @{Name="MFA_Method_temporaryAccessPass";Expression={$_.methodsRegistered -contains 'temporaryAccessPass'}},
    @{Name="MFA_Method_email";Expression={$_.methodsRegistered -contains 'email'}},
    @{Name="MFA_Method_officePhone";Expression={$_.methodsRegistered -contains 'officePhone'}},
    @{Name="MFA_Method_mobilePhone";Expression={$_.methodsRegistered -contains 'mobilePhone'}},
    @{Name="MFA_Method_alternateMobilePhone";Expression={$_.methodsRegistered -contains 'alternateMobilePhone'}},
    @{Name="MFA_Method_windowsHelloForBusiness";Expression={$_.methodsRegistered -contains 'windowsHelloForBusiness'}},
    @{Name="MFA_Method_passKeyDeviceBound";Expression={$_.methodsRegistered -contains 'passKeyDeviceBound'}},
    @{Name="MFA_Method_passKeyDeviceBoundAuthenticator";Expression={$_.methodsRegistered -contains 'passKeyDeviceBoundAuthenticator'}},
    @{Name="MFA_Method_securityQuestion";Expression={$_.methodsRegistered -contains 'securityQuestion'}},
    @{Name="MFA_Method_microsoftAuthenticatorPush";Expression={$_.methodsRegistered -contains 'microsoftAuthenticatorPush'}},
    @{Name="MFA_Method_microsoftAuthenticatorPasswordless";Expression={$_.methodsRegistered -contains 'microsoftAuthenticatorPasswordless'}}
  } catch {
   $ErrorInfo = $Error[0]
   if ( $ErrorInfo.Exception.StatusCode -eq "TooManyRequests") {
    Start-Sleep -Seconds $Throttle ; write-host " Being throttled waiting $Throttle`s"
   } else {
    Write-Error "$($ErrorInfo.Message) ($($ErrorInfo.StatusCode))"
   }
  }
 }
 $GlobalResult | Export-CSV $ExportFileName
 Write-Blank
 Return $ExportFileName
}
Function Add-AzureADUserMFAPhone { # Add phone number as a method for users
 Param (
  [parameter(Mandatory = $true)]$Token, # Access Token retrieved with Get-AzureGraphAPIToken
  [parameter(Mandatory = $true)]$PhoneNumber,
  [parameter(Mandatory = $true)]$User # can be UPN or GUID
 )

 Try {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Throw "Token is invalid, provide a valid token"
  }

  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

  $params = @{
   phoneNumber = $PhoneNumber
   phoneType = "mobile"
  }

  $GraphURL = "https://graph.microsoft.com/v1.0/users/$User/authentication/phoneMethods/"

  # Add check if user is found and / exists
  # Add check if value already exists

  $ParamJson = $params | convertto-json

  $Result = Invoke-RestMethod -Method POST -headers $header -Uri $GraphURL -Body $ParamJson

  if (! $Result) {
   Throw "Error during apply of update"
  }
 } catch {
  $Exception = $($Error[0])
  $StatusCode = ($Exception.ErrorDetails.message | ConvertFrom-json).error.code
  $StatusMessage = ($Exception.ErrorDetails.message | ConvertFrom-json).error.message
  Write-host -ForegroundColor Red "Error adding MFA Method $PhoneNumber of user $User ($StatusCode | $StatusMessage))"
 }
}
Function Get-AzureADUserMFADeviceBoundAAGUID {
 Param (
  [parameter(Mandatory = $true)]$Token, # Access Token retrieved with Get-AzureGraphAPIToken
  [parameter(Mandatory = $true)]$InputFile # Must contain be an output of Get-AzureADUserMFA
 )
 Try {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Throw "Token is invalid, provide a valid token"
  }

  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

  $usermfa = Import-csv $InputFile | Where-Object { $_.MFA_Method_passKeyDeviceBound -eq "True" }

 $aaGuidList = $usermfa | ForEach-Object {
  Progress -Message "Current Users " -PrintTime -Value $_.userDisplayName
  (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$($_.id)/authentication/fido2Methods").value | Select-Object -ExcludeProperty id
 }
 $aaGuidList | Group-Object aaGuid
} catch {
 $Exception = $($Error[0])
 $StatusCode = ($Exception.ErrorDetails.message | ConvertFrom-json).error.code
 $StatusMessage = ($Exception.ErrorDetails.message | ConvertFrom-json).error.message
 Write-host -ForegroundColor Red "Error $StatusCode | $StatusMessage"
}
}
Function Get-AzureADUserMFAMethods { # Check MFA Methods
 Param (
  [parameter(Mandatory = $true)]$Token, # Access Token retrieved with Get-AzureGraphAPIToken
  [parameter(Mandatory = $true)]$UPNorID, # can be UPN or GUID
  [ValidateSet("methods","emailMethods","fido2Methods","microsoftAuthenticatorMethods","passwordMethods","phoneMethods","softwareOathMethods",
  "temporaryAccessPassMethods","windowsHelloForBusinessMethods")]$Method = "methods", # Getting details from a specific Methods is about twice faster than the generic | Methods gets all methods
  [switch]$SkipTokenValidation # To make request faster
 )
 Try {
  if (! $SkipTokenValidation) {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }
  }

  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

  $GraphURL = "https://graph.microsoft.com/v1.0/users/$UPNorID/authentication/$Method"

  $Result = Invoke-RestMethod -Method GET -headers $header -Uri $GraphURL -MaximumRetryCount 2

  if (! $Result) {
   Throw "No result from Invoke-RestMethod"
  } else {
   $Result.Value
  }
 } catch {
  $Exception = $($Error[0])
  if ($Exception.ErrorDetails.message) {
   $StatusCode = ($Exception.ErrorDetails.message | ConvertFrom-json).error.code
   $StatusMessage = ($Exception.ErrorDetails.message | ConvertFrom-json).error.message
   Write-Error -Message "Error checking MFA Methods information for user $UPNorID (Method : $Method) ($StatusCode | $StatusMessage))"
  } else {
   Write-Error -Message "Error checking MFA Methods information for user $UPNorID (Method : $Method) ($Exception))"
  }
 }
}
Function Remove-AzureADUserMFAMethods { # Remove MFA Methods
 Param (
  [parameter(Mandatory = $true)]$Token, # Access Token retrieved with Get-AzureGraphAPIToken
  [parameter(Mandatory = $true)]$UPNorID, # can be UPN or GUID
  [parameter(Mandatory = $true)]$MethodID, # can be UPN or GUID
  [ValidateSet("methods","emailMethods","fido2Methods","microsoftAuthenticatorMethods","passwordMethods","phoneMethods","softwareOathMethods",
  "temporaryAccessPassMethods","windowsHelloForBusinessMethods")]$Method = "methods", # Getting details from a specific Methods is about twice faster than the generic | Methods gets all methods
  [switch]$SkipTokenValidation # To make request faster
 )
 Try {
  if (! $SkipTokenValidation) {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }
  }

  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

  $GraphURL = "https://graph.microsoft.com/v1.0/users/$UPNorID/authentication/$Method/$MethodID"

  Invoke-RestMethod -Method DELETE -headers $header -Uri $GraphURL

 } catch {
  $Exception = $($Error[0])
  if ($Exception.ErrorDetails.message) {
   $StatusCode = ($Exception.ErrorDetails.message | ConvertFrom-json).error.code
   $StatusMessage = ($Exception.ErrorDetails.message | ConvertFrom-json).error.message
   Write-Host -ForegroundColor Red -Message "Error Deleting MFA Methods information for user $UPNorID ($StatusCode | $StatusMessage))"
  } else {
   Write-Host -ForegroundColor Red -Message "Error Deleting MFA Methods information for user $UPNorID ($($Error[0])))"
  }
 }
}
Function Set-AzureADUserMFADefaultMethod { # Change Default Method for authentication (will work only if method is available in systemPreferredAuthenticationMethod endpoint)
 Param (
  [Parameter(Mandatory)]$UPNorID,
  [Parameter(Mandatory)][ValidateSet("push", "oath", "voiceMobile", "voiceAlternateMobile", "voiceOffice", "sms", "none", "unknownFutureValue")]$Method,
  [Parameter(Mandatory)]$Token
 )
 Try {
  if (Assert-IsGUID $UPNorID) {$UserGUID = $UPNorID}
  if ($UserGUID) { Write-Verbose "Working with GUID" } else {
   Write-Verbose "Working with UPN, will be slower"
   $UserGUID = (get-azureaduserInfo -UPNorID $UPNorID -Token $Token).id
  }
  if (! $UserGUID) {
   Write-Host -ForegroundColor Red "User $UPNorID not found" ; Return
  }
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Throw "Token is invalid, provide a valid token"
  }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

  $params = @{
   "userPreferredMethodForSecondaryAuthentication" = $Method
  }

  $ParamJson = $params | convertto-json
  Invoke-RestMethod -Method PATCH -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID/authentication/signInPreferences" -Body $ParamJson
 } catch {
  $Exception = $($Error[0])
  $StatusCodeJson = $Exception.ErrorDetails.message
  if ($StatusCodeJson) { $StatusCode = ($StatusCodeJson| ConvertFrom-json).error.code }
  $StatusMessageJson = $Exception.ErrorDetails.message
  if ($StatusMessageJson) { $StatusMessage = ($StatusMessageJson | ConvertFrom-json).error.message }
  if ((! $StatusMessageJson) -and (!$StatusCodeJson ) ) { $StatusCode = "Catch Error" ; $StatusMessage = $($Error[0])}
  Write-host -ForegroundColor Red "Error setting default MFA Method for user $UPNorID ($StatusCode | $StatusMessage))"
 }
}
Function Get-AzureADUserMFADefaultMethod { # Get Default Method for authentication
 Param (
  [Parameter(Mandatory)]$UPNorID,
  [Parameter(Mandatory)]$Token
 )
 Try {
  if (Assert-IsGUID $UPNorID) {$UserGUID = $UPNorID}
  if ($UserGUID) { Write-Verbose "Working with GUID" } else {
   Write-Verbose "Working with UPN, will be slower"
   $UserGUID = (get-azureaduserInfo -UPNorID $UPNorID -Token $Token).id
  }
  if (! $UserGUID) {
   Throw "User $UPNorID not found"
  }
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Throw "Token is invalid, provide a valid token"
  }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

 Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID/authentication/signInPreferences" | Select-Object -ExcludeProperty '@odata.context'
 } catch {
  $Exception = $($Error[0])
  $StatusCodeJson = $Exception.ErrorDetails.message
  if ($StatusCodeJson) { $StatusCode = ($StatusCodeJson| ConvertFrom-json).error.code }
  $StatusMessageJson = $Exception.ErrorDetails.message
  if ($StatusMessageJson) { $StatusMessage = ($StatusMessageJson | ConvertFrom-json).error.message }
  if ((! $StatusMessageJson) -and (!$StatusCodeJson ) ) { $StatusCode = "Catch Error" ; $StatusMessage = $($Error[0])}
  Write-host -ForegroundColor Red "Error getting default MFA Method for user $UPNorID ($StatusCode | $StatusMessage))"
 }
}

# AAD Group Management
Function Assert-IsAADUserInAADGroup { # Check if a User is in a AAD Group (Not required to have exact username) - Switch for ObjectID ID for faster result
 Param (
  [Parameter(Mandatory=$true)]$UserName,
  [Parameter(Mandatory=$true)]$Group,
  $Token
 )
 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { Write-Error "Token is invalid, provide a valid token" ; return } else {
   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }
  }
  if ( (! (Assert-IsGUID $Group)) -or (! (Assert-IsGUID $UserName)) ) { Write-host "When using graph GUID is mandatory" ; return }
  $Result = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/users/$UserName/memberof/$Group"
  if ($Result.id -eq $Group) { return $True } else { return $False }
 } else {
  if (Assert-IsGUID $Group) {
   (az ad group member check --group $Group --member-id $UserName -o json --only-show-errors | ConvertFrom-Json).Value
  } else {
   (az ad group member check --group $Group --member-id (Get-AzureUserStartingWith $UserName).ID -o json --only-show-errors | ConvertFrom-Json).Value
  }
 }
}
Function Get-AzureADGroupMembers { # Get Members from a Azure Ad Group (Using AzCli) - Before beta it did not list Service principals
 Param (
  [Parameter(Mandatory)]$Group,
  [Switch]$Recurse,
  [Switch]$ForceName,
  [Switch]$RecurseHideGroups, # Using recursive still shows groups by default, but using this switch they will be hidden
  [Switch]$Fast,
  $Token
 )

 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Write-Error "Token is invalid, provide a valid token"
   return
  }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
 } else {
  if (! $(Assert-IsCommandAvailable "Az")) {
   Write-Error "Missing Az Module"
   Return
  }
 }

 if (Assert-IsGUID $Group) {
  $GroupGUID = $Group
  if ($ForceName) {
   if ($Token) {
    $GroupName = (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/groups/$Group").displayName
   } else {
    $GroupName = (az ad group show -g $Group | convertfrom-json).displayname
   }
  } else {
   $GroupName = $Group
  }
 } else {

  if ($Token) {
   $GroupGUID = (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayname,'$Group')").value.id
  } else {
   $GroupGUID = (az ad group show -g $Group | convertfrom-json).id
  }
  $GroupName = $Group
 }

 if ($Recurse) {
  $SearchType = "transitiveMembers"
 } else {
  $SearchType = "members"
 }

 $FirstRun = $True
 $ContinueRunning = $True
 While ($ContinueRunning) { # Run until there are results
  if ($FirstRun) {
   if ($Token) {
    if ($Fast) {
     $GraphURL = "https://graph.microsoft.com/beta/groups/$GroupGUID/$SearchType`?`$top=999&`$select=userPrincipalName,id"
    } else {
     $GraphURL = "https://graph.microsoft.com/beta/groups/$GroupGUID/$SearchType`?`$top=999"
    }
    $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri $GraphURL
   } else {
    $GraphURL = '"https://graph.microsoft.com/beta/groups/"'+$GroupGUID+'"/"'+$SearchType+'"?$top=999"'
    $CurrentResult = az rest --method get --uri $GraphURL --headers "Content-Type=application/json" | ConvertFrom-Json
   }
   $FirstRun=$False
  } else {
   if ($Token) {
    $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri $NextRequest -MaximumRetryCount 2
   } else {
    $ResultJson = az rest --method get --uri $NextRequest --header Content-Type="application/json" -o json 2>&1
    # Add error management for API limitation of Azure
    $CurrentResult = $ResultJson | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | convertfrom-json
    $ErrorMessage = $ResultJson | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
    If (($ErrorMessage -and ($ErrorMessage -notlike "*Unable to encode the output with cp1252 encoding*"))) {
     Write-Host -ForegroundColor "Red" -Object "Detected Error ($ErrorMessage) ; Restart Current Loop after a 10s sleep"
     Start-Sleep 10
     Continue
    }
   }
  }
  if ($RecurseHideGroups) {
    $CurrentResult.Value = $CurrentResult.Value | Where-Object '@odata.type' -ne '#microsoft.graph.group'
  }
  if ($Token) {
   $NextRequest = $CurrentResult.'@odata.nextLink'
  } else {
   $NextRequest = "`""+$CurrentResult.'@odata.nextLink'+"`""
  }
  if ($CurrentResult.'@odata.nextLink') {$ContinueRunning = $True} else {$ContinueRunning = $False}
  $CurrentResult.Value | Sort-Object displayName | Select-Object @{Name="GroupID";Expression={$GroupGUID}},@{Name="GroupName";Expression={$GroupName}},userPrincipalName, displayName, mail,
   accountEnabled, userType, id, onPremisesSyncEnabled, onPremisesExtensionAttributes,@{Name="Type";Expression={($_.'@odata.type'.split("."))[-1]}}, createdDateTime, employeeHireDate, employeeLeaveDateTime
 }
}
Function Get-AzureADGroupIDFromName {
 Param (
  [Parameter(Mandatory)]$GroupName,
  $Token
 )
 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Write-Error "Token is invalid, provide a valid token"
   return
  }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
  (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/Groups?`$count=true&`$select=id&`$filter=displayName eq '$GroupName'").value.id
 } else {
  (az rest --method GET --uri "https://graph.microsoft.com/v1.0/Groups?`$count=true&`$select=id&`$filter=displayName eq '$GroupName'" --headers Content-Type=application/json | ConvertFrom-Json).Value.id
 }
}
Function Get-AzureADGroups { # Get all groups (with members), works with wildcard - Startswith (Using AzCli)
 Param (
  [Parameter(Mandatory)]$GroupName,
  [Switch]$ShowMembers,
  [Switch]$ShowAppRoles,
  [Switch]$ShowMemberOf,
  [Switch]$ExcludeDynamicGroups,
  $DoNotExpandGroups, # Used to avoid checking members of some groups, this must be an object like @("Group1","Group2")
  $Token
 )

 Try {
  if (Assert-IsGUID $GroupName) { Throw "GroupName must be a name not a GUID as this is a search function" }
  if ($Token) {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { Throw "Token is invalid, provide a valid token" }
   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }
   $GroupList = @()
   $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayname,'$GroupName')" -MaximumRetryCount 2
   $GroupList += $CurrentResult.Value
   while ($CurrentResult.'@odata.nextLink') {
    $CurrentResult = $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri $CurrentResult.'@odata.nextLink' -MaximumRetryCount 2
    $GroupList += $CurrentResult.Value
   }
   if ($ShowAppRoles) {
    $GroupWithRoles = @()
    $GroupList | ForEach-Object {
     $AppRoles = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/groups/$($_.ID)/appRoleAssignments" -MaximumRetryCount 2
     $_ | Add-Member -MemberType "NoteProperty" -Name "AppRoles" -Value $AppRoles.value.resourceDisplayName
     $GroupWithRoles += $_
    }
    $GroupList = $GroupWithRoles
   }
   if ($ShowMemberOf) {
    $GroupWithRoles = @()
    $GroupList | ForEach-Object {
     $memberOf = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/groups/$($_.ID)/memberOf" -MaximumRetryCount 2
     $_ | Add-Member -MemberType "NoteProperty" -Name "memberOf" -Value $($memberOf.value | Select-Object id,displayName)
     $GroupWithRoles += $_
    }
    $GroupList = $GroupWithRoles
   }
  } else { # If not using Tokens, simpler function (additional Switches are not available)
   $GroupList = az ad group list --filter "startswith(displayName, '$GroupName')" -o json | ConvertFrom-Json
  }

  # Exclude Dynamic Groups if requested
  if ($ExcludeDynamicGroups) { $GroupList = $GroupList | Where-Object {! $_.membershipRule}  }

  $Result = $GroupList |`
   Select-Object displayName,description,@{Name="GroupID";Expression={$_.Id}},
   @{Name="Type";Expression={
    if ($_.membershipRule -and ($_.membershipRuleProcessingState -ne 'Paused')) {"Dynamic"} else {"Fixed"}
   }},
    membershipRule,mailEnabled,securityEnabled,isAssignableToRole,onPremisesSyncEnabled,AppRoles,memberOf

  if (! $ShowAppRoles) { $Result = $Result | Select-Object -ExcludeProperty AppRoles }
  if (! $ShowMemberOf) { $Result = $Result | Select-Object -ExcludeProperty memberOf }

  if ($ShowMembers) {
   $Result | Select-Object *,@{Name="Members";Expression={
    if ($_.displayName -NotIn $DoNotExpandGroups) {
     if ($Token) {
      Get-AzureADGroupMembers -Group $($_.GroupID) -Recurse -RecurseHideGroups -ForceName -Token $Token
     } else {
      Get-AzureADGroupMembers -Group $($_.GroupID) -Recurse -RecurseHideGroups -ForceName
     }
    }
   }}
  } else {
   $Result
  }
 } Catch {
  Write-Error "Error getting groups ($($Error[0]))"
 }


}
Function Remove-AzureADGroupMember { # Remove Member from group (Using AzCli) or Rest if token is provided
 Param (
  [Parameter(Mandatory)]$GroupName,
  [Parameter(Mandatory)]$UPNorID,
  $Token
 )
 Try {
  if ($Token) {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }
   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }
  }

  # Get user GUID if not provided
  if (Assert-IsGUID $UPNorID) {
   $UserGUID = $UPNorID
  } else {
   if ($Token) {
    $UserGUID = (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users?`$count=true&`$select=id&`$filter=userPrincipalName eq '$UPNorID'").Value.Id
   } else {
    $UserGUID = (az rest --method GET --uri "https://graph.microsoft.com/beta/users?`$count=true&`$select=id&`$filter=userPrincipalName eq '$UPNorID'" --headers Content-Type=application/json | ConvertFrom-Json).Value.Id
   }
  }

  # Get Group GUID if not provided
  if (Assert-IsGUID $GroupName) {
   $GroupGUID = $GroupName
  } else {
   if ($Token) {
    $GroupGUID = (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayname eq '$GroupName'").Value.ID
   } else {
    $GroupGUID = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayname eq '$GroupName'" --headers Content-Type=application/json | ConvertFrom-Json).Value.Id
   }
  }

  if ($Token) {
   Invoke-RestMethod -Method DELETE -headers $header -Uri "https://graph.microsoft.com/v1.0/groups/$GroupGUID/members/$UserGUID/`$ref"
  } else {
   az ad group member remove --group $GroupGUID --member-id $UserGUID
  }
 } catch {
  $Exception = $($Error[0])
  $StatusCodeJson = $Exception.ErrorDetails.message
  if ($StatusCodeJson) { $StatusCode = ($StatusCodeJson| ConvertFrom-json).error.code }
  $StatusMessageJson = $Exception.ErrorDetails.message
  if ($StatusMessageJson) { $StatusMessage = ($StatusMessageJson | ConvertFrom-json).error.message }
  if ((! $StatusMessageJson) -and (!$StatusCodeJson ) ) { $StatusCode = "Catch Error" ; $StatusMessage = $($Error[0])}
  Write-host -ForegroundColor Red "Error removing user $UPNorID from group $GroupName ($StatusCode | $StatusMessage))"
 }
}
Function Remove-AzureADGroupOwner { # Remove Owner from group using Rest
 Param (
  [Parameter(Mandatory)]$GroupID,
  [Parameter(Mandatory)]$UserID,
  [Parameter(Mandatory)]$Token
 )
 Try {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Throw "Token is invalid, provide a valid token"
  }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
  Invoke-RestMethod -Method DELETE -headers $header -Uri "https://graph.microsoft.com/v1.0/groups/$GroupID/owners/$UserID/`$ref"

 } catch {
  $Exception = $($Error[0])
  $StatusCodeJson = $Exception.ErrorDetails.message
  if ($StatusCodeJson) { $StatusCode = ($StatusCodeJson| ConvertFrom-json).error.code }
  $StatusMessageJson = $Exception.ErrorDetails.message
  if ($StatusMessageJson) { $StatusMessage = ($StatusMessageJson | ConvertFrom-json).error.message }
  if ((! $StatusMessageJson) -and (!$StatusCodeJson ) ) { $StatusCode = "Catch Error" ; $StatusMessage = $($Error[0])}
  Write-host -ForegroundColor Red "Error removing user $UPNorID from group $GroupName ($StatusCode | $StatusMessage))"
 }
}
Function Add-AzureADGroupMember { # Add Member from group (Using AzCli or token)
 Param (
  [Parameter(Mandatory)]$GroupName,
  [Parameter(Mandatory)]$UPNorID,
  $Token
 )
 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Write-Error "Token is invalid, provide a valid token"
   return
  } else {
   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }
  }
 }

 if (Assert-IsGUID $UPNorID) {
  $UserGUID = $UPNorID
 } else {
  if ($Token) {
   $UserGUID = (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users?`$count=true&`$select=id&`$filter=userPrincipalName eq '$UPNorID'").Value.Id
  } else {
   $UserGUID = (az rest --method GET --uri "https://graph.microsoft.com/beta/users?`$count=true&`$select=id&`$filter=userPrincipalName eq '$UPNorID'" --headers Content-Type=application/json | ConvertFrom-Json).Value.Id
  }
 }

 if (Assert-IsGUID $GroupName) {
  $GroupGUID = $GroupName
 } else {
  if ($Token) {
   $GroupGUID = (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayname eq '$GroupName'").Value.Id
  } else {
   $GroupGUID = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayname eq '$GroupName'" --headers Content-Type=application/json | ConvertFrom-Json).Value.Id
  }
 }
 if ($Token) {
  Try {
   $params = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$UserGUID" }
   $ParamJson = $params | convertto-json
   Invoke-RestMethod -Method POST -headers $header -Uri "https://graph.microsoft.com/v1.0/groups/$GroupGUID/members/`$ref"  -Body $ParamJson
  } catch {
   $Exception = $($Error[0])
   $StatusCodeJson = $Exception.ErrorDetails.message
   if ($StatusCodeJson) { $StatusCode = ($StatusCodeJson| ConvertFrom-json).error.code }
   $StatusMessageJson = $Exception.ErrorDetails.message
   if ($StatusMessageJson) { $StatusMessage = ($StatusMessageJson | ConvertFrom-json).error.message }
   if ((! $StatusMessageJson) -and (!$StatusCodeJson ) ) { $StatusCode = "Catch Error" ; $StatusMessage = $($Error[0])}
   Write-host -ForegroundColor Red "Error adding user $UPNorID in group $GroupName ($StatusCode | $StatusMessage))"
  }
 } else {
  # Confirm that this works with GUID
  # az ad group member add --group $GroupName --member-id $UserGUID
  az ad group member add --group $GroupGUID --member-id $UserGUID
 }
}
Function Copy-AzureADGroupMembers {
 Param (
  [Parameter(Mandatory)]$SourceGroupName,
  [Parameter(Mandatory)]$DestinationGroupName
 )
 Get-AzureADGroupMembers -Group $SourceGroupName | ForEach-Object {
  Add-AzureADGroupMember -GroupName $DestinationGroupName -UPNorID $_.id
 }
}
Function Remove-AzureADDisabledUsersFromGroups { # Remove disabled users from Groups
 Param (
  [Parameter(Mandatory)]$GroupPrefix,
  [switch]$PrintOnly
 )
 $GroupList = Get-AzureADGroups -Group $GroupPrefix -ShowMembers -ExcludeDynamicGroups
 $Result = $GroupList |
  `Select-Object -ExpandProperty members @{Name="GroupName";Expression={$_.displayName}} -ErrorAction SilentlyContinue |
  `Where-Object {! $_.accountEnabled} |
  `Where-Object userPrincipalName |
  `Select-Object userPrincipalName,displayName,accountEnabled,GroupName,id -ErrorAction SilentlyContinue

 if ($($Result.Count) -eq 0) {
  Write-Host -Foregroundcolor Green "No disabled user found in groups starting with $GroupPrefix, nothing to do in $($GroupList.Count) groups"
 } else {
  write-host "Found $($Result.Count) disabled account in group $GroupPrefix*"
  if ($PrintOnly) {
   $Result
  } else {
   $QuestionResult = Question "Are you sure you want to remove the users from their respective Groups"
   if ($QuestionResult) {
    $Result | ForEach-Object {
     Write-Host "Removing user $($_.displayName) ($($_.userPrincipalName)) from group $($_.GroupName)"
     az ad group member remove --group $_.GroupName --member-id $_.id
    }
   }
  }
 }
}
Function New-AzureADGroup { # Create New Group using Graph
 Param (
  [Parameter(Mandatory)]$Token,
  [Parameter(Mandatory)]$GroupName,
  [Parameter(Mandatory)]$GroupDescription,
  [Switch]$SecurityEnabled,
  [Switch]$MailEnabled,
  [Switch]$Unified,
  [Switch]$Dynamic,
  [Switch]$isAssignableToRole,
  $membershipRule,
  $mailNickname
 )
 Try {

  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { Throw "Token is invalid, provide a valid token" }

  if (! $mailNickname) { $mailNickname = $GroupName }
  if ($Unified) {
   if ($Dynamic) {
    $GroupType = '["Unified","DynamicMembership"]'
   } else {
    $GroupType = '["Unified"]'
   }
  } else {
   if ($Dynamic) {
    $GroupType = '["DynamicMembership"]'
   } else {
    $GroupType = @()
   }
  }

  $params = @{
   description = $GroupDescription
   displayName = $GroupName
   groupTypes = $GroupType
   mailNickname = $mailNickname
  }

  if ($MailEnabled) { $params.mailEnabled = $true } else { $params.mailEnabled = $false }
  if ($SecurityEnabled) { $params.securityEnabled = $true } else { $params.securityEnabled = $false }
  if ($isAssignableToRole) { $params.isAssignableToRole = $true } else { $params.isAssignableToRole = $false }

  if ($membershipRule) {
   $params.membershipRule = $membershipRule
   $params.membershipRuleProcessingState = "On"
  }

  $ParamJSON = $params | ConvertTo-Json


  $headers = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

  $GraphURL = 'https://graph.microsoft.com/v1.0/groups/'

  Invoke-RestMethod -Method POST -headers $headers -Uri $GraphURL -Body $ParamJson
 } catch {
  Write-host -ForegroundColor Red "Error Creating Group $GroupName ($($Error[0]))"
 }
}
# AAD User Management
Function Get-AzureADUsers { # Get all AAD User of a Tenant (limited info or full info)
 Param (
  [parameter(Mandatory = $false, ParameterSetName="Advanced")][Switch]$Advanced,
  [parameter(Mandatory = $false, ParameterSetName="Graph")][Switch]$Graph,
  $ExportFileName = "$iClic_TempPath\Global_AzureAD_Users_Status_$([DateTime]::Now.ToString("yyyyMMdd")).csv",
  $Throttle = 2,
  $Token,
  [Switch]$NoFileExport,
  [Switch]$HideProgress
 )
 # Get list of all AAD users (takes some minutes with 50k+ users)
 if ($Advanced) {
  az ad user list --query '[].{userPrincipalName:userPrincipalName,displayName:displayName,mail:mail}' --output json --only-show-errors | ConvertFrom-Json
 } elseif ($Graph) {
  Try {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }
   # To Add License check
   $SKUList = Get-AzureSKUs -Token $Token

   # Init Variables
   $Count=0
   $GlobalResult = @()
   $FirstRun = $True
   $ContinueRunning = $True

   While ($ContinueRunning) {
    if (! $HideProgress) {
     Progress -Message "Getting all User Status Loop $Count : " -Value $GlobalResult.Count -PrintTime
    }
    if ($FirstRun) {
     $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users?`$top=999&`$select=id,userPrincipalName,
     displayName,mail,companyName,onPremisesImmutableId,accountEnabled,createdDateTime,onPremisesSyncEnabled,preferredLanguage,userType,signInActivity,
     creationType,onPremisesExtensionAttributes,assignedLicenses,employeeHireDate,employeeLeaveDateTime,lastPasswordChangeDateTime"
     $FirstRun=$False
    } else {
     $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri $NextRequest
    }
    $NextRequest = $CurrentResult.'@odata.nextLink'
    if ($NextRequest) {$ContinueRunning = $True} else {$ContinueRunning = $False}
    $Count++
    $GlobalResult += $CurrentResult.Value | select-object -ExcludeProperty signInActivity,onPremisesImmutableId,onPremisesExtensionAttributes,assignedLicenses,onPremisesSyncEnabled *,
    @{name="Local_GUID";expression={if ($_.onPremisesImmutableId) {Convert-ImmutableIDToGUID $_.onPremisesImmutableId} else {"None"}}},
     @{name="lastSignInDateTime";expression={$_.signInActivity.lastSignInDateTime}},
     @{name="lastNonInteractiveSignInDateTime";expression={$_.signInActivity.lastNonInteractiveSignInDateTime}},
     @{name="lastSuccessfulSignInDateTime";expression={$_.signInActivity.lastSuccessfulSignInDateTime}},
     @{name="onPremisesSyncEnabled";expression={
      if ($_.onPremisesSyncEnabled -eq "True") { # To avoid empty values of OnPremSync
       "True"
      } else {
       "False"
      }
     }},
     @{name="extensionAttribute1";expression={$_.onPremisesExtensionAttributes.extensionAttribute1}},
     @{name="extensionAttribute2";expression={$_.onPremisesExtensionAttributes.extensionAttribute2}},
     @{name="extensionAttribute3";expression={$_.onPremisesExtensionAttributes.extensionAttribute3}},
     @{name="extensionAttribute4";expression={$_.onPremisesExtensionAttributes.extensionAttribute4}},
     @{name="extensionAttribute5";expression={$_.onPremisesExtensionAttributes.extensionAttribute5}},
     @{name="extensionAttribute6";expression={$_.onPremisesExtensionAttributes.extensionAttribute6}},
     @{name="extensionAttribute7";expression={$_.onPremisesExtensionAttributes.extensionAttribute7}},
     @{name="extensionAttribute8";expression={$_.onPremisesExtensionAttributes.extensionAttribute8}},
     @{name="extensionAttribute9";expression={$_.onPremisesExtensionAttributes.extensionAttribute9}},
     @{name="extensionAttribute10";expression={$_.onPremisesExtensionAttributes.extensionAttribute10}},
     @{name="extensionAttribute11";expression={$_.onPremisesExtensionAttributes.extensionAttribute11}},
     @{name="extensionAttribute12";expression={$_.onPremisesExtensionAttributes.extensionAttribute12}},
     @{name="extensionAttribute13";expression={$_.onPremisesExtensionAttributes.extensionAttribute13}},
     @{name="extensionAttribute14";expression={$_.onPremisesExtensionAttributes.extensionAttribute14}},
     @{name="extensionAttribute15";expression={$_.onPremisesExtensionAttributes.extensionAttribute15}},
     @{name="License";expression={(($_.assignedLicenses | ForEach-Object { ($SKUList[$SKUList.skuId.indexof($_.skuid)]).skuPartNumber}) | Sort-Object ) -join "," }}
   }
  } catch {
   $ErrorInfo = $Error[0]
   if ( $ErrorInfo.Exception.StatusCode -eq "TooManyRequests") {
    Start-Sleep -Seconds $Throttle ; write-host "Being throttled waiting $Throttle`s"
   } else {
    Write-Error "$($ErrorInfo.Message) ($($ErrorInfo.StatusCode))"
   }
  }
  if ($NoFileExport) {
   return $GlobalResult
  } else {
   $GlobalResult | Export-CSV $ExportFileName
   Write-Blank
   return $ExportFileName
  }
 } else { # When launched without param
  az ad user list --query '[].{userPrincipalName:userPrincipalName,displayName:displayName,accountEnabled:accountEnabled,dirSyncEnabled:dirSyncEnabled,createdDateTime:createdDateTime,creationType:creationType,mail:mail,userType:userType}' --output json --only-show-errors | convertfrom-json
 }
}
Function Get-AzureADUserInfo { # Show user information From AAD (Uses Graph Beta for Detailed to get all default values, to get specific value they must be specifically selected, like signInActivity)
 Param (
  [Parameter(Mandatory)]$UPNorID,
  [Switch]$Detailed,
  [Switch]$ShowManager,
  [Switch]$ShowMemberOf,
  [Switch]$ShowOwnedObjects,
  [Switch]$ShowOwnedDevices,
  $Token
 )

 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
 }

 if (Assert-IsGUID $UPNorID) {
  $UserGUID = $UPNorID
 } else {
  if ($Token) {
   $UserGUID = (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users?`$count=true&`$select=id&`$filter=userPrincipalName eq '$UPNorID'").value.id
  } else {
   $UserGUID = (az rest --method GET --uri "https://graph.microsoft.com/beta/users?`$count=true&`$select=id&`$filter=userPrincipalName eq '$UPNorID'" --headers Content-Type=application/json | ConvertFrom-Json).Value.Id
  }
 }
 if (! $UserGUID) { Write-Host -ForegroundColor "Red" -Object "User $UPNorID was not found" ; Return}
 if ($Detailed) { # Version v1.0 of graph is really limited with the values it returns
  if ($Token) {
   $Result = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$UPNorID" -MaximumRetryCount 2
  } else {
   $Result = az rest --method GET --uri "https://graph.microsoft.com/beta/users/$UPNorID" --headers Content-Type=application/json | ConvertFrom-Json
  }
 } else {
  $Filter = "id,onPremisesImmutableId,userPrincipalName,displayName,mail,accountEnabled,createdDateTime,signInActivity,lastPasswordChangeDateTime"
  if ($Token) {
   $RestResult = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID`?`$select=$Filter" -MaximumRetryCount 2
  } else {
   $RestResult = az rest --method GET --uri "https://graph.microsoft.com/beta/users/$UserGUID`?`$select=$Filter" --headers Content-Type=application/json | ConvertFrom-Json
  }
  $Result = $RestResult | Select-Object `
  id,onPremisesImmutableId,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,
  @{name="lastSignInDateTime";expression={$_.signInActivity.lastSignInDateTime}},
  @{name="lastNonInteractiveSignInDateTime";expression={$_.signInActivity.lastNonInteractiveSignInDateTime}},
  @{name="lastSuccessfulSignInDateTime";expression={$_.signInActivity.lastSuccessfulSignInDateTime}},lastPasswordChangeDateTime
 }
 if ($ShowManager) {
  if ($Token) {
   $ManagerJson = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID/manager"
  } else {
   $ManagerJson = az rest --method GET --uri "https://graph.microsoft.com/beta/users/$UserGUID/manager" --headers Content-Type=application/json | ConvertFrom-Json
  }
  $Manager = $ManagerJson | Select-Object `
    @{name="ManagerdisplayName";expression={$_.displayName}},
    @{name="ManagerUPN";expression={$_.userPrincipalName}},
    @{name="ManagerMail";expression={$_.mail}}
  $Result | Add-Member -NotePropertyName ManagerdisplayName -NotePropertyValue $Manager.ManagerdisplayName
  $Result | Add-Member -NotePropertyName ManagerUPN -NotePropertyValue $Manager.ManagerUPN
  $Result | Add-Member -NotePropertyName ManagerMail -NotePropertyValue $Manager.ManagerMail
 }
 if ($ShowOwnedObjects) {
  if ($Token) { # This my limit to the first 100 objects
   $OwnedObjects = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID/ownedObjects"
  } else {
   $OwnedObjects = az rest --method GET --uri "https://graph.microsoft.com/beta/users/$UserGUID/ownedObjects" --headers Content-Type=application/json | ConvertFrom-Json
  }
  $Result | Add-Member -NotePropertyName OwnedObjects -NotePropertyValue $OwnedObjects
 }
 if ($ShowOwnedDevices) {
  if ($Token) { # This my limit to the first 100 objects
   $OwnedDevices = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID/OwnedDevices"
  } else {
   $OwnedDevices = az rest --method GET --uri "https://graph.microsoft.com/beta/users/$UserGUID/OwnedDevices" --headers Content-Type=application/json | ConvertFrom-Json
  }
  $Result | Add-Member -NotePropertyName OwnedDevices -NotePropertyValue $OwnedDevices
 }
 if ($ShowMemberOf) {
  $MemberOf=@()
  if ($Token) { # This my limit to the first 100 objects
   $MemberOfTmp = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID/memberOf"
   $MemberOf += $MemberOfTmp.Value
   While ($MemberOfTmp.'@odata.nextLink') {
    $MemberOf += $MemberOfTmp.Value
    $MemberOfTmp = az rest --method get --uri $MemberOfTmp.'@odata.nextLink' --header Content-Type="application/json" -o json | convertfrom-json
   }

  } else {
   $MemberOfTmp = az rest --method GET --uri "https://graph.microsoft.com/beta/users/$UserGUID/memberOf" --headers Content-Type=application/json | ConvertFrom-Json
   $MemberOf += $MemberOfTmp.Value
   While ($MemberOfTmp.'@odata.nextLink') {
    $MemberOf += $MemberOfTmp.Value
    $MemberOfTmp = az rest --method get --uri $MemberOfTmp.'@odata.nextLink' --header Content-Type="application/json" -o json | convertfrom-json
   }
  }
  $MemberOfFinal = $MemberOf | Select-Object id,displayName,@{name="Type";expression={
   if (($_.'@odata.type' -eq '#microsoft.graph.group') -and ($_.securityEnabled) -and ($_.onPremisesSyncEnabled)) {
    "AD_SecurityGroup"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.group') -and (! $_.securityEnabled) -and ($_.onPremisesSyncEnabled)) {
    "AD_Group"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.administrativeUnit') -and ($_.membershipType -eq 'Dynamic') ) {
    "AdminUnit_Dynamic"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.administrativeUnit') -and ($_.membershipType -ne 'Dynamic') ) {
    "AdminUnit_Fixed"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.group') -and ($_.groupTypes -contains 'DynamicMembership') -and ($_.securityEnabled) -and (! $_.onPremisesSyncEnabled)) {
    "Entra_Dynamic_SecurityGroup"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.group') -and ($_.groupTypes -Contains 'DynamicMembership') -and (! $_.securityEnabled) -and (! $_.onPremisesSyncEnabled)) {
    "Entra_Dynamic_Group"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.group') -and ($_.groupTypes -contains 'Unified') -and ($_.securityEnabled) -and (! $_.onPremisesSyncEnabled)) {
    "Entra_Unified_SecurityGroup"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.group') -and ($_.groupTypes -contains 'Unified') -and (! $_.securityEnabled) -and (! $_.onPremisesSyncEnabled)) {
    "Entra_Unified_Group"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.group') -and ($_.securityEnabled) -and (! $_.onPremisesSyncEnabled)) {
    "Entra_Security_Group"
   } elseif (($_.'@odata.type' -eq '#microsoft.graph.group') -and (! $_.securityEnabled) -and (! $_.onPremisesSyncEnabled)) {
    "Entra_Group"
   }
  }}
  $Result | Add-Member -NotePropertyName MemberOf -NotePropertyValue $MemberOfFinal
 }
 $Result
}
Function Get-AzureUserStartingWith { # Get all AAD Users starting with something
 param (
  [Parameter(Mandatory=$true)]$SearchValue,
  [ValidateSet("displayName","userPrincipalName")]$Type = "displayName"
 )
 az ad user list --query '[].{objectId:id,displayName:displayName,userPrincipalName:userPrincipalName}' --filter "startswith($Type, `'$SearchValue`')" -o json --only-show-errors | ConvertFrom-Json
}
Function Get-AzureADUserCustomAttributes { # Show user information From O365
 Param (
  [Parameter(Mandatory)]$UPN
 )
 #Check if a session is already opened otherwise open it
 if (!((Get-ConnectionInformation).State -eq "Connected")) { Connect-ExchangeOnline }

 Get-EXORecipient -Identity $UPN -PropertySets Custom
}
Function Set-AzureADManager { # Set Manager on User in Azure
 Param (
  [Parameter(Mandatory)]$UserID,
  [Parameter(Mandatory)]$ManagerID
 )
 $ManagerOdataObject = @{
  "@odata.id"="https://graph.microsoft.com/v1.0/users/$ManagerID"
 }
 Set-MgUserManagerByRef -UserId $UserID -BodyParameter $ManagerOdataObject
}
Function Set-AzureADUserExtensionAttribute { # Set Extension Attribute on Cloud Only Users ; For Exchange use the Exchange Module and the cmdline : Set-Mailbox -Identity $_.id -CustomAttribute10 "Value"
 Param (
  [Parameter(Mandatory)]$UPNorID,
  [Parameter(Mandatory)][Int32][ValidateRange(1,12)]$ExtensionAttributeNumber,
  [Parameter(Mandatory)]$Value,
  [Switch]$ShowResult,
  $Token
 )
 if (Assert-IsGUID $UPNorID) {$UserGUID = $UPNorID}
 if ($UserGUID) { Write-Verbose "Working with GUID" } else {
  Write-Verbose "Working with UPN, will be slower"
  if ($Token) {
   $UserGUID = (get-azureaduserInfo -UPNorID $UPNorID -Token $Token).id
  } else {
   $UserGUID = (get-azureaduserInfo -UPNorID $UPNorID).id
  }
 }

 if (! $UserGUID) {
  Write-Host -ForegroundColor Red "User $UPNorID not found"
  Return
 }

 if ($Token) {
  Try {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }
   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }

   $params = @{
    "onPremisesExtensionAttributes" = @{
     $("extensionAttribute"+$ExtensionAttributeNumber) = $Value
    }
   }

   $ParamJson = $params | convertto-json
   Invoke-RestMethod -Method PATCH -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID"  -Body $ParamJson | Out-Null
   if ($ShowResult) {
    $ExtensionAttributeName = $("extensionAttribute"+$ExtensionAttributeNumber)
    Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users/$UserGUID" | Select-Object displayName,userPrincipalName,
     @{name="extensionAttribute";expression={$_.onPremisesExtensionAttributes.$ExtensionAttributeName}}
   }
  } catch {
   $Exception = $($Error[0])
   $StatusCodeJson = $Exception.ErrorDetails.message
   if ($StatusCodeJson) { $StatusCode = ($StatusCodeJson| ConvertFrom-json).error.code }
   $StatusMessageJson = $Exception.ErrorDetails.message
   if ($StatusMessageJson) { $StatusMessage = ($StatusMessageJson | ConvertFrom-json).error.message }
   if ((! $StatusMessageJson) -and (!$StatusCodeJson ) ) { $StatusCode = "Catch Error" ; $StatusMessage = $($Error[0])}
   Write-host -ForegroundColor Red "Error setting extension attribute $ExtensionAttributeNumber for user $UPNorID ($StatusCode | $StatusMessage))"
  }
 } else {
  $Body = '{\"onPremisesExtensionAttributes\": {\"extensionAttribute'+$ExtensionAttributeNumber+'\": \"'+$Value+'\"}}'
  az rest --method PATCH --uri "https://graph.microsoft.com/beta/users/$UserGUID/" --headers Content-Type=application/json --body $body
  if ($ShowResult) {
   (az rest --method GET --uri "https://graph.microsoft.com/beta/users/$UserGUID/" --headers Content-Type=application/json | ConvertFrom-Json).onPremisesExtensionAttributes
  }
 }
}
Function Set-AzureADUserDisablePasswordExpiration { # Set Disable password Expiration on Azure AD Account
 Param (
  [Parameter(Mandatory)]$UPNorID,
  [Parameter(Mandatory)]$Token
 )
 Try {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Throw "Token is invalid, provide a valid token"
  }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

  $params = @{
   "passwordPolicies" = "DisablePasswordExpiration"
  }

  $ParamJson = $params | convertto-json
  Invoke-RestMethod -Method PATCH -headers $header -Uri "https://graph.microsoft.com/beta/users/$UPNorID"  -Body $ParamJson | Out-Null
 } catch {
  $Exception = $($Error[0])
  $StatusCodeJson = $Exception.ErrorDetails.message
  if ($StatusCodeJson) { $StatusCode = ($StatusCodeJson| ConvertFrom-json).error.code }
  $StatusMessageJson = $Exception.ErrorDetails.message
  if ($StatusMessageJson) { $StatusMessage = ($StatusMessageJson | ConvertFrom-json).error.message }
  if ((! $StatusMessageJson) -and (!$StatusCodeJson ) ) { $StatusCode = "Catch Error" ; $StatusMessage = $($Error[0])}
  Write-host -ForegroundColor Red "Error setting Password Never Expires for user $UPNorID ($StatusCode | $StatusMessage))"
 }
}
Function Set-AzureDeviceExtensionAttribute { # Same as User but with the updates for Devices vs Users
 Param (
  [Parameter(Mandatory)][GUID]$DeviceObjectID,
  [Parameter(Mandatory)][Int32][ValidateRange(1,12)]$ExtensionAttributeNumber,
  [Parameter(Mandatory)]$Value,
  [Parameter(Mandatory)]$Token,
  [Switch]$ShowResult
 )
  Try {
   if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
    Throw "Token is invalid, provide a valid token"
   }
   $header = @{
    'Authorization' = "$($Token.token_type) $($Token.access_token)"
    'Content-type'  = "application/json"
   }

   $params = @{
    "extensionAttributes" = @{
     $("extensionAttribute"+$ExtensionAttributeNumber) = $Value
    }
   }

   $ParamJson = $params | convertto-json
   Invoke-RestMethod -Method PATCH -headers $header -Uri "https://graph.microsoft.com/v1.0/devices/$DeviceObjectID"  -Body $ParamJson | Out-Null
   if ($ShowResult) {
    $ExtensionAttributeName = $("extensionAttribute"+$ExtensionAttributeNumber)
    Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/devices/$DeviceObjectID" | Select-Object displayName,userPrincipalName,
     @{name="extensionAttribute";expression={$_.onPremisesExtensionAttributes.$ExtensionAttributeName}}
   }
  } catch {
   $Exception = $($Error[0])
   $StatusCodeJson = $Exception.ErrorDetails.message
   if ($StatusCodeJson) { $StatusCode = ($StatusCodeJson| ConvertFrom-json).error.code }
   $StatusMessageJson = $Exception.ErrorDetails.message
   if ($StatusMessageJson) { $StatusMessage = ($StatusMessageJson | ConvertFrom-json).error.message }
   if ((! $StatusMessageJson) -and (!$StatusCodeJson ) ) { $StatusCode = "Catch Error $($Error[0].TargetObject)" ; $StatusMessage = $($Error[0])}
   Write-host -ForegroundColor Red "Error setting extension attribute $ExtensionAttributeNumber for Device $DeviceObjectID ($StatusCode | $StatusMessage))"
  }
}
Function Get-AzureADRiskyUsers { # Can only get 500 users at the time
 Param (
  [Parameter(Mandatory)]$Token
 )
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { throw "Token is invalid, provide a valid token" }

 # Set Header
 $header = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }

 $UserList = @()
 $Count = 0
 $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/identityProtection/riskyUsers?`$top=500&`$filter=riskState eq 'atRisk'"
 $UserList += $CurrentResult.Value
 while ($CurrentResult.'@odata.nextLink') {
  $Count++
  Progress -Message "Looping through result Loop : " -Value $Count
  $CurrentResult = $CurrentResult = Invoke-RestMethod -Method GET -headers $header -Uri $CurrentResult.'@odata.nextLink' -MaximumRetryCount 2
  $UserList += $CurrentResult.Value
 }
 $UserList
}
Function Confirm-AzureADRiskyUser {
 Param (
  [Parameter(Mandatory)]$Token,
  [Parameter(Mandatory)]$UserList # Array of user Object ID
 )
 Try {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
   Throw "Token is invalid, provide a valid token"
  }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }

 $UserListOject = @{}
 $UserListOject.userIds = $UserList
 $UserListJson = $UserListOject | ConvertTo-Json

 Invoke-RestMethod -Method POST -headers $header -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss" -Body $UserListJson | Out-Null
 } catch {
  Write-host -ForegroundColor Red "Error during  Azure AD Risky Users Removal ($($Error[0]))"
 }
}
Function Disable-AzureADUser { # Set Extension Attribute on Cloud Only Users
 Param (
  [Parameter(Mandatory)]$UPNorID,
  [Switch]$ShowResult
 )
 if (Assert-IsGUID $UPNorID) {$UserGUID = $UPNorID}
 if ($UserGUID) { Write-Verbose "Working with GUID" } else {
  Write-Verbose "Working with UPN, will be slower"
  $UserGUID = (get-azureaduserInfo -UPNorID $UPNorID).id
 }

 if (! $UserGUID) {
  Write-Host -ForegroundColor Red "User $UPNorID not found"
  Return
 }

 $Body = '{\"accountEnabled\": \"false\"}}'
 az rest --method PATCH --uri "https://graph.microsoft.com/beta/users/$UserGUID/" --headers Content-Type=application/json --body $body
 if ($ShowResult) {
  (az rest --method GET --uri "https://graph.microsoft.com/beta/users/$UserGUID/" --headers Content-Type=application/json | ConvertFrom-Json).onPremisesExtensionAttributes
 }
}
Function Get-AzureADUserAppRoleAssignments { # Get all Application Assigned to a user in Azure
 Param (
  [Parameter(Mandatory)]$UPNorID,
  $Token
 )

 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
 }

 if (Assert-IsGUID $UPNorID) {
  $UserGUID = $UPNorID
 } else {
  if ($Token) {
   $UserGUID = (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/beta/users?`$count=true&`$select=id&`$filter=userPrincipalName eq '$UPNorID'").value.id
  } else {
   $UserGUID = (az rest --method GET --uri "https://graph.microsoft.com/beta/users?`$count=true&`$select=id&`$filter=userPrincipalName eq '$UPNorID'" --headers Content-Type=application/json | ConvertFrom-Json).Value.Id
  }
 }

 if (! $UserGUID) { Write-Host -ForegroundColor "Red" -Object "User $UPNorID was not found" ; Return}

 if ($Token) {
  $RestResult = Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/users/$UserGUID/appRoleAssignments"
 } else {
  $RestResult = az rest --method GET --uri "https://graph.microsoft.com/v1.0/users/$UserGUID/appRoleAssignments" --headers Content-Type=application/json | ConvertFrom-Json
 }
 $RestResult
}
# Token Management
Function Get-AzureGraphAPIToken { # Generate Graph API Token, Works with App Reg with Secret or CertificateThumbprint on user device (personal cert) or interractive (No External Modules needed)
 [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
 Param (
  # --- Common Parameters for All Sets ---

  # This parameter is mandatory for all three authentication methods.
  [parameter(Mandatory = $True, ParameterSetName="ClientSecret")]
  [parameter(Mandatory = $True, ParameterSetName="Certificate")]
  [parameter(Mandatory = $True, ParameterSetName="Interactive")]
  $TenantID,

  # This parameter is optional for all sets and defaults to the Azure CLI's public App ID.
  [parameter(Mandatory = $False, ParameterSetName="ClientSecret")]
  [parameter(Mandatory = $False, ParameterSetName="Certificate")]
  [parameter(Mandatory = $False, ParameterSetName="Interactive")]
  $ApplicationID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46", # Azure CLI's Public App ID

  # Optional resource parameter, available to all sets /.default is the modern recommended scope.
  [parameter(Mandatory = $False)]$Scope = "https://graph.microsoft.com/.default",

  # --- Parameters for Specific Auth Sets ---

  # This parameter is mandatory ONLY for the 'ClientSecret' set.
  [parameter(Mandatory = $True, ParameterSetName="ClientSecret")]$ClientKey,

  # This parameter is mandatory ONLY for the 'Certificate' set. Thumbprint must be in the local user certificate store
  [parameter(Mandatory = $True, ParameterSetName="Certificate")]$CertificateThumbprint,

  # This switch activates the 'Interactive' parameter set.
  [parameter(Mandatory = $True, ParameterSetName="Interactive")][switch]$Interactive
 )

 try {
  # --- Endpoint and Body setup based on Parameter Set ---
  $tokenResponse = $null
  $tokenEndpoint = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

  if ($PSCmdlet.ParameterSetName -in @("ClientSecret", "Certificate")) {
   # Client Credentials flow for non-interactive methods
   $Body = @{
    grant_type = 'client_credentials'
    client_id  = $ApplicationID
    scope   = $Scope
   }

   if ($PSCmdlet.ParameterSetName -eq "ClientSecret") {
    $Body.client_secret = $ClientKey
   } else { # Certificate
    # 1. GET THE CERTIFICATE
    $Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
    # 2. BUILD THE JWT HEADER - The x5t claim (SHA-1 thumbprint) is required.
    $jwtHeader = @{ alg = "RS256"; typ = "JWT"; x5t = ConvertTo-Base64Url -InputObject $Certificate.GetCertHash() } | ConvertTo-Json -Compress
    # 3. BUILD THE JWT CLAIMS (Payload) - Using modern methods for timestamps and adding recommended claims.
    $now = [System.DateTimeOffset]::UtcNow
    $jwtClaims = @{
     aud = $tokenEndpoint
     iss = $ApplicationID
     sub = $ApplicationID
     jti = [System.Guid]::NewGuid().ToString()
     nbf = $now.ToUnixTimeSeconds()
     exp = $now.AddHours(1).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    # 4. ENCODE, SIGN, AND ASSEMBLE THE JWT
    $encodedHeader = ConvertTo-Base64Url -InputObject ([System.Text.Encoding]::UTF8.GetBytes($jwtHeader))
    $encodedClaims = ConvertTo-Base64Url -InputObject ([System.Text.Encoding]::UTF8.GetBytes($jwtClaims))
    $signingInput = "$encodedHeader.$encodedClaims"
    $rsaPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    $signatureBytes = $rsaPrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($signingInput), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $encodedSignature = ConvertTo-Base64Url -InputObject $signatureBytes

    # 5. BUILD THE FINAL REQUEST BODY Using the V2 endpoint parameters.
    $Body.client_assertion = "$encodedHeader.$encodedClaims.$encodedSignature"
    $Body.client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
   }
   $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $Body

  } elseif ($PSCmdlet.ParameterSetName -eq "Interactive") {
   # --- Native Interactive Authentication Flow ---

   # 1. Set up a listener on localhost to catch the redirect
   $redirectPort = 5001 # Can be any available port
   $redirectUri = "http://localhost:$redirectPort/"
   $httpListener = New-Object System.Net.HttpListener
   $httpListener.Prefixes.Add($redirectUri)
   $httpListener.Start()

   # 2. Build the authorization URL and launch the browser
   $authUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/authorize?" +
    "client_id=$ApplicationID" +
    "&response_type=code" +
    "&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($redirectUri))" +
    "&response_mode=query" +
    "&scope=$([System.Web.HttpUtility]::UrlEncode($Scope))"

   Write-Host "Launching browser for interactive login. Please complete authentication..." -ForegroundColor Yellow
   Start-Process $authUrl

   # 3. Wait for the user to login and be redirected
   $context = $httpListener.GetContext()
   $authCode = $context.Request.QueryString["code"]

   # 4. Send a response to the browser and stop the listener
   $responseHtml = "<html><body><h1>Authentication successful!</h1><p>You can close this browser tab now.</p></body></html>"
   $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseHtml)
   $context.Response.ContentLength64 = $buffer.Length
   $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
   $context.Response.Close()
   $httpListener.Stop()

   if (-not $authCode) { throw "Authentication failed or was cancelled. Authorization code not received." }

   # 5. Exchange the authorization code for an access token
   $Body = @{
    grant_type = 'authorization_code'
    client_id  = $ApplicationID
    code    = $authCode
    redirect_uri  = $redirectUri
    scope   = $Scope
   }
   $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $Body
  }

  # --- Process and return the token ---
  if ($tokenResponse) {
   # If the server response includes a scope (interactive flow), use it.
   # Otherwise (client credentials flow), use the scope that was originally requested.
   $finalScope = if ($tokenResponse.PSObject.Properties.Match('scope').Count -gt 0) {
    $tokenResponse.scope
   } else {
    $Scope
   }

   $token = [PSCustomObject]@{
    token_type   = $tokenResponse.token_type
    # Return a [DateTimeOffset] object. It's timezone-aware and prevents comparison issues.
    expires_on   = ([System.DateTimeOffset]::UtcNow).AddSeconds($tokenResponse.expires_in)
    scope  = $finalScope
    access_token = $tokenResponse.access_token
   }
   $ExpirationDateTime = Format-date ($token.expires_on.ToLocalTime().DateTime)
   Write-Host "API Token successfully acquired from '$Scope'. It will expire at: $ExpirationDateTime" -ForegroundColor Cyan
   return $token
  } else {
   throw "Token acquisition failed for an unknown reason. ($Scope)"
  }
 } catch {
  Write-Error "Failed to acquire token. Error: $_"
  if ($_.Exception.InnerException) {
   Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
  }
  return $null
 }
}
Function Get-AzureGraphAPITokenMSAL { # Get API Token using base MS Authentication Module : MSAL.PS # May conflict with other MS Modules
 [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
 Param (
  # --- Common Parameters for All Sets ---

  # This parameter is mandatory for all three authentication methods.
  [parameter(Mandatory = $True, ParameterSetName="ClientSecret")]
  [parameter(Mandatory = $True, ParameterSetName="Certificate")]
  [parameter(Mandatory = $True, ParameterSetName="Interactive")]
  $TenantID,

  # This parameter is optional for all sets and defaults to the Azure CLI's public App ID.
  [parameter(Mandatory = $False, ParameterSetName="ClientSecret")]
  [parameter(Mandatory = $False, ParameterSetName="Certificate")]
  [parameter(Mandatory = $False, ParameterSetName="Interactive")]
  $ApplicationID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",

  # Optional resource parameter, available to all sets.
  # Changed the default to /.default which is the modern recommended scope.
  $Resource = "https://graph.microsoft.com/.default",

  # --- Parameters for Specific Auth Sets ---

  # This parameter is mandatory ONLY for the 'ClientSecret' set.
  [parameter(Mandatory = $True, ParameterSetName="ClientSecret")]
  $ClientKey,

  # This parameter is mandatory ONLY for the 'Certificate' set.
  [parameter(Mandatory = $True, ParameterSetName="Certificate")]
  $CertificateThumbprint, # Thumbprint must be in the local user certificate store

  # This switch activates the 'Interactive' parameter set.
  [parameter(Mandatory = $True, ParameterSetName="Interactive")]
  [switch]$Interactive
 )

 Write-Verbose "Active Parameter Set: $($PSCmdlet.ParameterSetName)"

 try {
  switch ($PSCmdlet.ParameterSetName) {
   "ClientSecret" {
     Write-Host "Authenticating with Application ID and Client Secret..."
     $tokenResponse = Get-MsalToken -TenantId $TenantID -ClientId $ApplicationID -Scopes $Resource -ClientSecret $ClientKey
     # $tokenResponse = Get-MsalToken -TenantId $TenantID -ClientId $ApplicationID -Scopes $Resource -ClientSecret (ConvertTo-SecureString $ClientKey -AsPlainText -Force)
   }
   "Certificate" {
     Write-Host "Authenticating with Application ID and Certificate..."
     $ClientCertificate = Get-Item "Cert:\CurrentUser\My\$($CertificateThumbprint)"
     $tokenResponse = Get-MsalToken -TenantId $TenantID -ClientId $ApplicationID -Scopes $Resource -ClientCertificate $ClientCertificate
   }
   "Interactive" {
     Write-Host "Authenticating interactively..."
     $tokenResponse = Get-MsalToken -TenantId $TenantID -ClientId $ApplicationID -Scopes $Resource -Interactive
   }
  }

  $accessToken=[pscustomobject]@{
   token_type=$tokenResponse.TokenType;
   expires_on=$tokenResponse.ExpiresOn.LocalDateTime;
   resource=$tokenResponse.Scopes;
   access_token=$tokenResponse.AccessToken;
  }

  Write-Verbose "Successfully retrieved token!"
  return $accessToken
 } catch {
  Write-Error "Failed to acquire token. Error: $_"
 }
}
Function Assert-IsTokenLifetimeValid { # Check validity of token
 Param (
  [parameter(Mandatory = $True)]$Token,
  [switch]$ShowExpiration
 )
 if (! $token.expires_on) {
  Write-host -ForegroundColor "Red" -Object "Incorrect Token Format"
  Return
 }
 $ExpirationTimeLocal = $token.expires_on.toLocalTime().DateTime
 if ($ShowExpiration) {
  # $ExpirationDate = $(Format-date (Get-Date -UnixTimeSeconds $token.expires_on))
  # $ExpirationDate = $(Format-date (Get-Date $token.expires_on))
  $ExpirationDate = $(Format-date (Get-Date $ExpirationTimeLocal))
  Write-Host "Token will expire at $ExpirationDate"
 }
 # return $((NEW-TIMESPAN -Start $(Get-Date) -End $(Format-date (Get-Date -UnixTimeSeconds $token.expires_on))) -gt 0)
 return $((NEW-TIMESPAN -Start $(Get-Date) -End $(Format-date (Get-Date $ExpirationTimeLocal))) -gt 0)
}
Function Convert-AccessToken { # Convert Access Token
 Param (
  [Parameter(Mandatory=$true, ValueFromPipeline=$true)]$Token
 )
 process {
  # This code will now run FOR EACH $Token object piped in
  try {
   if (! $(Assert-IsCommandAvailable -commandname Get-JwtPayload)) {Throw "Get-JwtPayload (Module JWT) not available" }
   # Assumes Get-JwtPayload is a function/cmdlet you have that decodes JWTs
   $Token.access_token | Get-JwtPayload -ErrorAction Stop | ConvertFrom-Json
  } catch {
   Write-Error "Failed to get token: $($_.Exception.Message)"
  }
 }
}
Function Get-AzureGraphJWTToken { # Requires module : JWT (Install-Module JWT)
 (az account get-access-token --scope https://graph.microsoft.com/.default | ConvertFrom-Json).accessToken | Get-JwtPayload | ConvertFrom-Json
}
# Graph Management
Function Get-AzureGraph { # Send base graph request without any requirements
 Param (
  [parameter(Mandatory = $True)]$Token,
  [parameter(Mandatory = $True)]$GraphRequest,
  $BaseURL = 'https://graph.microsoft.com/beta',
  [ValidateSet("GET","POST","DELETE")]$Method='GET',
  $Body # Json Format Body
 )

 try {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { throw "Token is invalid, provide a valid token" }

 # Set Header
 $header = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }

 # Build the Base URL for the API call
 $URL = $BaseURL + $GraphRequest

 # Call the REST-API
 if ($Body) {
  $RestResult = Invoke-RestMethod -Method $Method -headers $header -Uri $url -Body $Body -ContentType "application/json"
 } else {
  $RestResult = Invoke-RestMethod -Method $Method -headers $header -Uri $url
 }

 return $RestResult
 } catch {
  if ($($Error[0].ErrorDetails.Message)) {
   $ConvertedErrorMessage = $($Error[0].ErrorDetails.Message | ConvertFrom-Json).error.message
  } else {
   $ConvertedErrorMessage = $Error[0]
  }

  Write-host -ForegroundColor Red "Error during Azure Graph Request $URL ($ConvertedErrorMessage)"
 }
}
# Conditional Access
Function Get-AzureConditionalAccessLocations {
 Param (
  [Parameter(Mandatory)]$Token
 )
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
 $headers = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }
 (Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations").value | Select-Object `
 id,displayName,@{name="Location_Type";expression={($'@odata.type' -split('.'))[-1]}},isTrusted,@{name="Country";expression={$_.countriesAndRegions -join(";")}},
 countryLookupMethod,@{name="IP_Range";expression={$_.iPRanges.cidrAddress -join(";")}}
}
Function Get-AzureConditionalAccessPolicies {
 Param (
  [Parameter(Mandatory)]$Token,
  [Switch]$ShowOnlyEnabled,
  $NameFilter
 )
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { write-Error -Message "Token is invalid, provide a valid token" ; Return }
 $headers = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }
 $Result = (Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/Policies").value

 $NamedLocations = Get-AzureConditionalAccessLocations -Token $Token
 $RoleNames = Get-AzureRoleDefinitions -Token $token
 $RoleNamesHash = @{} ; $RoleNames | ForEach-Object { $RoleNamesHash[$_.ID] = $_ }

 if ($NameFilter) { $Result = $Result | Where-Object displayName -like $NameFilter }

 if ($ShowOnlyEnabled) { $Result = $Result | Where-Object state -eq enabled }

 $Result | Select-Object `
 id,displayName,createdDateTime,modifiedDateTime,state,
 @{name="Access_Control";expression={
  $Controls = @()
  if ($_.grantControls.builtInControls) {
   $Controls += $_.grantControls.builtInControls
  }
  if ($_.grantcontrols.authenticationStrength) {
   $Controls += "$($_.grantcontrols.authenticationStrength.displayname) [$($_.grantcontrols.authenticationStrength.allowedCombinations -replace ",","+" -join ";")]"
  }
  if ($Controls.Count -gt 1) {
   $Controls -join(" "+$_.grantControls.operator+" ")
  } else {
   $Controls
  }
 }},
 @{name="Sign-in frequency";expression={
  if ($_.sessionControls.signInFrequency.isEnabled) {
   $_.sessionControls.signInFrequency.frequencyInterval
  } else {
   "False"
  }

 }},
 @{name="IncludedUsers";expression={
  if (($_.conditions.users.includeUsers) -and ($_.conditions.users.includeUsers -ne "All")) {
   ($_.conditions.users.includeUsers | ForEach-Object { Get-AzureObjectSingleValueFromID -Type Users -Token $Token -ID $_ } ) -Join(";")
  } else {
   $_.conditions.users.includeUsers
  }
 }},
 @{name="includeGroups";expression={
  if ($_.conditions.users.includeGroups) {
   ($_.conditions.users.includeGroups | ForEach-Object { Get-AzureObjectSingleValueFromID -Type Groups -Token $Token -ID $_ } ) -Join(";")
  } else {
   $_.conditions.users.includeGroups
  }
 }},
 @{name="includeRoles";expression={
  ($_.conditions.users.includeRoles | ForEach-Object {
   $RoleNamesHash[$_].displayName
  }) -join(";")
 }},
 @{name="includeGuestsOrExternalUsers";expression={($_.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes -replace ",",";") -join(";")}},
 @{name="excludeUsers";expression={
  ($_.conditions.users.excludeUsers | ForEach-Object { Get-AzureObjectSingleValueFromID -Type Users -Token $Token -ID $_ } ) -Join(";")
 }},
 @{name="excludeGroups";expression={
  ($_.conditions.users.excludeGroups | ForEach-Object { Get-AzureObjectSingleValueFromID -Type Groups -Token $Token -ID $_ } ) -Join(";")
 }},
 @{name="excludeRoles";expression={
  ($_.conditions.users.excludeRoles | ForEach-Object {
   $RoleNamesHash[$_].displayName
  }) -join(";")
 }},
 @{name="excludeGuestsOrExternalUsers";expression={
  # $ExternalGuestUsers = $_.conditions.users.excludeGuestsOrExternalUsers
  # $ExternalGuestUsers | Select-Object @{name="ExternalUsers";expression={"$($_.guestOrExternalUserTypes) [$($_.externalTenants.members)]"}}
  $_.conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes -replace ",",";" -join(";")
 }},
 @{name="includeApplications";expression={
  ($_.conditions.applications.includeApplications | ForEach-Object { Get-AzureServicePrincipalNameFromID -AppID  $_ -Token $Token }) -Join(";")
 }},
 @{name="excludeApplications";expression={
  ($_.conditions.applications.excludeApplications | ForEach-Object { Get-AzureServicePrincipalNameFromID -AppID  $_ -Token $Token }) -Join(";")
 }},
 @{name="applicationFilter_Include";expression={
  ($_.conditions.applications.applicationFilter | Where-Object mode -eq include).Rule
 }},
 @{name="applicationFilter_Exclude";expression={
  ($_.conditions.applications.applicationFilter | Where-Object mode -eq exclude).Rule
 }},
 @{name="includePlatforms";expression={
  $_.conditions.platforms.includePlatforms -Join(";")
 }},
 @{name="excludePlatforms";expression={
  $_.conditions.platforms.excludePlatforms -Join(";")
 }},
 @{name="signInRiskLevels";expression={
  $_.conditions.signInRiskLevels -Join(";")
 }},
 @{name="userRiskLevels";expression={
  $_.conditions.userRiskLevels -Join(";")
 }},
 @{name="clientAppTypes";expression={
  $_.conditions.clientAppTypes -Join(";")
 }},
 @{name="deviceFilterIncluded";expression={
  if ($_.conditions.devices.deviceFilter) { ($_.conditions.devices.deviceFilter | Where-Object {$_.mode -eq "include"}).Rule }
 }},
 @{name="deviceFilterExluded";expression={
  if ($_.conditions.devices.deviceFilter) { ($_.conditions.devices.deviceFilter | Where-Object {$_.mode -eq "exclude"}).Rule }
 }},
 @{name="includeLocations";expression={
  if (($_.conditions.locations.includeLocations ) -and ($_.conditions.locations.includeLocations -ne "All")) {
   ($_.conditions.locations.includeLocations | ForEach-Object { $NamedLocations[$NamedLocations.id.IndexOf($_)].displayName } ) -Join(";")
  } else {
   $_.conditions.locations.includeLocations
  }
 }},
 @{name="excludeLocations";expression={
  if (($_.conditions.locations.excludeLocations ) -and ($_.conditions.locations.excludeLocations  -ne "All")) {
   ($_.conditions.locations.excludeLocations | ForEach-Object { $NamedLocations[$NamedLocations.id.IndexOf($_)].displayName } ) -Join(";")
  } else {
   $_.conditions.locations.excludeLocations
  }}},
  @{name="Full_JSON";expression={
   $_ | ConvertTo-Json -Depth 6
  }}
}
# Log Analytics
Function Convert-AzureLogAnalyticsRequestAnswer { # Convert Log Analytics Request to a proper PS Object [ Created with Gemini ]
 Param (
  [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,Mandatory)]$LogAnalyticsResult
 )
  process {
   Write-Verbose -Message "Converting result to Object"

   # First, check if the result has the expected structure and contains any rows.
   # The '?.' null-conditional operator safely checks for the 'rows' property.
   if (-not $LogAnalyticsResult.tables?.rows) {
    Write-Host "No results found for the query."
    # Exit the function, returning nothing ($null).
    return $False
   }

   # FIX 1: Guarantee that column headers are always an array.
   # The .name property on a single-column result would return a single string.
   # Wrapping it in @() ensures that even a single column name becomes an array of one.
   $headerRow = @($LogAnalyticsResult.tables.columns.name)
   $columnsCount = $headerRow.Count

   $logData = @()

   # FIX 2: Guarantee that the rows collection is always an array of arrays.
   # This is the main fix for the "single result" problem.
   $rowsCollection = $LogAnalyticsResult.tables.rows

   # When one row is returned, PowerShell might "unwrap" it from [["value1", "value2"]]
   # to just ["value1", "value2"]. We need to detect this and re-wrap it.
   # The condition checks if the collection's first item is NOT another collection.
   if ($rowsCollection -is [System.Collections.IList] -and $rowsCollection.Count -gt 0 -and $rowsCollection[0] -isnot [System.Collections.IList]) {
    # The collection is a single, unwrapped row. We re-wrap it into an outer array
    # using the unary comma operator, so it becomes a collection of one row.
    $rowsCollection = @(,$rowsCollection)
   }

   # Now that we are certain $rowsCollection is an array of arrays, we can safely loop.
   foreach ($row in $rowsCollection) {
    $properties = [ordered]@{}
    for ($i = 0; $i -lt $columnsCount; $i++) {
     # We can now safely index into the $row array.
     $properties[$headerRow[$i]] = $row[$i]
    }
    $logData += [PSCustomObject]$properties
   }
   # Return the final array of PSObjects.
   $logData
 }
}
Function Get-AzureLogAnalyticsRequest {
 Param(
  [Parameter(Mandatory)]$WorkspaceID,
  [Parameter(Mandatory)]$Query, #in string (if JSON it can be a POST query with query in BODY)
  [Parameter(Mandatory)]$Token,
  $BaseAPIURL = "api.loganalytics.io" #URL api.loganalytics.io will be deprecated, replace it with https://api.loganalytics.azure.com when available
 )

 Write-Verbose -Message "Checking Token validity"
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
  Write-Error "Token is invalid, provide a valid token"
  return
 }

 Write-Verbose -Message "Generating Headers"
 $headers = @{ 'Authorization' = "$($Token.token_type) $($Token.access_token)" ; 'Content-type'  = "application/json" }

 Write-Verbose -Message "Requesting Rest Method"
 # Using GET with Query in the URL
 # $Result = Invoke-RestMethod -Method GET -headers $headers -Uri "https://$BaseAPIURL/v1/workspaces/$WorkspaceID/query?query=$query" -MaximumRetryCount 2

 # Using post with Query in the BODY
 $QueryJSON = @{"query" = $Query} | ConvertTo-Json
 $Result = Invoke-RestMethod -Method POST -headers $headers -Uri "https://$BaseAPIURL/v1/workspaces/$WorkspaceID/query?query=$query" -MaximumRetryCount 2 -Body $QueryJSON

 Write-Verbose -Message "Converting result to Object"
 $Result | Convert-AzureLogAnalyticsRequestAnswer
}
# Misc
Function Get-AzureADUserOwnedDevice {
 Param (
  [parameter(Mandatory = $true)]$Token, # Access Token retrieved with Get-AzureGraphAPIToken
  [parameter(Mandatory = $true)]$UserID,
  $ValuesToShow = "displayName,deviceOwnership,isCompliant,enrollmentType,enrollmentProfileName,managementType,profileType,trustType,manufacturer,accountEnabled,approximateLastSignInDateTime,createdDateTime"
 )
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) {
  write-host -ForegroundColor "Red" "Token is invalid, provide a valid token"
  Return
 }
 $headers = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }
 (Invoke-RestMethod -Method GET -headers $headers -Uri "https://graph.microsoft.com/v1.0/users/$UserID/ownedDevices?`$select=$ValuesToShow").Value
}
Function New-AzureServiceBusSASToken { # Generate SAS Token using Powershell using Access Policy Name & Key
 Param (
  [Parameter(Mandatory)]$Access_Policy_Name,
  [Parameter(Mandatory)]$Access_Policy_Key,
  [Parameter(Mandatory)]$URI,
  $DurationInSeconds=300
 )
 [Reflection.Assembly]::LoadWithPartialName("System.Web")| out-null
 $Expires=([DateTimeOffset]::Now.ToUnixTimeSeconds())+$DurationInSeconds
 $SignatureString=[System.Web.HttpUtility]::UrlEncode($URI)+ "`n" + [string]$Expires
 $HMAC = New-Object System.Security.Cryptography.HMACSHA256
 $HMAC.key = [Text.Encoding]::ASCII.GetBytes($Access_Policy_Key)
 $Signature = $HMAC.ComputeHash([Text.Encoding]::ASCII.GetBytes($SignatureString))
 $Signature = [Convert]::ToBase64String($Signature)
 $SASToken = "SharedAccessSignature sr=" + [System.Web.HttpUtility]::UrlEncode($URI) + "&sig=" + [System.Web.HttpUtility]::UrlEncode($Signature) + "&se=" + $Expires + "&skn=" + $Access_Policy_Name
 $SASToken
}
Function Get-AzureObjectSingleValueFromID { # Get Single Value from Group ID, must faster and simpler that Get-AzureAdGroup*
 Param (
  [Parameter(Mandatory)]$ID,
  [ValidateSet("Users","","Groups","Applications","servicePrincipals")]$Type,
  $Value = "displayName", # or UserPrincipalName
  $Token
 )
 if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
 $header = @{
  'Authorization' = "$($Token.token_type) $($Token.access_token)"
  'Content-type'  = "application/json"
 }
 (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/$Type/$ID`?`$select=$Value").$Value
}
Function Get-AzureADObjectInfo { # Get Object GUID Info
 Param (
  [Parameter(Mandatory)][GUID]$ObjectID,
  [Switch]$PrintError,
  [Switch]$ShowAll,
  $Token
 )
 if ($Token) {
  $Result = Get-AzureGraph -Token $Token -GraphRequest "/directoryObjects/$ObjectID"
  if ($ShowAll) {
   $Result
  } else {
   $Result | Select-Object `
    @{name="ID";expression={$_.id}},
    @{name="Type";expression={$_.'@odata.type' -replace "#microsoft.graph.",""}},
    @{name="DisplayName";expression={$_.displayName}},mail,userPrincipalName,description
  }
 } else {
  $ResultJson = az rest --method GET --uri "https://graph.microsoft.com/beta/directoryObjects/$ObjectID" --headers Content-Type=application/json 2>&1
  $ErrorMessage = $ResultJson | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }
  $Result = $ResultJson | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }
  if ($ErrorMessage) {
   if ($PrintError) { write-host -ForegroundColor "Red" -Object "Error searching for ObjectID $ObjectID [$ErrorMessage]" }
   [pscustomobject]@{ID=$ObjectID;Type="Unknown";DisplayName="ID Not Found in Azure";mail="Unknown";userPrincipalName="Unknown"}
  } else {
   $Result = $ResultJson | ConvertFrom-Json
   if ($ShowAll) {
    $Result
   } else {
    $Result | Select-Object `
     @{name="ID";expression={$_.id}},
     @{name="Type";expression={$_.'@odata.type'}},
     @{name="DisplayName";expression={$_.displayName}},mail,userPrincipalName
   }
  }
 }
}
Function Send-MailMGGraph {  # To make automated Email, it requires an account with a mailbox | Should add a "From" Option | Requires MG Graph
 Param (
  [Parameter(Mandatory)]$UserMail,
  [Parameter(Mandatory)]$SenderUPN,
  [Parameter(Mandatory)]$MessageContent, # Format @"TEXT"@
  [Parameter(Mandatory)]$Subject,
  $From
 )

 $CurrentConnection = Get-MgContext | where-object { ($_.ContextScope -eq "Process") -and ($_.Scopes -contains "Mail.Send") }
 if (!$CurrentConnection) { Open-MgGraphConnection -Scopes 'Mail.Send' -ContextScope 'Process' }

 $params = @{
  Message = @{
   Subject = $Subject
   Body = @{ ContentType = "HTML" ; Content = $MessageContent }
   ToRecipients = @( @{ EmailAddress = @{ Address = $UserMail } } )
  }
  SaveToSentItems = "true"
 }
 if ($From) {
  $params.Message.Add("From",@( @{ From = @{ Address = $From } } ))
 }
 Send-MgUserMail -UserId $SenderUPN -BodyParameter $params
}
Function Send-Mail {
 Param (
  [Parameter(Mandatory)]$Recipient,
  [Parameter(Mandatory)]$SenderUPN,
  [Parameter(Mandatory)]$MessageContent, # Format @"TEXT"@
  [Parameter(Mandatory)]$Subject,
  $From,
  $Token
 )

 if (! $From) {
  $From = $SenderUPN
 }

 $AccessToken = $Token.access_token

 $Headers = @{
  'Content-Type'  = "application\json"
  'Authorization' = "Bearer $AccessToken"
 }

 $MessageParams = @{
  "URI"         = "https://graph.microsoft.com/v1.0/users/$SenderUPN/sendMail"
  "Headers"     = $Headers
  "Method"      = "POST"
  "ContentType" = 'application/json'
  "Body" = (@{
   "message" = @{
    "subject" = $Subject
    "body"    = @{
     "contentType" = 'HTML'
     "content"     = $MessageContent
    }
   "toRecipients" = @(
    @{
     "emailAddress" = @{"address" = $Recipient }
    })
   "from" = @{ "emailAddress" = @{"address" = $From } }
   }
  }) | ConvertTo-JSON -Depth 6
 }
 Invoke-RestMethod @Messageparams
}
Function Get-AzureSKUs { # Usefull to get all license related IDs and descriptions in the current tenant
 Param (
  $Token
 )
 if ($Token) {
  if (! $(Assert-IsTokenLifetimeValid -Token $Token ) ) { return "Token is invalid, provide a valid token" }
  $header = @{
   'Authorization' = "$($Token.token_type) $($Token.access_token)"
   'Content-type'  = "application/json"
  }
  (Invoke-RestMethod -Method GET -headers $header -Uri "https://graph.microsoft.com/v1.0/subscribedSkus").value | Select-Object appliesTo,capabilityStatus,skuId,skuPartNumber
 } else {
  ((az rest --method GET --uri "https://graph.microsoft.com/v1.0/subscribedSkus" -o json | ConvertFrom-Json).value | Select-Object appliesTo,capabilityStatus,skuId,skuPartNumber)
 }
}
Function Get-TOR_IP_List { # Will not work with Zscaler
 $response = Invoke-WebRequest -Uri "https://check.torproject.org/torbulkexitlist" -UseBasicParsing
 $response.RawContent -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' }
}

#Alias
Set-Alias -Name ls -Value "Get-ChildItemBen" -Option AllScope
Set-Alias -Name ll -Value "ls" -Option AllScope
Set-Alias -Name ip -Value "get-ip" -Option AllScope
Set-Alias -Name uptime -Value "Get-UptimePerso" -Option AllScope
Set-Alias -Name npp -Value "notepad++.exe" -Option AllScope
Set-Alias -Name su -Value "pselevate" -Option AllScope
Set-Alias -Name du -Value "Get-DiskUsage" -Option AllScope
Set-Alias -Name df -Value "Get-PartitionInfo" -Option AllScope
Set-Alias -Name dns -Value "checkdns" -Option AllScope
Set-Alias -Name grep -Value "Select-String"
Function Start-Jdownloader { get-job | remove-job ;  invoke-expression -Command "java -jar C:\JDownloader\JDownloader.jar &" }
Function LoadMMC { mmc "$env:OneDriveCommercial\RootConsole.msc" }
Set-Alias -Name jd -value Start-Jdownloader
Set-Alias -Name Home -value "LoginHome"
Set-Alias -Name Which -value "Get-Command"

if (Assert-MinPSVersion 6 -Silent) {
 if ( (test-path $env:iClic_Addon_Path -ErrorAction SilentlyContinue)) { import-module $env:iClic_Addon_Path }
 if ( (test-path $env:iClic_Perso_Path -ErrorAction SilentlyContinue)) { import-module $env:iClic_Perso_Path }
} else {
 Try {
  Write-Host -ForegroundColor "Magenta" -Object "WARNING : You are using old legacy PowerShell versions - Some Cmdlet will surely fail"
 } Catch {
  Write-Output -InputObject "WARNING : You are using old legacy PowerShell versions - Some Cmdlet will surely fail"
 }
}