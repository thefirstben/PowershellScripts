Param(
  $SourcePath=$(Split-Path $MyInvocation.MyCommand.Path),
  # $SourcePath=$PSScriptRoot,
  [ValidateSet("32","64")][String]$Architecture,
  [ValidateSet("Insiders","Monthly","Targeted","Broad")][string]$ChangeUpdateChannel,
  [ValidateSet("EN","FR","DE")][string]$Language,
  [switch]$Office=$false,
  [switch]$Visio=$false,
  [switch]$Project=$false,
  [switch]$Download=$false,
  [switch]$NoPause=$false,
  $LogPath="C:\Temp\"
)

#Functions
Function Write-Colored ($Color="Cyan",$NonColoredText,$ColoredText,[switch]$NoNewLine=$false,$filepath) {
 write-host -nonewline $NonColoredText
 if ($NoNewLine) {write-host -nonewline -foregroundcolor $Color $ColoredText} else {write-host -foregroundcolor $Color $ColoredText}
 if ($filepath) { write-output "$NonColoredText $ColoredText" | out-file -append $filepath }
}
Function GenerateOfficeXML {

#Generate XML Files
$tmp_file_creation=Get-Command New-TemporaryFile -ErrorAction SilentlyContinue
if ($tmp_file_creation) {
  $TMP_XML_FILE = New-TemporaryFile
 } else {
  $TMP_XML_FILE = "$($env:temp)\OfficeInstallation.xml"
}

# Language
if ($Language -eq "EN") { $langXML="   <Language ID='en-us' />"
} elseif ($Language -eq "FR") { $langXML="   <Language ID='fr-fr' />"
} elseif ($Language -eq "DE") { $langXML="   <Language ID='de-de' />"
} else {    
$langXML="   <Language ID='en-us' />
   <Language ID='fr-fr' />
   <Language ID='de-de' />"
}

# Standard
 write-output "<Configuration>
  <Add " > $TMP_XML_FILE
# If Source are available
if (test-path "$SourcePath\Office\Data") {
 write-output "   SourcePath=`"$SourcePath`"" >> $TMP_XML_FILE
 }
# 32 or 64 BITS
if ($Architecture -eq '64') {
 write-output "   OfficeClientEdition='64'" >> $TMP_XML_FILE
} else {
 write-output "   OfficeClientEdition='32'" >> $TMP_XML_FILE
}
# Update Channel
 write-output "   Channel='Monthly'
  >" >> $TMP_XML_FILE

# Office Install
if ($Office -or $Download) {
 write-output "
  <Product ID='O365ProPlusRetail' >
$langXML
   <ExcludeApp ID='OneDrive' />
   <ExcludeApp ID='Groove' />
   <Property Name='PinIconsToTaskbar' Value='TRUE' />
  </Product>" >> $TMP_XML_FILE
}

# Visio Install
if ($Visio -or $Download) {
write-output "
  <Product ID='VisioProRetail'>
$langXML
  </Product>" >> $TMP_XML_FILE
}

# Project
if ($Project -or $Download) {
write-output "
  <Product ID='ProjectProRetail'>
$langXML
  </Product>" >> $TMP_XML_FILE
}

write-output "
<!-- Remove MSI Install -->  
  <RemoveMSI All='True' />
<!-- Allow updates to be checked -->
  <Updates Enabled='TRUE' Channel='Monthly' />
  </Add>
<!-- verbose Install -->
  <Display Level='Full' AcceptEULA='TRUE' />

  <Property Name='FORCEAPPSHUTDOWN' Value='TRUE'/>
<!-- Log info and path -->
  <Logging Level='Standard' Path='$LogPath' />
  <Property Name='AUTOACTIVATE' Value='1' />

</Configuration>" >> $TMP_XML_FILE

return $TMP_XML_FILE
}
Function PrintLatestLog {
 $logfile="$LogPath\$(gci $LogPath -Filter "$hostname-$(get-date -uformat "%Y%m%d")*.log" | select -last 1)"
 write-host "$(get-date -uformat '%Y-%m-%d-%T') | In case of error check logfile in $logfile"
}

#Variables
$hostname=$env:COMPUTERNAME
$SourcePathDeploymentTool=$SourcePath+"\Office Deployment Tool"
$logfile="$LogPath\Office_Install.log"

write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Check Log Folder"
if ( ! (test-path $LogPath)) { 
 Try {
  write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Creating Temp Folder"
  New-Item -Type Directory $LogPath -ErrorAction Stop | out-null
 } catch {
  write-colored "Red" "$(get-date -uformat "%Y-%m-%d %T") "  $Error[0]
  return
 }
}

write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Start process" $logfile

write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Switch folder to source path $SourcePath" $logfile
try {
 Set-Location $SourcePath -ErrorAction Stop
} catch {
 write-colored "Red" "$(get-date -uformat "%Y-%m-%d %T") "  $Error[0] $logfile
}
 
write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Checking Setup.exe" $logfile
if (! (test-path "setup.exe")) {
 write-colored "Red" "$(get-date -uformat "%Y-%m-%d %T") " "Setup.exe is not available, it must be in the same folder as the script" $logfile
 return
}
 
write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Generate XML used for install" $logfile
$OfficeXMLFile=GenerateOfficeXML
cat $OfficeXMLFile >> $logfile
write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "File that will be used for Office Install : $($OfficeXMLFile.FullName)" $logfile

# Change Update Channel (Not required for new installs)
if ($ChangeUpdateChannel) { 
 write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Changing Office Update Channel to : $ChangeUpdateChannel" $logfile
 . "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /changesetting Channel=$ChangeUpdateChannel
 . "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /update user
}
  
# Download new version to repository
if ($Download) { 
 write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Updating Repository" $logfile
 PrintLatestLog
 . ".\setup.exe" /download $OfficeXMLFile
}

# Install base package
if ($Office -or $Visio -or $Project) { 
 write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "Installing Office" $logfile
 PrintLatestLog
 . ".\setup.exe" /configure $OfficeXMLFile
}

write-colored "Blue" "$(get-date -uformat "%Y-%m-%d %T") " "End process" $logfile

#Add Stop for manual install  
if (! $NoPause) { 
 write-output "Press a key to continue"
 [void][System.Console]::ReadKey($FALSE) 
}
