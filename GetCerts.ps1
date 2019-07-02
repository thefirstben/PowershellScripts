Function Get-ADOUFromServer ($ServerName=$env:COMPUTERNAME) {
 $DistinguishedName=(get-adcomputer $Servername -properties DistinguishedName).DistinguishedName.split(",")
 ($DistinguishedName[1..($DistinguishedName.Length -1)] -join ",")
}
Function Get-ADCertificateStatus {
param(
 $ComputerList=$(Get-ADOUFromServer),
 $Requester,
 $CALocation=(Get-CaLocationString)[0],
 [ValidateSet("Machine","CodeSigning","EFS","WebServer","DomainController","User","CrossCA","AOVPNUserAuthentication")]$CertType='machine' 
 )
 Try {

 $CertList=Get-IssuedCertificate -CAlocation $CALocation 

 if ($CertType -eq 'AOVPNUserAuthentication') {
  $CertOID=Get-CertificateTemplateOID $CertType
  $CertListFiltered=$CertList | where {$_.'Certificate Template' -eq $CertOID}
 } else {
  $CertListFiltered=$CertList | where {$_.'Certificate Template' -eq $CertType}
 }

 if ($Requester) {
  $CertListFiltered=$CertListFiltered | where {$_.'Requester Name' -like "*$Requester*"}
 }
 
 if ($CertType -eq 'machine') { 
  $ComputerListInfo=Get-AdComputer -SearchBase $ComputerList -Filter {Enabled -eq "True"} -Properties LastLogonDate,Description,DNSHostName,created,OperatingSystem,LastLogonDate,CanonicalName | select `
  Name,SamAccountName,DNSHostName,Description,Created,LastLogonDate,OperatingSystem, @{name="OU";expression={$_.CanonicalName | % {(($_ -split('/'))| select -skiplast 1) -join '/'}}}
 
  $ComputerListInfo | select *,@{name="Cert";expression={$tmp=$_.DNSHostName;($CertListFiltered | where {$_.'Issued Common Name' -eq $tmp})[-1]}}`
   | select -exclude cert *,`
    @{name="CertCN";expression={if (! $_.Cert) {'NotFound'} else {$_.Cert.'Issued Request ID'}}},`
    @{name="CertMSG";expression={if ($_.Cert) {if ($_.Cert.Message -ne 'Issued') {'Error'} else {'Issued'}}}},`
    @{name="CertCreateDate";expression={if ($_.Cert) {$_.Cert.'Certificate Effective Date'}}},`
    @{name="CertExpirationDate";expression={if ($_.Cert) {$_.Cert.'Certificate Expiration Date'}}}
 } else {
   $CertListFiltered | select 'Certificate Template','Issued Common Name','Requester Name','Issued Request ID','Certificate Effective Date',`
    'Certificate Expiration Date',@{name="Message";expression={$_.'Request Disposition Message' -replace "`t","" -replace "`n",""}}`
    | sort 'Issued Request ID'
 }
 } Catch {
   write-host -ForegroundColor "Red" $Error[0]
 }
# Get-ComputerCertificateStatus -ComputerList 'OU=Computers,OU=Systems,OU=A_Nouvelle Structure AD,DC=auto-contact,DC=com' | Export-Csv "ComputerListCertStatus-$(get-date -uformat '%Y-%m-%d').csv" -encoding "UTF8" -notypeinformation -NoClobber
}