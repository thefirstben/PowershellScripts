$ModulePath = Join-Path $PSScriptRoot '..\iClic.psm1'
$ParseErrors = $null
$ModuleAst = [System.Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$null, [ref]$ParseErrors)
if ($ParseErrors.Count) { throw ($ParseErrors | Out-String) }
$FunctionAst = $ModuleAst.Find({
 param($Node)
 $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'Get-AzureGraphAPIToken'
}, $false)
. ([scriptblock]::Create($FunctionAst.Extent.Text))

Describe 'Get-AzureGraphAPIToken interactive renewal' {
 function Convert-AccessToken {
  [CmdletBinding()]
  param([Parameter(ValueFromPipeline)]$Token)
  process { }
 }

 BeforeEach {
  $Query = [System.Collections.Specialized.NameValueCollection]::new()
  $Query.Add('code', 'test-authorization-code')
  $Response = [pscustomobject]@{ ContentLength64 = 0; OutputStream = [System.IO.MemoryStream]::new() }
  $Response | Add-Member -MemberType ScriptMethod -Name Close -Value { }
  $Context = [pscustomobject]@{ Request = [pscustomobject]@{ QueryString = $Query }; Response = $Response }
  $script:Listener = [pscustomobject]@{
   Prefixes = [System.Collections.Generic.List[string]]::new()
   ContextTask = [System.Threading.Tasks.Task[object]]::FromResult($Context)
  }
  foreach ($MethodName in 'Start', 'Stop', 'Close') {
   $script:Listener | Add-Member -MemberType ScriptMethod -Name $MethodName -Value { }
  }
  $script:Listener | Add-Member -MemberType ScriptMethod -Name GetContextAsync -Value { $this.ContextTask }

  Mock New-Object { $script:Listener } -ParameterFilter { $TypeName -eq 'System.Net.HttpListener' }
  Mock Start-Process { }
  Mock Write-Host { }
  Mock Write-Warning { }
  Mock Convert-AccessToken { [pscustomobject]@{ appid = 'test-client'; tid = 'example-tenant' } }
  Mock Invoke-RestMethod {
   [pscustomobject]@{
    access_token = 'test-access-token'
    refresh_token = 'rotated-refresh-token'
    token_type = 'Bearer'
    expires_in = 3600
   }
  }
 }

 It 'renews silently without creating a listener or opening a browser' {
  $Result = Get-AzureGraphAPIToken -Interactive -RefreshToken 'previous-refresh-token' -TenantID 'example-tenant'

  $Result.access_token | Should Be 'test-access-token'
  $Result.token_response.refresh_token | Should Be 'rotated-refresh-token'
  $Result.token_source | Should Be 'Interactive'
  Assert-MockCalled Start-Process -Times 0 -Exactly -Scope It
  Assert-MockCalled New-Object -Times 0 -Exactly -Scope It -ParameterFilter { $TypeName -eq 'System.Net.HttpListener' }
  Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
   $Uri -eq 'https://login.microsoftonline.com/example-tenant/oauth2/v2.0/token' -and
   $Body.grant_type -eq 'refresh_token' -and $Body.refresh_token -eq 'previous-refresh-token'
  }
 }

 It 'preserves the prior refresh token when the service does not rotate it' {
  Mock Invoke-RestMethod {
   [pscustomobject]@{ access_token = 'test-access-token'; token_type = 'Bearer'; expires_in = 3600 }
  }
  $Result = Get-AzureGraphAPIToken -Interactive -RefreshToken 'previous-refresh-token'

  $Result.token_response.refresh_token | Should Be 'previous-refresh-token'
 }

 It 'chooses the correct public client for <Scope>' -TestCases @(
  @{ Scope = 'https://graph.microsoft.com/.default'; ClientID = '14d82eec-204b-4c2f-b7e8-296a70dab67e' }
  @{ Scope = 'https://management.azure.com/.default'; ClientID = '04b07795-8ddb-461a-bbee-02f9e1bf7b46' }
  @{ Scope = 'https://api.loganalytics.io/.default'; ClientID = '04b07795-8ddb-461a-bbee-02f9e1bf7b46' }
  @{ Scope = '499b84ac-1321-427f-aa17-267ca6975798/.default'; ClientID = '04b07795-8ddb-461a-bbee-02f9e1bf7b46' }
 ) {
  param($Scope, $ClientID)
  $Result = Get-AzureGraphAPIToken -Interactive -Scope $Scope -RefreshToken 'previous-refresh-token'

  $Result.client_id | Should Be $ClientID
  Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter { $Body.client_id -eq $ClientID }
 }

 It 'honors an explicitly supplied custom public client' {
  $Result = Get-AzureGraphAPIToken -Interactive -Scope 'https://management.azure.com/.default' -ApplicationID 'custom-client' -RefreshToken 'previous-refresh-token'

  $Result.client_id | Should Be 'custom-client'
  Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter { $Body.client_id -eq 'custom-client' }
 }

 It 'requests offline access during browser sign-in' {
  $Result = Get-AzureGraphAPIToken -Interactive

  $Result.token_response.refresh_token | Should Be 'rotated-refresh-token'
  Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It -ParameterFilter {
   [System.Web.HttpUtility]::ParseQueryString(([uri]$FilePath).Query)['scope'] -eq 'https://graph.microsoft.com/.default offline_access'
  }
  Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
   $Body.grant_type -eq 'authorization_code' -and $Body.scope -eq 'https://graph.microsoft.com/.default offline_access'
  }
 }

 It 'opens the browser when silent renewal requires interaction' {
  Mock Invoke-RestMethod {
   if ($Body.grant_type -eq 'refresh_token') {
    $Failure = [System.Management.Automation.ErrorRecord]::new(
     [System.InvalidOperationException]::new('Interaction required'), 'OAuthError',
     [System.Management.Automation.ErrorCategory]::AuthenticationError, $null)
    $Failure.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":"invalid_grant"}')
    throw $Failure
   }
   [pscustomobject]@{ access_token = 'test-access-token'; refresh_token = 'new-refresh-token'; token_type = 'Bearer'; expires_in = 3600 }
  }
  $Result = Get-AzureGraphAPIToken -Interactive -RefreshToken 'expired-refresh-token'

  $Result.token_response.refresh_token | Should Be 'new-refresh-token'
  Assert-MockCalled Start-Process -Times 1 -Exactly -Scope It
  Assert-MockCalled Invoke-RestMethod -Times 2 -Exactly -Scope It
 }

 It 'does not retry invalid-client failures in a browser' {
  Mock Invoke-RestMethod {
   $Failure = [System.Management.Automation.ErrorRecord]::new(
    [System.InvalidOperationException]::new('Invalid client'), 'OAuthError',
    [System.Management.Automation.ErrorCategory]::AuthenticationError, $null)
   $Failure.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":"invalid_client"}')
   throw $Failure
  }

    { Get-AzureGraphAPIToken -Interactive -RefreshToken 'test-refresh-token' } | Should Throw 'Invalid client'
  Assert-MockCalled Start-Process -Times 0 -Exactly -Scope It
  Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -Scope It
 }

 It 'leaves client-secret acquisition unchanged' {
  $Result = Get-AzureGraphAPIToken -TenantID 'example-tenant' -ApplicationID 'application-client' -ClientKey 'test-client-secret'

  $Result.token_source | Should Be 'ClientSecret'
  Assert-MockCalled Start-Process -Times 0 -Exactly -Scope It
  Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -Scope It -ParameterFilter {
   $Body.grant_type -eq 'client_credentials' -and $Body.scope -eq 'https://graph.microsoft.com/.default'
  }
 }
}