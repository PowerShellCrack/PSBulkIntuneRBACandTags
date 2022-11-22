
<#
.SYNOPSIS
    Deletes Azure AD groups, Tags and Intune RBAC Roles based comma-delimited list

.NOTES
    Version: 1.4.3

    DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  **THIS SAMPLE CODE AND ANY
    RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
    MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE**.  We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to
    reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your
    software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded;
    and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result
    from the use or distribution of the Sample Code.

    This posting is provided "AS IS" with no warranties, and confers no rights. Use of included script samples are subject to the terms specified
    at https://www.microsoft.com/en-us/legal/copyright.

.PARAMETER GraphAdminUPN
    Provide Azure UPN to authenticate to Graph

.PARAMETER RbacListPath
    Default value is '.\ManagementRoles.csv'

.PARAMETER TagAndAssignmentListPath
    Default value is '.\ScopeTagAndAssignments.csv'

.PARAMETER NoAction
    Simulates action using Whatif output. No deletion will occur

.EXAMPLE
    .\IntuneRolesDeletion.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com

.EXAMPLE
    .\IntuneRolesDeletion.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com -NoAction

.EXAMPLE
    .\IntuneRolesDeletion.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv

.EXAMPLE
    .\IntuneRolesDeletion.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -NoAction
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$GraphAdminUPN,

    [ValidateScript({Test-Path $_})]
    $RbacListPath = '.\ManagementRoles.csv',

    [ValidateScript({Test-Path $_})]
    $TagAndAssignmentListPath = '.\ScopeTagAndAssignments.csv',

    [switch]$NoAction
)


## =======================================
#  FUNCTIONS
## =======================================
Function Write-PadOutput{
    param(
        $Message
    )

    ("lalala","hehe","hi" | Measure-Object -Maximum -Property Length).Maximum

}

function Get-AzureAuthToken {
    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface

    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name

    .EXAMPLE
    Get-AzureAuthToken -User admin@azuredomain
    Authenticates you with the Graph API interface
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        $User
    )

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    $tenant = $userUpn.Host

    Write-Host "Checking for AzureAD module..." -NoNewline
    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($null -eq $AadModule) {
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    }
    #Check again maybe AzureAD preview module is installed...
    if ($null -eq $AadModule) {
        Write-Host "Not installed" -f Red
        Write-Host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        exit
    }
    Else{
        Write-Host "Available" -f Green
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found
            if($AadModule.count -gt 1){
                $aadModule = $AadModule | select -Unique
            }
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }
    else {
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI = "https://graph.microsoft.com"
    $authority = "https://login.microsoftonline.com/$Tenant"

    try {

        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header
        if($authResult.AccessToken){

            # Creating header for Authorization token
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
            return $authHeader

        }
        else {
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            break

        }
    }
    catch {
        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        break
    }

}


####################################################
Function Get-IntuneRole{

    <#
    .SYNOPSIS
    This function is used to get RBAC Role Definitions from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and gets any RBAC Role Definitions

    .EXAMPLE
    Get-IntuneRole
    Returns all custom RBAC Role Definitions configured in Intune

    .EXAMPLE
    Get-IntuneRole -IncludeBuiltin
    Returns all RBAC Role Definitions configured in Intune including builtin

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-get?view=graph-rest-1.0
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [String]$Name,

        [Parameter(Mandatory=$false)]
        [switch]$Assignments,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeBuiltin
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"

    try {

        if($Name){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            $Result = (Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") -and $_.isBuiltInRoleDefinition -eq $IncludeBuiltin }
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            $Result = (Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Get).Value
        }


        If($Assignments){
            #TEST $Def = $Result[0]
            Foreach($Def in $Result){
                $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$($Def.id)')?`$expand=roleassignments"
                (Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Get).roleAssignments
            }
        }
        Else{
            return $Result
        }
    }

    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose ("Request to {0} failed with HTTP Status {1}: {2}" -f $Uri,$ex.Response.StatusCode,$ex.Response.StatusDescription)
        Write-Error ("{0}" -f $responseBody)
    }

}

####################################################

Function Remove-IntuneRole{

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$DisplayName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [int32]$Id
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"
    if($DisplayName){
        $RoleId = (Get-IntuneRole -Name $DisplayName) | Where IsBuiltin -ne $true | Select -ExpandProperty id
    }Else{
        #$DisplayName = (Get-IntuneRole -Id $Id).displayName
        $RoleId = $Id
    }

    If($RoleId)
    {
        Write-verbose ("Role [{0}] has an Id of [{1}]" -f $DisplayName,$RoleId)
    }
    Else{
        Write-verbose ("No Role by the name of [{0}] or is a builtin role" -f $DisplayName)
        Break
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$($RoleId)')"
        Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Delete
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose ("Request to {0} failed with HTTP Status {1}: {2}" -f $Uri,$ex.Response.StatusCode,$ex.Response.StatusDescription)
        Write-Error ("{0}" -f $responseBody)
    }
}

####################################################


Function Get-IntuneScopeTag{

    <#
    .SYNOPSIS
    This function is used to get scope tags using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and gets scope tags

    .EXAMPLE
    Get-IntuneScopeTag -DisplayName "Test"
    Gets a scope tag with display Name 'Test'

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-get?view=graph-rest-beta
    #>

    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [string]$DisplayName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Id')]
        [int32]$Id
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleScopeTags"

    try {
        if($DisplayName){
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)`?`$filter=displayName eq '$DisplayName'"
            $Result = Invoke-RestMethod -Method Get -Uri $uri -Headers $global:authToken -ErrorAction Stop
        }
        elseif($Id){
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)`?`$filter=id eq '$Id'"
            $Result = Invoke-RestMethod -Method Get -Uri $uri -Headers $global:authToken -ErrorAction Stop
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            $Result = Invoke-RestMethod -Method Get -Uri $uri -Headers $global:authToken -ErrorAction Stop

        }
        return $Result.Value
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose ("Request to {0} failed with HTTP Status {1}: {2}" -f $Uri,$ex.Response.StatusCode,$ex.Response.StatusDescription)
        Write-Error ("{0}" -f $responseBody)
    }
}

####################################################
Function Remove-IntuneScopeTag{

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        $DisplayName
    )

    $graphApiVersion = "beta"
    $Resource = "/deviceManagement/roleScopeTags"

    $ScopeTagId = (Get-IntuneScopeTag -DisplayName $DisplayName).id

    If($ScopeTagId -and ($DisplayName -ne 'default') )
    {
        Write-verbose ("Scope tag [{0}] has an Id of [{1}]" -f $DisplayName,$ScopeTagId)
    }
    Else{
        Write-verbose ("No Scope tag by the name of [{0}] was found" -f $DisplayName)
        Break
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$($ScopeTagId)')"
        Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Delete
    }

    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose ("Request to {0} failed with HTTP Status {1}: {2}" -f $Uri,$ex.Response.StatusCode,$ex.Response.StatusDescription)
        Write-Error ("{0}" -f $responseBody)
    }
}

####################################################


####################################################
Function Get-IntuneRoleAadGroup{

    <#

    .SYNOPSIS
    This function is used to get AAD Groups from the Graph API REST interface for Intune

    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Groups registered with AAD

    .EXAMPLE
    Get-IntuneRoleAadGroup
    Returns all users registered with Azure AD

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-get?view=graph-rest-beta&tabs=http
    #>
    [cmdletbinding()]
    param
    (
        [string]$GroupName,
        [string]$id,
        [switch]$Members
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Group_resource = "groups"

    $ShowAll = $True
    if($id){
        $Property = 'id'
        $Value = $id
        $FilterString = "?`$filter=id eq '$id'"
        $ShowAll = $False
    }

    if($GroupName){
        $Property = 'displayname'
        $Value = $GroupName
        $FilterString = "?`$filter=displayname eq '$GroupName'"
        $ShowAll = $False
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)$FilterString"
        $Result = Invoke-RestMethod -Method Get -Uri $uri -Headers $global:authToken -ErrorAction Stop

        # if group or id is not found or null, by default, all groups are displayed
        #ensure all groups are not displayed when id or groupname params are used
        If($ShowAll -eq $False -and $Result.value.$Property -ne $Value){
            $Result = $Null
        }

        If($Members)
        {
            Foreach($Group in $Result.value){
                $GID = $Group.id
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                (Invoke-RestMethod -Method Get -Uri $uri -Headers $global:authToken -ErrorAction Stop).Value
            }
        }
        Else{
            $Result.value
        }
    }
    Catch{
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose ("Request to {0} failed with HTTP Status {1}: {2}" -f $Uri,$ex.Response.StatusCode,$ex.Response.StatusDescription)
        Write-Error ("{0}" -f $responseBody)
    }
}

####################################################
Function Remove-IntuneAADDynamicGroup{

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )

    $graphApiVersion = "beta"
    $Resource = "groups"

    $AADGroupId = (Get-IntuneRoleAADGroup -GroupName $GroupName).id

    If($AADGroupId)
    {
        Write-verbose ("Azure AD Group [{0}] has an Id of [{1}]" -f $GroupName,$AADGroupId)
    }
    Else{
        Write-verbose ("No Azure AD Group by the name of [{0}] was found" -f $GroupName)
        Break
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$AADGroupId"
        Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Delete
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose ("Request to {0} failed with HTTP Status {1}: {2}" -f $Uri,$ex.Response.StatusCode,$ex.Response.StatusDescription)
        Write-Error ("{0}" -f $responseBody)
    }
}

## =======================================
#  MAIN
## =======================================
#region Authentication

$stopwatch =  [system.diagnostics.stopwatch]::StartNew()
#region Authentication

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($global:authToken.ExpiresOn.datetime - $DateTime).Minutes
    if($TokenExpires -le 0){

        Write-Host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow

        # Defining User Principal Name if not present
        if([string]::IsNullOrEmpty($GraphAdminUPN)){
            $GraphAdminUPN = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        }
        $global:authToken = Get-AzureAuthToken -User $GraphAdminUPN
    }
}
# Authentication doesn't exist, calling Get-AzureAuthToken function
else {
    if([string]::IsNullOrEmpty($GraphAdminUPN)){
        $GraphAdminUPN = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    }
    # Getting the authorization token
    $global:authToken = Get-AzureAuthToken -User $GraphAdminUPN
}

#endregion

## =====================
## Import New Roles info
## ======================
$RbacList = Import-Csv $RbacListPath
#filter out empty ones
$RbacList = $RbacList | Where Role -ne ''

$TagAndAssignment = Import-Csv $TagAndAssignmentListPath

## ==============
## Remove Tags
## ==============
Foreach($Tag in $TagAndAssignment)
{
    Write-Host ('Searching for scope tag [{0}]...' -f $Tag.'Scope Tags') -NoNewline

    If(Get-IntuneScopeTag -DisplayName $Tag.'Scope Tags')
    {
        Write-Host ("Found") -ForegroundColor Green

        If(!$NoAction)
        {
            Write-Host ('  Removing scope tag [{0}]...' -f $Tag.'Scope Tags') -NoNewline
            Try{
                $Result = Remove-IntuneScopeTag -DisplayName $Tag.'Scope Tags'
                Write-Host 'Done' -ForegroundColor Green
            }
            Catch{
                Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
            }
        }
        Else{
            Write-Host ('  What if: Performing the operation "Remove-IntuneScopeTag" on target "{0}"' -f $Tag.'Scope Tags') -ForegroundColor Cyan
        }
    }
    Else{
        Write-Host ("doesn't exist!") -ForegroundColor Yellow
    }
    Write-Host '-------------------------------------------------------------------'
}
Write-Host

#Create tags and group can take awhile; re-auth to Graph may be required
If( [System.DateTimeOffset]$Global:Authtoken.ExpiresOn -lt [System.DateTimeOffset](Get-Date)){
    $Global:Authtoken = Get-AuthToken -User $GraphAdminUPN
}
## ==============
## Remove Roles
## ==============
Foreach($Rbac in $RbacList)
{
    Write-Host ('Searching for Intune RBAC role [{0}]...' -f $Rbac.Role) -NoNewline
    If(Get-IntuneRole -Name $Rbac.Role)
    {
        Write-Host ("Found") -ForegroundColor Green

        If(!$NoAction)
        {
            Write-Host ('  Removing Intune RBAC role [{0}]...' -f $Rbac.Role) -NoNewline
            Try{
                $Result = Remove-IntuneRole -DisplayName $Rbac.Role
                Write-Host 'Done' -ForegroundColor Green
            }
            Catch{
                Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
            }
        }
        Else{
            Write-Host ('  What if: Performing the operation "Remove-IntuneRole" on target "{0}"' -f $Rbac.Role) -ForegroundColor Cyan
        }
    }
    Else{
        Write-Host ("doesn't exist!") -ForegroundColor Yellow
    }
    Write-Host '-------------------------------------------------------------------'
}
Write-Host

#Create tags and group can take awhile; re-auth to Graph may be required
If( [System.DateTimeOffset]$Global:Authtoken.ExpiresOn -lt [System.DateTimeOffset](Get-Date)){
    $Global:Authtoken = Get-AuthToken -User $GraphAdminUPN
}

## ==============================
## Remove Azure AAD Device groups
## ==============================
Foreach($AadGroup in $TagAndAssignment)
{
    Write-Host ('Searching for Azure AD Dynamic Group [{0}]...' -f $AadGroup.'Scope Groups') -NoNewline
    If(Get-IntuneRoleAADGroup -GroupName $AadGroup.'Scope Groups')
    {
        Write-Host ("Found") -ForegroundColor Green

        If(!$NoAction)
        {
            Write-Host ('  Removing Azure AD Dynamic Group [{0}]...' -f $AadGroup.'Scope Groups') -NoNewline
            Try{
                $Result = Remove-IntuneAADDynamicGroup -GroupName $AadGroup.'Scope Groups'
                Write-Host 'Done' -ForegroundColor Green
            }
            Catch{
                Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
                Continue
            }
        }
        Else{
            Write-Host ('  What If: Performing the operation "Remove-IntuneAADDynamicGroup" on target "{0}"' -f $AadGroup.'Scope Groups') -ForegroundColor Cyan
        }
    }
    Else{
        Write-Host ("doesn't exist!") -ForegroundColor Yellow
    }
    Write-Host '-------------------------------------------------------------------'
}


$totalSecs = [timespan]::fromseconds($stopwatch.Elapsed.TotalSeconds)
Write-Host ("Completed Intune Roles and tag deletion [{0:hh\:mm\:ss}]" -f $totalSecs) -ForegroundColor Green
Write-Host '___________________________________________________________________' -ForegroundColor Green
