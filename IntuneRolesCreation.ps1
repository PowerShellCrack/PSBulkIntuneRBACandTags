
<#
.SYNOPSIS
    Creates and assigns Azure AD groups, Tags and Intune RBAC Roles based comma-delimited list

.DESCRIPTION
    Written using Microsoft Graph api calls to creates and assign Azure AD groups and Tags to Intune RBAC Roles.

.NOTES
    Version: 1.4.4

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
    REQUIRED
    Provide Azure UPN to authenticate to Graph

.PARAMETER RbacListPath
    Default value is '.\ManagementRoles.csv'

.PARAMETER TagAndAssignmentListPath
    Default value is '.\ScopeTagAndAssignments.csv'

.PARAMETER DefaultAdminAADGroup
    Default value is 'SG-DMG-EndpointMgr-Admins'

.PARAMETER DeviceFilter
    Can be an Array eg. @('Windows') or @('Windows','Android')

.PARAMETER SkipRoleAssignment
    Skips the role assignment enumeration. No roles will be assigned to their respective Azure AD group

.PARAMETER SkipRoleTags
    Skips the tagging Roles and in the assignments. Tagging roles allows member to view Role and its assignment

.PARAMETER NoPrompts
    Ignores question on creating member groups and forces it

.EXAMPLE
    $Global:Authtoken = Get-AzureAuthToken -User admin@yourdomain.onmicrosoft.com

.EXAMPLE
    #Run script using default values
    .\IntuneRolesCreation.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com

.EXAMPLE
    #Run script using default csv but assign Role members to specified Azure AAD group
    .\IntuneRolesCreation.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com -DefaultAdminAADGroup "SG-FTE-EndpointMgr-Admins"

.EXAMPLE
    #Run script using specified csv files
    .\IntuneRolesCreation.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv

.EXAMPLE
     #Run script using specified csv files and filter only groups with 'Windows' in the name
    .\IntuneRolesCreation.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -DeviceFilter @('Windows')

.EXAMPLE
    #Run script using specified csv files but don't assign Roles to Azure AD groups
    .\IntuneRolesCreation.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -SkipRoleAssignment

.EXAMPLE
    #Run script using specified csv files but don't assign tags to RBAC Roles
    .\IntuneRolesCreation.ps1 -GraphAdminUPN admin@yourdomain.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -SkipRoleTags

.EXAMPLE
    $RbacListPath = '.\ManagementRolesSample.csv'
    $TagAndAssignmentListPath = '.\ScopeTagAndAssignmentsSample.csv'
    $DefaultAdminAADGroup = 'SG-DMG-EndpointMgr-Admins'
    $GraphAdminUPN = 'admin@M365x436969.onmicrosoft.com'
    .\IntuneRolesCreation.ps1 -GraphAdminUPN $GraphAdminUPN -RbacListPath $RbacListPath -TagAndAssignmentListPath $TagAndAssignmentListPath -NoPrompts
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$GraphAdminUPN,

    [ValidateScript({Test-Path $_})]
    $RbacListPath = '.\ManagementRoles.csv',

    [ValidateScript({Test-Path $_})]
    $TagAndAssignmentListPath = '.\ScopeTagAndAssignments.csv',

    $DefaultAdminAADGroup = 'SG-DMG-EndpointMgr-Admins',

    [string[]]$DeviceFilter,

    [switch]$SkipRoleAssignment,

    [switch]$SkipRoleTags,

    [switch]$NoPrompts
)


## =======================================
#  FUNCTIONS
## =======================================

#region FUNCTION: Check if running in ISE
Function Test-IsISE {
    # try...catch accounts for:
    # Set-StrictMode -Version latest
    try {
        return ($null -ne $psISE);
    }
    catch {
        return $false;
    }
}
#endregion

#region FUNCTION: Check if running in Visual Studio Code
Function Test-VSCode{
    if($env:TERM_PROGRAM -eq 'vscode') {
        return $true;
    }
    Else{
        return $false;
    }
}
#endregion

#region FUNCTION: Find script path for either ISE or console
Function Get-ScriptPath {
    <#
        .SYNOPSIS
            Finds the current script path even in ISE or VSC
        .LINK
            Test-MyVSCode
            Test-IsISE
    #>
    param(
        [switch]$Parent
    )

    Begin{}
    Process{
        Try{
            if ($PSScriptRoot -eq "")
            {
                if (Test-IsISE)
                {
                    $ScriptPath = $psISE.CurrentFile.FullPath
                }
                elseif(Test-VSCode){
                    $context = $psEditor.GetEditorContext()
                    $ScriptPath = $context.CurrentFile.Path
                }Else{
                    $ScriptPath = (Get-location).Path
                }
            }
            else
            {
                $ScriptPath = $PSCommandPath
            }
        }
        Catch{
            $ScriptPath = '.'
        }
    }
    End{

        If($Parent){
            Split-Path $ScriptPath -Parent
        }Else{
            $ScriptPath
        }
    }
}
#endregion


#region FUNCTION: Get parameter values from cmdlet
#https://michaellwest.blogspot.com/2013/03/get-validateset-or-enum-options-in_9.html
function Get-ParameterOption {
    param(
        $Command,
        $Parameter
    )

    $parameters = Get-Command -Name $Command | Select-Object -ExpandProperty Parameters
    $type = $parameters[$Parameter].ParameterType
    if($type.IsEnum) {
        [System.Enum]::GetNames($type)
    } else {
        $parameters[$Parameter].Attributes.ValidValues
    }
}
#endregion

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

Function Test-JSON{
    <#
    .SYNOPSIS
    This function is used to test if the JSON passed to a REST Post request is valid

    .DESCRIPTION
    The function tests if the JSON passed to the REST Post is valid

    .EXAMPLE
    Test-JSON -JSON $JSON
    Test if the JSON is valid before calling the Graph REST interface
    #>

    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=0)]
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $validJson = $true

    }
    catch {
        $validJson = $false
        $_.Exception
    }

    Return $validJson

}


####################################################
Function Get-IntuneRoleAadGroup{
    <#
    .SYNOPSIS
    This function is used to get Azure AD Groups from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Groups registered with AAD

    .PARAMETER GroupName
    Specify name of Azure AD group

    .PARAMETER Id
    Specify Id of Azure AD group in GUID format

    .EXAMPLE
    Get-IntuneRoleAadGroup
    Returns all groups within Azure AD

    .EXAMPLE
    Get-IntuneRoleAadGroup -GroupName 'sg-IT'
    Returns security group  object for 'sg-IT'

    .EXAMPLE
    Get-IntuneRoleAadGroup -GroupName 'sg-IT' -Members
    Returns members in security group 'sg-IT'

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-get?view=graph-rest-beta&tabs=http
    #>
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [string]$GroupName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Id')]
        [string]$Id,

        [switch]$Members
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Group_resource = "groups"

    $ShowAll = $True
    if($PsCmdlet.ParameterSetName -eq 'Id'){
        $Property = 'id'
        $Value = $Id
        $FilterString = "?`$filter=id eq '$Id'"
        $ShowAll = $False
    }

    if($PsCmdlet.ParameterSetName -eq 'Name'){
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
Function New-IntuneAadGroup{
    <#
    .SYNOPSIS
    This function is used create Azure AD group

    .DESCRIPTION
    The function connects to the Graph API Interface and creates an Azure AD group

    .EXAMPLE
    New-IntuneAadGroup
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http
    #>
    #
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$False)]
        [string]$RuleExpression,

        [ValidateSet('Unified','DynamicMembership')]
        [string]$GroupType = 'DynamicMembership'
    )

    $graphApiVersion = "beta"
    $Resource = "groups"

    If($GroupType -eq 'DynamicMembership' -and [string]::IsNullOrEmpty($RuleExpression) ){
        Write-Error "You must supply '-RuleExpressions' parameter when GroupType equals 'DynamicMembership'!"
        Break
    }

    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    If($Description){$object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description}
    $object | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @($GroupType)
    $object | Add-Member -MemberType NoteProperty -Name 'mailEnabled' -Value $false
    If($Description){
        $object | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $DisplayName.replace(' ','')
    }Else{
        $object | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $DisplayName.replace(' ','').replace('-','')
    }
    $object | Add-Member -MemberType NoteProperty -Name 'securityEnabled' -Value $true
    If($GroupType -eq 'DynamicMembership'){
        $object | Add-Member -MemberType NoteProperty -Name 'membershipRule' -Value $RuleExpression
        $object | Add-Member -MemberType NoteProperty -Name 'membershipRuleProcessingState' -Value "on"
    }
    $JSON = $object | ConvertTo-Json

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $Result = Invoke-RestMethod -Method Post -Uri $uri -Headers $global:authToken -Body $JSON -ErrorAction Stop
        return $Result

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
Function New-IntuneAADDynamicGroup{
    <#
    .SYNOPSIS
    This function is used create Azure AD dynamic group

    .DESCRIPTION
    The function connects to the Graph API Interface and creates an Azure AD group

    .EXAMPLE
    New-IntuneAADDynamicGroup
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$true)]
        [string]$RuleExpression
    )

    $graphApiVersion = "beta"
    $Resource = "groups"

    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    $object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description
    $object | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @('DynamicMembership')
    $object | Add-Member -MemberType NoteProperty -Name 'mailEnabled' -Value $false
    $object | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $DisplayName.replace(' ','')
    $object | Add-Member -MemberType NoteProperty -Name 'securityEnabled' -Value $true
    $object | Add-Member -MemberType NoteProperty -Name 'membershipRule' -Value $RuleExpression
    $object | Add-Member -MemberType NoteProperty -Name 'membershipRuleProcessingState' -Value "on"
    $JSON = $object | ConvertTo-Json

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $Result = Invoke-RestMethod -Method Post -Uri $uri -Headers $global:authToken -Body $JSON -ErrorAction Stop
        return $Result

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
Function Update-IntuneAadDynamicGroup{
    <#
    .SYNOPSIS
    This function is used update a Azure AD dynamic group

    .DESCRIPTION
    The function connects to the Graph API Interface and updates an Azure AD dynamic group

    .EXAMPLE
    Update-IntuneAadDynamicGroup -DisplayName 'SG-AZ-DYN-DMG-ALL-VirtualMachines' -NewRuleExpression '(device.deviceModel -eq "Virtual Machine") or (device.deviceModel -eq "VMware Virtual Platform")'

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/group-update?view=graph-rest-1.0&tabs=http

    .LINK
    Get-IntuneRoleAadGroup
    #>
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$DisplayName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [string]$Id,

        [string]$NewName,

        [Parameter(Mandatory=$false)]
        [string]$NewDescription,

        [Parameter(Mandatory=$false)]
        [string]$NewRuleExpression
    )

    $graphApiVersion = "beta"
    $Resource = "groups"

    If($PsCmdlet.ParameterSetName -eq 'Name'){
        $ExistingGroup = Get-IntuneRoleAadGroup -GroupName $DisplayName
    }

    If($PsCmdlet.ParameterSetName -eq 'Id'){
        $ExistingGroup = Get-IntuneRoleAadGroup -Id $Id
    }

    If( [string]::IsNullOrEmpty($NewName) -and [string]::IsNullOrEmpty($NewDescription) -and [string]::IsNullOrEmpty($NewRuleExpression) ){
        Write-Verbose "No changes made the group. Please specify an update parameter -NewName, -NewDescription, or -NewRuleExpressison"
        Break
    }

    If($NewRuleExpression){
        If($ExistingGroup.membershipRule -eq $NewRuleExpression){
            Write-Verbose "MembershipRule are the same. No changes made the group"
            Break
        }
    }

    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    If($NewName){
        $object | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $NewName
        $object | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $NewName.replace(' ','')
    }
    If($NewDescription){$object | Add-Member -MemberType NoteProperty -Name 'description' -Value $NewDescription}
    #$object | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @('DynamicMembership')
    #$object | Add-Member -MemberType NoteProperty -Name 'mailEnabled' -Value $false

    $object | Add-Member -MemberType NoteProperty -Name 'securityEnabled' -Value $true
    If($NewRuleExpression){
        $object | Add-Member -MemberType NoteProperty -Name 'membershipRule' -Value $NewRuleExpression
        $object | Add-Member -MemberType NoteProperty -Name 'membershipRuleProcessingState' -Value "on"
    }
    $JSON = $object | ConvertTo-Json

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$($ExistingGroup.Id)"
        $null = Invoke-RestMethod -Method Patch -Uri $uri -Headers $global:authToken -Body $JSON -ErrorAction Stop
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

Function New-IntuneRole{
    <#
    .SYNOPSIS
    This function is used to add an RBAC Role Definitions from the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and adds an RBAC Role Definitions

    .EXAMPLE
    New-IntuneRole -JsonDefinition $JSON

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-get?view=graph-rest-1.0

    .LINK
    Test-JSON
    #>

    [cmdletbinding()]
    param(
        [ValidateScript({Test-JSON $_})]
        [Parameter(Mandatory=$true)]
        [string]$JsonDefinition
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Post -Body $JsonDefinition
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

Function Set-IntuneRole{
    <#
    .SYNOPSIS
    This function is used to set the RBAC Role Definitions from an existing Intune Role

    .DESCRIPTION
     This function is used to set the RBAC Role Definitions from the Graph API REST interface

    .EXAMPLE
    Set-IntuneRole -JsonDefinition $JSON

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-update?view=graph-rest-beta

    .LINK
    Test-JSON
    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Id,

        [ValidateScript({Test-JSON $_})]
        [Parameter(Mandatory=$true)]
        [string]$JsonDefinition,

        [Parameter(Mandatory=$false)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"

    #build Object for JSON body
    $RoleObject = $JsonDefinition | ConvertFrom-Json

    #TEST $RoleObject = $RoleDefinition | ConvertFrom-Json
    If($DisplayName){
        $RoleObject.displayName = $DisplayName
    }
    If($Description){
        $RoleObject.description = $Description
    }
    #build Json body from object
    $JsonDefinition = $RoleObject | ConvertTo-Json -Depth 10
    #test $id='5d789e69-e99d-40dc-aaea-02bddfb2a8bc'
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$($Id)"
        Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Patch -Body $JsonDefinition
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
Function New-IntuneScopeTag{

    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$False)]
        [string]$Description
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleScopeTags"

    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#microsoft.graph.roleScopeTag"
    $object | Add-Member -MemberType NoteProperty -Name "displayName" -Value $DisplayName
    $object | Add-Member -MemberType NoteProperty -Name "description" -Value $Description
    $object | Add-Member -MemberType NoteProperty -Name "isBuiltIn" -Value $false
    $JSON = $object | ConvertTo-Json

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/"
        $result = Invoke-RestMethod -Method Post -Uri $uri -Headers $global:authToken -Body $JSON -ErrorAction Stop
        return $result.id
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
Function Invoke-IntuneRoleAssignment{

    <#
    .SYNOPSIS
    This function is used to set an assignment for an RBAC Role using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and sets and assignment for an RBAC Role

    .PARAMETER DisplayName
    specify a display or friendly name of the role Assignment.

    .PARAMETER DisplayName
    Specify a display or friendly name of the role Assignment.

    .PARAMETER MemberGroupId
    Specify ids of role member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER TargetGroupId
    Specify ids of role scope member security group(s). These are IDs from Azure Active Directory.

    .EXAMPLE
    Invoke-IntuneRoleAssignment -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupId $MemberGroupId -TargetGroupId $TargetGroupId
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/resources/intune-rbac-roleassignment?view=graph-rest-beta
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $Id,

        [Parameter(Mandatory=$true)]
        $DisplayName,

        [Parameter(Mandatory=$false)]
        $Description,

        [Parameter(Mandatory=$true)]
        [string[]]$MemberGroupId,

        [Parameter(Mandatory=$true)]
        [string[]]$TargetGroupId
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleAssignments"


    #build Object for JSON body
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'id' -Value ""
    $object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    $object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description
    $object | Add-Member -MemberType NoteProperty -Name 'members' -Value @($MemberGroupId)
    $object | Add-Member -MemberType NoteProperty -Name 'scopeMembers' -Value @($TargetGroupId)
    $object | Add-Member -MemberType NoteProperty -Name 'roleDefinition@odata.bind' -Value "https://graph.microsoft.com/$graphApiVersion/deviceManagement/roleDefinitions('$Id')"
    $JSON = $object | ConvertTo-Json

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $Result = Invoke-RestMethod -Method Post -Uri $uri -Headers $global:authToken -Body $JSON -ErrorAction Stop
        return $Result

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
Function Update-IntuneRoleAssignmentGroups{

    <#
    .SYNOPSIS
    This function is used to update an assignment for an RBAC Role using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and update an assignment for an RBAC Role

    .PARAMETER DisplayName
    specify a display or friendly name of the role Assignment.

    .PARAMETER DisplayName
    Specify a display or friendly name of the role Assignment.

    .PARAMETER MemberGroupIds
    Specify ids of role member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER TargetGroupIds
    Specify ids of role scope member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER AllDevices

    .PARAMETER AllUsers

    .EXAMPLE
    Update-IntuneRoleAssignmentGroups -RoleDefinitionId '63eaea9a-3ba8-44ef-88eb-79b2f60c9bc1' -AssignmentId 'c1aa9d17-2ef8-4100-940d-517f163bcc5a' -MemberGroupIds $MemberGroupIds -TargetGroupIds $TargetGroupIds
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .EXAMPLE
    Update-IntuneRoleAssignmentGroups -RoleDefinitionId '63eaea9a-3ba8-44ef-88eb-79b2f60c9bc1' -AssignmentId 'c1aa9d17-2ef8-4100-940d-517f163bcc5a' -MemberGroupIds $MemberGroupIds -AllUsers

    .EXAMPLE
    Update-IntuneRoleAssignmentGroups -RoleDefinitionId '63eaea9a-3ba8-44ef-88eb-79b2f60c9bc1' -AssignmentId 'c1aa9d17-2ef8-4100-940d-517f163bcc5a' -MemberGroupIds $MemberGroupIds -AllDevices

    .NOTES
    !!!! STILL WORK IN PROGRESS !!!!

    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roleassignment-update?view=graph-rest-beta
    #>

    [CmdletBinding(DefaultParameterSetName = 'Targeted')]
    param
    (
        [Parameter(Mandatory=$true)]
        $RoleDefinitionId,

        [Parameter(Mandatory=$true)]
        $AssignmentId,

        [Parameter(Mandatory=$false)]
        [string[]]$MemberGroupIds,

        [Parameter(Mandatory = $true, ParameterSetName = 'Targeted')]
        [string[]]$TargetGroupIds,

        [Parameter(Mandatory=$false)]
        $DisplayName,

        [Parameter(Mandatory=$false)]
        $Description,

        [Parameter(Mandatory = $false, ParameterSetName = 'All')]
        [switch]$AllDevices,

        [Parameter(Mandatory = $false, ParameterSetName = 'All')]
        [switch]$AllUsers
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"


    #build Object for JSON body
    If($AllDevices -and $AllUsers){
        $ScopeType = 'allDevicesAndLicensedUsers'
    }
    ElseIf($AllDevices){
        $ScopeType = 'allDevices'
    }
    ElseIf($AllUsers){
        $ScopeType = 'allLicensedUsers'
    }
    Else{
        $ScopeType = 'resourceScope'
    }

    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#microsoft.graph.groupAssignmentTarget"
    #$object | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#microsoft.graph.roleAssignment"
    If($DisplayName){$object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName}
    If($Description){$object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description}
    If($MemberGroupIds.count -gt 0){$object | Add-Member -MemberType NoteProperty -Name 'scopeMembers' -Value @($MemberGroupIds)}
    If($AllDevices -or $AllUsers){
        $object | Add-Member -MemberType NoteProperty -Name 'scopeType' -Value $ScopeType
        #$object | Add-Member -MemberType NoteProperty -Name 'resourceScopes' -Value ''
    }Else{
        $object | Add-Member -MemberType NoteProperty -Name 'resourceScopes' -Value @($TargetGroupIds)
    }
    $JSON = $object | ConvertTo-Json

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$RoleDefinitionId/roleAssignments/$AssignmentId"
        $Result = Invoke-RestMethod -Method Patch -Uri $uri -Headers $global:authToken -Body $JSON -ErrorAction Stop
        return $Result

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
Function Invoke-IntuneRoleAssignmentAll{

    <#
    .SYNOPSIS
    This function is used to set an assignment for an RBAC Role using the Graph API REST interface

    .DESCRIPTION
    The function connects to the Graph API Interface and sets and assignment for an RBAC Role

    .PARAMETER DisplayName
    specify a display or friendly name of the role Assignment.

    .PARAMETER DisplayName
    Specify a display or friendly name of the role Assignment.

    .PARAMETER MemberGroupIds
    Specify ids of role member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER TargetGroupIds
    Specify ids of role scope member security group(s). These are IDs from Azure Active Directory.

    .PARAMETER AllDevices

    .PARAMETER AllUsers

    .EXAMPLE
    Invoke-IntuneRoleAssignmentAll -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupIds $MemberGroupIds -TargetGroupIds $TargetGroupIds
    Creates and Assigns and Intune Role assignment to an Intune Role in Intune

    .EXAMPLE
    Invoke-IntuneRoleAssignmentAll -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupIds $MemberGroupIds -AllUsers

    .EXAMPLE
    Invoke-IntuneRoleAssignmentAll -Id $IntuneRoleID -DisplayName "Assignment" -MemberGroupIds $MemberGroupIds -AllDevices


    .NOTES
    !!!! STILL WORK IN PROGRESS !!!!

    REFERENCE: https://docs.microsoft.com/en-us/graph/api/resources/intune-rbac-roleassignment?view=graph-rest-beta
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $Id,

        [Parameter(Mandatory=$true)]
        $DisplayName,

        [Parameter(Mandatory=$false)]
        $Description,

        [Parameter(Mandatory=$true)]
        [string[]]$MemberGroupIds,

        [Parameter(Mandatory=$true)]
        [string[]]$TargetGroupIds,

        [switch]$AllDevices,

        [switch]$AllUsers
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"


    #build Object for JSON body
    If($AllDevices -and $AllUsers){
        $ScopeType = 'allDevicesAndLicensedUsers'
    }
    ElseIf($AllDevices){
        $ScopeType = 'allDevices'
    }
    ElseIf($AllUsers){
        $ScopeType = 'allLicensedUsers'
    }
    Else{
        $ScopeType = 'resourceScope'
    }

    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#microsoft.graph.roleAssignment"
    $object | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    $object | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description
    $object | Add-Member -MemberType NoteProperty -Name 'scopeMembers' -Value @($MemberGroupIds)
    $object | Add-Member -MemberType NoteProperty -Name 'scopeType' -Value $ScopeType
    If($AllDevices -or $AllUsers){
        $object | Add-Member -MemberType NoteProperty -Name 'resourceScopes' -Value ''
    }Else{
        $object | Add-Member -MemberType NoteProperty -Name 'resourceScopes' -Value @($TargetGroupIds)
    }
    $JSON = $object | ConvertTo-Json

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$Id/roleAssignments"
        $Result = Invoke-RestMethod -Method Post -Uri $uri -Headers $global:authToken -Body $JSON -ErrorAction Stop
        return $Result

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
Function Get-IntuneScopeTagAssignment{
    <#
    .DESCRIPTION
    This function updates the scope tag for an assignment

    .PARAMETER ScopeTagId
    Gets the assignment of scope tag using Id

    .PARAMETER ScopeTagName
    Gets the assignment of scope tag using Name

    .EXAMPLE
    Get-IntuneScopeTagAssignment -ScopeTagId 1

    .EXAMPLE
    Get-IntuneScopeTagAssignment -ScopeTagName SiteRegion1

    .NOTES

    .LINK
    Get-IntuneScopeTag
    #>
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [int32]$ScopeTagId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$ScopeTagName
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleScopeTags"

    If($ScopeTagName){
        $ScopeTagId = (Get-IntuneScopeTag -DisplayName $ScopeTagName).id
    }

    If($ScopeTagId){
        $ScopeTagName = (Get-IntuneScopeTag -Id $ScopeTagId).DisplayName
    }
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$ScopeTagId/assignments"
        $Result = Invoke-RestMethod -Method Get -Uri $uri -Headers $global:authToken -ErrorAction Stop
        If($Result){
            $ResultObj = "" | Select ScopeName,ScopeId,AssignmentId,GroupId
            $ResultObj.ScopeName = $ScopeTagName
            $ResultObj.ScopeId = $ScopeTagId
            $ResultObj.AssignmentId = $Result.Value.id
            $ResultObj.GroupId = $Result.Value.target.groupId

            Return $ResultObj
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
Function Invoke-IntuneScopeTagAssignment{
    <#
    .DESCRIPTION
    This function assigns an Azure Ad group to tag

    .PARAMETER ScopeTagId


    .PARAMETER TargetGroupIds


    .EXAMPLE
    Invoke-IntuneScopeTagAssignment


    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-assign?view=graph-rest-beta

    .LINK
    Get-IntuneScopeTag
    ConvertFrom-Json
    #>
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [int32]$ScopeTagId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$ScopeTagName,

        [Parameter(Mandatory=$true)]
        [string[]]$TargetGroupIds
    )


    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleScopeTags"

    If($ScopeTagName){
        $ScopeTagId = (Get-IntuneScopeTag -DisplayName $ScopeTagName).id
    }

    $AutoTagObject = @()
    foreach ($TargetGroupId in $TargetGroupIds)
    {
        #Build custom object for assignment
        $AssignmentProperties = "" | Select id,target
        $AssignmentProperties.id = ($TargetGroupId + '_' + $ScopeTagId)


        #Build custom object for target
        $targetProperties = "" | Select "@odata.type",deviceAndAppManagementAssignmentFilterId,deviceAndAppManagementAssignmentFilterType,groupId
        $targetProperties."@odata.type" = "microsoft.graph.groupAssignmentTarget"
        $targetProperties.deviceAndAppManagementAssignmentFilterId = $null
        $targetProperties.deviceAndAppManagementAssignmentFilterType = 'none'
        $targetProperties.groupId = $TargetGroupId

        #add target object to assignment
        $AssignmentProperties.target = $targetProperties

        $AutoTagObject += $AssignmentProperties

    }
    #build body object
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($AutoTagObject)
    $JSON = $object | ConvertTo-Json -Depth 10

   try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$ScopeTagId/assign"
        $Result = Invoke-RestMethod -Method Post -Uri $uri -Headers $global:authToken -Body $JSON -ErrorAction Stop
        Return $Result.value.id
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $rea der = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose ("Request to {0} failed with HTTP Status {1}: {2}" -f $Uri,$ex.Response.StatusCode,$ex.Response.StatusDescription)
        Write-Error ("{0}" -f $responseBody)
    }
}




####################################################
Function Get-IntuneRoleAssignmentGroups{
    <#
    .DESCRIPTION
    This function gets the Groups for a Role assignment

    .PARAMETER RoleDefinitionId
    Role Definition Id. Use Get-IntuneRole to get definition id

    .PARAMETER RoleAssignmentId
    Assignment Id. Use  Get-IntuneScopeTagAssignment to get assignment id

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-get?view=graph-rest-beta

    .LINK
    Get-IntuneScopeTagAssignment
    Get-IntuneRole
    #>
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [string]$DisplayName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Id')]
        [string]$Id
    )

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleAssignments"

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
Function Invoke-IntuneRoleAssignmentScopeTag{
    <#
    .DESCRIPTION
    This function updates the scope tag for a Role assignment

    .PARAMETER AssignmentId
    Role assignment Id. Use Get-IntuneRoleAssignmentScopeTag to get id

    .PARAMETER $ScopeTagIds
    Array of Tag Ids to set. Use Get-IntuneScopeTag to get id's

    .EXAMPLE
    Invoke-IntuneRoleAssignmentScopeTag -AssignmentId 'c08c5ab7-b73e-4c4f-a12b-00bb9d1b7262' -ScopeTagIds @('57','58')

    This example updates the scope tags ids for the Assignment

    .LINK
    Get-IntuneRoleAssignmentScopeTag
    Get-IntuneScopeTag
    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AssignmentId,

        [Parameter(Mandatory=$true)]
        [string[]]$ScopeTagIds
    )


    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleAssignments"

    #build Object for JSON body
    foreach ($ScopeTagid in $ScopeTagids) {
        $object = New-Object -TypeName PSObject
        $object | Add-Member -MemberType NoteProperty -Name '@odata.id' -Value "https://graph.microsoft.com/$graphApiVersion/deviceManagement/roleScopeTags('$ScopeTagId')"
        $JSON = $object | ConvertTo-Json

        try {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$AssignmentId/roleScopeTags/`$ref"
            $Null = Invoke-RestMethod -Method Post -Uri $uri -Headers $global:authToken  -Body $JSON
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

}


####################################################

Function New-IntuneRoleDefinitionBeta{
    <#
    .SYNOPSIS
    Th

    .DESCRIPTION
    Creates a roleDefinition object for

    .PARAMETER DisplayName
    Specifies a display name.

    .PARAMETER Description
    Specifies a description.

    .PARAMETER PermissionSet
    Specify built-in role permissions.

    .PARAMETER RolePermissions
    Specify role permissions dot format. Can be in an array @()

    .PARAMETER ScopeTags
    Specify Tag integer Ids. Can be in an array @()

    .PARAMETER AsJson
    returns json format of definition

    .EXAMPLE
    New-IntuneRoleDefinitionBeta -DisplayName "Reporting role" -AsJson
    Generates a new Role definition object with empty permissions sets in json format

    .EXAMPLE
    New-IntuneRoleDefinitionBeta -DisplayName "Reporting role" -Description "Powershell create Reporting role" -PermissionSet Report-Only -ScopeTags @(1,2) -AsJson
    Generates a new Role definition object with report only permissions with scope tags presets in json format

    .EXAMPLE
    New-IntuneRoleDefinitionBeta -DisplayName "new role" -Description "Testing powershell automation" -PermissionSet Report-Only -ScopeTags @(1,2) -rolePermissions @("Microsoft.Intune_PolicySets_Read", "Microsoft.Intune_EndpointAnalytics_Read") -AsJson
    Generates a new Role definition object with report only permissions presets, plus additional access, in json format

    .OUTPUTS
    PSObject. New-IntuneRoleDefinitionBeta returns Definition object by default
    Json. New-IntuneRoleDefinitionBeta returns json format of definition if -AsJson specified

    .NOTES
    REFERENCE: https://docs.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-get?view=graph-rest-1.0

    .LINK
    New-IntuneRoleAssignment
    #>

    param
    (
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Application-Manager','Help-Desk-Operator','Read-Only-Operator','Report-Only','Endpoint-Security-Manager')]
        [string]$PermissionSet,

        [Parameter(Mandatory=$false)]
        [string[]]$RolePermissions,

        [Parameter(Mandatory=$false)]
        [string[]]$ScopeTags,

        [Parameter(Mandatory=$false)]
        [switch]$AsJson
    )

    $Actions = @()

    Switch($PermissionSet){
        'Application-Manager' {
            $Actions = @(
                "Microsoft.Intune_Organization_Read",
                "Microsoft.Intune_MobileApps_Create",
                "Microsoft.Intune_MobileApps_Read",
                "Microsoft.Intune_MobileApps_Update",
                "Microsoft.Intune_MobileApps_Delete",
                "Microsoft.Intune_MobileApps_Assign",
                "Microsoft.Intune_MobileApps_Relate",
                "Microsoft.Intune_ManagedDevices_Read",
                "Microsoft.Intune_ManagedApps_Create",
                "Microsoft.Intune_ManagedApps_Read",
                "Microsoft.Intune_ManagedApps_Update",
                "Microsoft.Intune_ManagedApps_Delete",
                "Microsoft.Intune_ManagedApps_Assign",
                "Microsoft.Intune_ManagedApps_Wipe",
                "Microsoft.Intune_AndroidSync_Read",
                "Microsoft.Intune_AndroidSync_UpdateApps",
                "Microsoft.Intune_DeviceConfigurations_Read",
                "Microsoft.Intune_PolicySets_Assign",
                "Microsoft.Intune_PolicySets_Create",
                "Microsoft.Intune_PolicySets_Delete",
                "Microsoft.Intune_PolicySets_Read",
                "Microsoft.Intune_PolicySets_Update",
                "Microsoft.Intune_AssignmentFilter_Create",
                "Microsoft.Intune_AssignmentFilter_Delete",
                "Microsoft.Intune_AssignmentFilter_Read",
                "Microsoft.Intune_AssignmentFilter_Update",
                "Microsoft.Intune_MicrosoftDefenderATP_Read",
                "Microsoft.Intune_MicrosoftStoreForBusiness_Read",
                "Microsoft.Intune_WindowsEnterpriseCertificate_Read",
                "Microsoft.Intune_PartnerDeviceManagement_Read",
                "Microsoft.Intune_MobileThreatDefense_Read",
                "Microsoft.Intune_CertificateConnector_Read",
                "Microsoft.Intune_DerivedCredentials_Read",
                "Microsoft.Intune_Customization_Read"
            )
        }

        'Help-Desk-Operator' {
            $Actions = @(
                "Microsoft.Intune_MobileApps_Read",
                "Microsoft.Intune_MobileApps_Assign",
                "Microsoft.Intune_ManagedApps_Read",
                "Microsoft.Intune_ManagedApps_Assign",
                "Microsoft.Intune_ManagedApps_Wipe",
                "Microsoft.Intune_ManagedDevices_Read",
                "Microsoft.Intune_ManagedDevices_Update",
                "Microsoft.Intune_ManagedDevices_SetPrimaryUser",
                "Microsoft.Intune_ManagedDevices_ViewReports",
                "Microsoft.Intune_RemoteTasks_Wipe",
                "Microsoft.Intune_RemoteTasks_Retire",
                "Microsoft.Intune_RemoteTasks_RemoteLock",
                "Microsoft.Intune_RemoteTasks_ResetPasscode",
                "Microsoft.Intune_RemoteTasks_EnableLostMode",
                "Microsoft.Intune_RemoteTasks_DisableLostMode",
                "Microsoft.Intune_RemoteTasks_LocateDevice",
                "Microsoft.Intune_RemoteTasks_PlayLostModeSound",
                "Microsoft.Intune_RemoteTasks_SetDeviceName",
                "Microsoft.Intune_RemoteTasks_RebootNow",
                "Microsoft.Intune_RemoteTasks_ShutDown",
                "Microsoft.Intune_RemoteTasks_RequestRemoteAssistance",
                "Microsoft.Intune_RemoteTasks_EnableWindowsIntuneAgent",
                "Microsoft.Intune_RemoteTasks_CleanPC",
                "Microsoft.Intune_RemoteTasks_ManageSharedDeviceUsers",
                "Microsoft.Intune_RemoteTasks_SyncDevice",
                "Microsoft.Intune_RemoteTasks_WindowsDefender",
                "Microsoft.Intune_RemoteTasks_RotateBitLockerKeys",
                "Microsoft.Intune_RemoteTasks_UpdateDeviceAccount",
                "Microsoft.Intune_RemoteTasks_RevokeAppleVppLicenses",
                "Microsoft.Intune_RemoteTasks_CustomNotification",
                "Microsoft.Intune_RemoteTasks_ActivateDeviceEsim",
                "Microsoft.Intune_DeviceConfigurations_Read",
                "Microsoft.Intune_DeviceConfigurations_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_Read",
                "Microsoft.Intune_DeviceCompliancePolices_ViewReports",
                "Microsoft.Intune_TelecomExpenses_Read",
                "Microsoft.Intune_RemoteAssistance_Read",
                "Microsoft.Intune_RemoteAssistanceApp_ViewScreen",
                "Microsoft.Intune_RemoteAssistanceApp_TakeFullControl",
                "Microsoft.Intune_RemoteAssistanceApp_Elevation",
                "Microsoft.Intune_Organization_Read",
                "Microsoft.Intune_EndpointProtection_Read",
                "Microsoft.Intune_EnrollmentProgramToken_Read",
                "Microsoft.Intune_AppleEnrollmentProfiles_Read",
                "Microsoft.Intune_AppleDeviceSerialNumbers_Read",
                "Microsoft.Intune_DeviceEnrollmentManagers_Read",
                "Microsoft.Intune_CorporateDeviceIdentifiers_Read",
                "Microsoft.Intune_TermsAndConditions_Read",
                "Microsoft.Intune_Roles_Read",
                "Microsoft.Intune_AndroidSync_Read",
                "Microsoft.Intune_Audit_Read",
                "Microsoft.Intune_RemoteTasks_GetFileVaultKey",
                "Microsoft.Intune_RemoteTasks_RotateFileVaultKey",
                "Microsoft.Intune_SecurityBaselines_Read",
                "Microsoft.Intune_PolicySets_Read",
                "Microsoft.Intune_RemoteTasks_ConfigurationManagerAction",
                "Microsoft.Intune_RemoteTasks_DeviceLogs",
                "Microsoft.Intune_AssignmentFilter_Read",
                "Microsoft.Intune_EndpointAnalytics_Read",
                "Microsoft.Intune_MicrosoftDefenderATP_Read",
                "Microsoft.Intune_MicrosoftStoreForBusiness_Read",
                "Microsoft.Intune_WindowsEnterpriseCertificate_Read",
                "Microsoft.Intune_PartnerDeviceManagement_Read",
                "Microsoft.Intune_MobileThreatDefense_Read",
                "Microsoft.Intune_CertificateConnector_Read",
                "Microsoft.Intune_DerivedCredentials_Read",
                "Microsoft.Intune_Customization_Read"
            )

        }

        'Read-Only-Operator' {
            $Actions = @(
                "Microsoft.Intune_MobileApps_Read",
                "Microsoft.Intune_TermsAndConditions_Read",
                "Microsoft.Intune_ManagedApps_Read",
                "Microsoft.Intune_ManagedDevices_Read",
                "Microsoft.Intune_ManagedDevices_ViewReports",
                "Microsoft.Intune_DeviceConfigurations_Read",
                "Microsoft.Intune_DeviceConfigurations_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_Read",
                "Microsoft.Intune_DeviceCompliancePolices_ViewReports",
                "Microsoft.Intune_TelecomExpenses_Read",
                "Microsoft.Intune_RemoteAssistance_Read",
                "Microsoft.Intune_RemoteAssistance_ViewReports",
                "Microsoft.Intune_Organization_Read",
                "Microsoft.Intune_EndpointProtection_Read",
                "Microsoft.Intune_EnrollmentProgramToken_Read",
                "Microsoft.Intune_AppleEnrollmentProfiles_Read",
                "Microsoft.Intune_AppleDeviceSerialNumbers_Read",
                "Microsoft.Intune_DeviceEnrollmentManagers_Read",
                "Microsoft.Intune_CorporateDeviceIdentifiers_Read",
                "Microsoft.Intune_Roles_Read",
                "Microsoft.Intune_Reports_Read",
                "Microsoft.Intune_AndroidSync_Read",
                "Microsoft.Intune_Audit_Read",
                "Microsoft.Intune_RemoteTasks_GetFileVaultKey",
                "Microsoft.Intune_SecurityBaselines_Read",
                "Microsoft.Intune_PolicySets_Read",
                "Microsoft.Intune_EndpointAnalytics_Read",
                "Microsoft.Intune_AssignmentFilter_Read",
                "Microsoft.Intune_MicrosoftDefenderATP_Read",
                "Microsoft.Intune_Customization_Read",
                "Microsoft.Intune_MicrosoftStoreForBusiness_Read",
                "Microsoft.Intune_WindowsEnterpriseCertificate_Read",
                "Microsoft.Intune_PartnerDeviceManagement_Read",
                "Microsoft.Intune_MobileThreatDefense_Read",
                "Microsoft.Intune_CertificateConnector_Read",
                "Microsoft.Intune_DerivedCredentials_Read"
            )

        }

        'Report-Only' {
            $Actions = @(
                "Microsoft.Intune_ManagedDevices_ViewReports",
                "Microsoft.Intune_DeviceConfigurations_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_ViewReports",
                "Microsoft.Intune_RemoteAssistance_ViewReports",
                "Microsoft.Intune_MobileApps_ViewReports"
            )
        }

        'Endpoint-Security-Manager' {
            $Actions = @(
                "Microsoft.Intune_MobileApps_Read",
                "Microsoft.Intune_TermsAndConditions_Read",
                "Microsoft.Intune_ManagedApps_Read",
                "Microsoft.Intune_ManagedDevices_Delete",
                "Microsoft.Intune_ManagedDevices_Read",
                "Microsoft.Intune_ManagedDevices_Update",
                "Microsoft.Intune_ManagedDevices_SetPrimaryUser",
                "Microsoft.Intune_ManagedDevices_ViewReports",
                "Microsoft.Intune_DeviceConfigurations_Read",
                "Microsoft.Intune_DeviceConfigurations_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_Create",
                "Microsoft.Intune_DeviceCompliancePolices_Read",
                "Microsoft.Intune_DeviceCompliancePolices_ViewReports",
                "Microsoft.Intune_DeviceCompliancePolices_Update",
                "Microsoft.Intune_DeviceCompliancePolices_Delete",
                "Microsoft.Intune_DeviceCompliancePolices_Assign",
                "Microsoft.Intune_TelecomExpenses_Read",
                "Microsoft.Intune_RemoteAssistance_Read",
                "Microsoft.Intune_RemoteAssistance_ViewReports",
                "Microsoft.Intune_Organization_Read",
                "Microsoft.Intune_EndpointProtection_Read",
                "Microsoft.Intune_EnrollmentProgramToken_Read",
                "Microsoft.Intune_AppleEnrollmentProfiles_Read",
                "Microsoft.Intune_AppleDeviceSerialNumbers_Read",
                "Microsoft.Intune_DeviceEnrollmentManagers_Read",
                "Microsoft.Intune_CorporateDeviceIdentifiers_Read",
                "Microsoft.Intune_Roles_Read",
                "Microsoft.Intune_Reports_Read",
                "Microsoft.Intune_AndroidSync_Read",
                "Microsoft.Intune_Audit_Read",
                "Microsoft.Intune_RemoteTasks_ConfigurationManagerAction",
                "Microsoft.Intune_RemoteTasks_GetFileVaultKey",
                "Microsoft.Intune_RemoteTasks_RebootNow",
                "Microsoft.Intune_RemoteTasks_RemoteLock",
                "Microsoft.Intune_RemoteTasks_RotateBitLockerKeys",
                "Microsoft.Intune_RemoteTasks_RotateFileVaultKey",
                "Microsoft.Intune_RemoteTasks_ShutDown",
                "Microsoft.Intune_RemoteTasks_SyncDevice",
                "Microsoft.Intune_RemoteTasks_WindowsDefender",
                "Microsoft.Intune_SecurityBaselines_Create",
                "Microsoft.Intune_SecurityBaselines_Read",
                "Microsoft.Intune_SecurityBaselines_Update",
                "Microsoft.Intune_SecurityBaselines_Delete",
                "Microsoft.Intune_SecurityBaselines_Assign",
                "Microsoft.Intune_SecurityTasks_Read",
                "Microsoft.Intune_SecurityTasks_Update",
                "Microsoft.Intune_PolicySets_Read",
                "Microsoft.Intune_AssignmentFilter_Read",
                "Microsoft.Intune_EndpointAnalytics_Read",
                "Microsoft.Intune_MicrosoftDefenderATP_Read",
                "Microsoft.Intune_MicrosoftStoreForBusiness_Read",
                "Microsoft.Intune_WindowsEnterpriseCertificate_Read",
                "Microsoft.Intune_PartnerDeviceManagement_Read",
                "Microsoft.Intune_MobileThreatDefense_Read",
                "Microsoft.Intune_CertificateConnector_Read",
                "Microsoft.Intune_DerivedCredentials_Read",
                "Microsoft.Intune_Customization_Read"
            )
        }
    }

    #append any additional permission sets to action list
    If($rolePermissions){
        $Actions += $rolePermissions | Select -Unique
    }

    #added default if not scopes have been specified
    If(-Not($ScopeTags)){
        $ScopeTags += 0
    }

    #build roles permissions object
    #v1.0 $rolesProperties = "" | Select '@odata.type',displayName,description,roleScopeTagIds,permissions,isBuiltInRoleDefinition
    $rolesProperties = "" | Select '@odata.type',displayName,description,roleScopeTagIds,permissions,rolePermissions,isBuiltInRoleDefinition,isBuiltIn
    $rolesProperties.'@odata.type' = '#microsoft.graph.roleDefinition'
    $rolesProperties.displayName = $DisplayName
    If($Description){$rolesProperties.description = $Description}

    If($ScopeTags.count -gt 0){$rolesProperties.roleScopeTagIds = $ScopeTags}
    #Build custom object for actions
    #v1.0 $actionsProperties = "" | Select actions
    $actionsProperties = "" | Select "@odata.type",actions,resourceActions
    $actionsProperties."@odata.type" = "microsoft.graph.rolePermission"
    $actionsProperties.actions = $Actions

    #build resourceActions object
    $resourceProperties = "" | Select "@odata.type",allowedResourceActions,notAllowedResourceActions
    $resourceProperties."@odata.type" = "microsoft.graph.resourceAction"
    $resourceProperties.allowedResourceActions = $Actions
    $resourceProperties.notAllowedResourceActions = @()
    #$resourceProperties
    #append to roles
    $actionsProperties.resourceActions = @($resourceProperties)

    #append actions to permissions as object within an array @()
    $rolesProperties.permissions = @($actionsProperties)
    $rolesProperties.rolePermissions = @($actionsProperties)

    #Added builtin role definition
    $rolesProperties.isBuiltInRoleDefinition = $false
    #beta
    $rolesProperties.isBuiltIn = $false
    #convert to json
    #$rolesProperties
    $data = $rolesProperties
    If($AsJson){
        $data = ConvertTo-json $rolesProperties -Depth 10
    }

    return $data
}


## =======================================
#  MAIN
## =======================================
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

##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VARIABLES: Building paths & values
# Use function to get paths because Powershell ISE & other editors have different results
[string]$scriptPath = Get-ScriptPath
[string]$scriptRoot = Split-Path -Path $scriptPath -Parent

##*=============================================
##* Collect Intune Roles
##*=============================================

#collect Intune roles
$CurrentRbacRoles = Get-IntuneRole -IncludeBuiltin

#collect default permission sets and make it a regex string
$DefaultRoleTemplates = (Get-ParameterOption -Command New-IntuneRoleDefinitionBeta -Parameter PermissionSet)

#check if default group is created; if not create it
If(-Not(Get-IntuneRoleAadGroup -GroupName $DefaultAdminAADGroup) ){
    If($NoPrompts){
        Write-Host ('[{0}] group was not found in Azure AD. Creating group....' -f $DefaultAdminAADGroup) -ForegroundColor Yellow
        $CreateDefaultGroup = 'Y'
    }
    Else{
        Write-Host ('[{0}] group was not found in Azure AD. Please specify an existing default Azure AD group for Member assignment' -f $DefaultAdminAADGroup) -ForegroundColor Red
        $CreateDefaultGroup = Read-host ("Would you like to create the Azure Ad group [{0}]? [Y or N]" -f $DefaultAdminAADGroup)
    }

    If($CreateDefaultGroup -eq 'Y'){
        Try{
            $Result = New-IntuneAadGroup -DisplayName $DefaultAdminAADGroup -GroupType Unified -ErrorAction Stop
        }
        Catch{
            Write-Host ('Failed. {0}' -f ($_.exception.message | ConvertFrom-Json).error.message) -ForegroundColor Red
            Exit
        }
    }
    Else{Exit}
}

##*=============================================
##* 1. Import New Roles info
##*=============================================
#append $ to each device type based on naming convention
#Builds regex filter (eg. "Windows$|iOS-Mobile$")
$FilterRegex = ($DeviceFilter | %{$_ + '$'}) -join '|'

#Import RBAC csv and filter out and empty roles
$RbacList = Import-Csv $RbacListPath
$RbacList = $RbacList | Where Role -ne ''

#Import Tag csv and apply any device filters
$TagAndAssignment = Import-Csv $TagAndAssignmentListPath
#both collects have same values, used to distinguish iteration in script
If($TagAndAssignment| Get-Member | Where Name -eq 'Device Type'){
    $FilteredTagAndAssignment = $TagAndAssignment | Where 'Device Type' -Match $FilterRegex
    $FilteredAzureADGroups = $TagAndAssignment | Where 'Device Type' -Match $FilterRegex
}
Else{
    $FilteredTagAndAssignment = $TagAndAssignment | Where 'Scope Tags' -Match $FilterRegex
    $FilteredAzureADGroups = $TagAndAssignment | Where 'Scope Tags' -Match $FilterRegex
}

#Build error report for rbac list
$ErrorDated = "_errors-$(Get-Date -Format 'yyyy-MM-dd_Thh-mm-ss-tt').csv"
$RbacListErrorReportCsv = $RbacListPath.replace('.csv','') + $ErrorDated
#Build  error report for scope tags and assignments
$TagAndAssignmentErrorReportCsv = $TagAndAssignmentListPath.replace('.csv','') + $ErrorDated

##*=============================================
##* 2: Build Azure AD dynamic groups (filtered)
##*=============================================
$NewAadGrp = @()
$UpdatedAadGrp = 0
$FailedNewAadGrp = @()
$a = 0
Foreach($AzGroup in $FilteredAzureADGroups)
{
    $a++
    Write-Host ("[{0} of {1}] " -f $a, $FilteredAzureADGroups.count) -NoNewline

    #check to see if rule is longer than supported length; will skip creation if true
    If($AzGroup.Criteria.Length -gt 3072)
    {
            $ErrorMsg = ("{0}'s Criteria Rule expression is longer [{1}] than supported characters [{2}]."-f $AzGroup.'Scope Groups',$AzGroup.Criteria.Length,3072)
            Write-Host $ErrorMsg -ForegroundColor Red
            Write-Host "Refer to: 'https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/groups-dynamic-membership#rule-syntax-for-a-single-expression'" -ForegroundColor Cyan
            $AzGroup | Add-Member NoteProperty 'Error Reason' -Value $ErrorMsg -Force
            $AzGroup | Export-Csv "$scriptRoot\$TagAndAssignmentErrorReportCsv" -NoTypeInformation -Append
            Continue
    }

    Write-Host ('Searching for Azure AD Dynamic Group [{0}]...' -f $AzGroup.'Scope Groups') -NoNewline

    #Create new Azure Ad group if not already exists; Azure AD groups can have same name
    $ExistingAadGroup = Get-IntuneRoleAadGroup -GroupName $AzGroup.'Scope Groups'
    If(!$ExistingAadGroup)
    {
        #create dynamic group
        Try{
            $NewAadGrp += New-IntuneAadGroup -DisplayName $AzGroup.'Scope Groups' -Description $AzGroup.'Scope Tags' -RuleExpression $AzGroup.Criteria -GroupType DynamicMembership -ErrorAction Stop
            Write-Host 'Created' -ForegroundColor Green
        }
        Catch{
            $ErrorMsg = ($_.exception.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
            Write-Host ('Failed. {0}' -f $ErrorMsg) -ForegroundColor Red
            $FailedNewAadGrp += ('[{0}] :: {1}' -f $tag.'Scope Tags',$ErrorMsg)
            $AzGroup | Add-Member NoteProperty 'Error Reason' -Value $ErrorMsg -Force
            $AzGroup | Export-Csv "$scriptRoot\$TagAndAssignmentErrorReportCsv" -NoTypeInformation -Append
            Continue
        }
    }
    #Check to see if the rules in list are equal to existing groups rule; if not, attempt to update them
    ElseIf($ExistingAadGroup.membershipRule -ne $AzGroup.Criteria)
    {
        #update dynamic group rule expression
        Try{
            Update-IntuneAadDynamicGroup -DisplayName $AzGroup.'Scope Groups' -NewRuleExpression $AzGroup.Criteria -ErrorAction Stop
            $UpdatedAadGrp ++
            Write-Host 'Updated Rule Expression' -ForegroundColor Yellow
        }
        Catch{
            $ErrorMsg = ($_.exception.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
            Write-Host ('Failed. {0}' -f $ErrorMsg) -ForegroundColor Red
            $FailedNewAadGrp += ('[{0}] :: {1}' -f $tag.'Scope Tags',$ErrorMsg)
            $AzGroup | Add-Member NoteProperty 'Error Reason' -Value $ErrorMsg -Force
            $AzGroup | Export-Csv "$scriptRoot\$TagAndAssignmentErrorReportCsv" -NoTypeInformation -Append
            Continue
        }
    }
    Else{
        Write-Host ('Already exists!') -ForegroundColor Cyan
    }
}

Write-Host '-------------------------------------------------------------------'

##*=============================================
##* 3: Build Intune Scope Tags
##*=============================================
$NewTags = 0
$NewTagsAssigned = 0
$FailedNewTags = @()
$FailedAssignTag = @()
$GroupedTags = $FilteredTagAndAssignment | Group 'Scope Tags'
$t=0
#Group all items with same scopetags
Foreach($TagGroup in $GroupedTags)
{
    $t++
    Write-Host ("[{0} of {1}] " -f $t, $GroupedTags.count) -NoNewline

    #Create tags and group can take awhile; re-auth to Graph may be required
    If( [System.DateTimeOffset]$Global:Authtoken.ExpiresOn -lt [System.DateTimeOffset](Get-Date)){
        $Global:Authtoken = Get-AzureAuthToken -User $GraphAdminUPN
    }

    #grab all items in group with similar tags
    $GroupSet = ($TagGroup | Select -ExpandProperty Group)

    #grab just first item from selection to build the tag
    $Tag = $GroupSet[0]


    #Build description from values
    $TargetType = ($Tag.'Scope Tags').replace($Tag.Region,'').replace($Tag.Area,'').replace('-',' ').Trim()
    $Description = ('[{0}] devices assigned to the [{2}] area in [{1}] region' -f $TargetType,$Tag.Region,$Tag.Area)

    Write-Host ('Creating scope tag [{0}]...' -f $Tag.'Scope Tags') -NoNewline
    If(-Not(Get-IntuneScopeTag -DisplayName $Tag.'Scope Tags')){
        Try{
            $TagId = New-IntuneScopeTag -DisplayName $Tag.'Scope Tags' -Description $Description -ErrorAction Stop
            $NewTags ++
            Write-Host ('Done.') -ForegroundColor Green
            Write-Verbose ('Tag ID: {0}' -f $TagId)
        }
        Catch{
            $ErrorMsg = ($_.exception.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
            Write-Host ('Failed. {0}' -f $ErrorMsg) -ForegroundColor Red
            $FailedNewTags += ('[{0}] :: {1}' -f $Tag.'Scope Tags',$ErrorMsg)
            #only output whats needed
            $TagError = $Tag | Select Region,Area,'Scope Tags','Scope Groups'
            $TagError | Add-Member NoteProperty 'Error Reason' -Value $$ErrorMsg -Force
            $TagError | Export-Csv "$scriptRoot\$TagAndAssignmentErrorReportCsv" -NoTypeInformation -Append
        }
        Finally{
            Start-Sleep 5
        }
    }
    Else{
        Write-Host ('Already exists!') -ForegroundColor Cyan
    }

    #Sometimes multiple azure group exist for each tag
    $TargetGroupIds = @()
    Foreach($Group in $GroupSet){
        $TargetGroupIds += (Get-IntuneRoleAadGroup -GroupName $Group.'Scope Groups').id
    }

    #get tag id
    $ScopeTagId = (Get-IntuneScopeTag -DisplayName $Tag.'Scope Tags').id

    If($TargetGroupIds.count -gt 0)
    {
        $TagAssignments = Get-IntuneScopeTagAssignment -ScopeTagId $ScopeTagId
        Write-Host ('Assigning tag [{0}] to {1} Azure AD group(s)...' -f $Tag.'Scope Tags',$TargetGroupIds.count) -NoNewline

        #determine if there needs to be an assignment
        $AssignTags = $true
        If($TagAssignments.GroupId)
        {
            #If assignment exists; compare already assigned Id's, if they are different attempt to rebuild assignment
            If( $null -eq (Compare-Object -ReferenceObject $TagAssignments.GroupId -DifferenceObject $TargetGroupIds) ){
                Write-Host ('{0} group(s) already assigned!' -f $TargetGroupIds.count) -ForegroundColor Cyan
                $AssignTags = $false
            }
            Else{
                Write-Host ('Updating...') -NoNewline -ForegroundColor Yellow
            }
        }

        #Assign scope tags
        If($AssignTags)
        {
            Try{
                $TagAssignId = Invoke-IntuneScopeTagAssignment -ScopeTagId $ScopeTagId -TargetGroupIds $TargetGroupIds -ErrorAction Stop
                $NewTagsAssigned ++
                Write-Host ('Done.') -ForegroundColor Green
                Write-Verbose (' Assignment ID: {0}' -f $TagAssignId)
            }
            Catch{
                $ErrorMsg = ($_.exception.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
                Write-Host ('Failed. {0}' -f $ErrorMsg) -ForegroundColor Red
                $FailedAssignTags += ('[{0}] :: {1}' -f $Tag.'Scope Tags',$ErrorMsg)
                $TagGroup | Add-Member NoteProperty 'Error Reason' -Value $ErrorMsg -Force
                $TagGroup | Export-Csv "$scriptRoot\$TagAndAssignmentErrorReportCsv" -NoTypeInformation -Append
            }
            Finally{
                #give Azure time to refresh
                Start-Sleep 5
            }
        }
    }
    Else{
        $ErrorMsg = ('Unable to assign tag to Azure AD group [{0}]; group does not exist!' -f $Tag.'Scope Tags')
        Write-Host $ErrorMsg -ForegroundColor Red
        $TagGroup | Add-Member NoteProperty 'Error Reason' -Value $ErrorMsg -Force
        $TagGroup | Export-Csv "$scriptRoot\$TagAndAssignmentErrorReportCsv" -NoTypeInformation -Append
    }
    Write-Host '-------------------------------------------------------------------'
}

#collect current scope tags
$CurrentScopeTags = Get-IntuneScopeTag

##*=============================================
##* 4. Build Intune RBAC Roles
##*=============================================
$NewRoles = @()
$FailedRoleDef = @()
$FailedNewRole = @()
$FailedRoleAssign = @()
$FailedAadGrpId =@()
$NewRolesAssign = 0
$UpdateRolesAssign = 0
$r = 0
<#TESTS
$Rbac = $RbacList[0]
$Rbac = $RbacList[-1]
#>
Foreach($Rbac in $RbacList)
{
    $r++
    Write-Host ("[{0} of {1}] " -f $r, $RbacList.count) -NoNewline

    #Create tags and group can take awhile; re-auth to Graph may be required
    If( [System.DateTimeOffset]$Global:Authtoken.ExpiresOn -lt [System.DateTimeOffset](Get-Date)){
        $Global:Authtoken = Get-AzureAuthToken -User $GraphAdminUPN
    }

    #attempt to find role within the the available permission sets
    #Does role name exist within Intune roles?
    #Does role DEFINITION exist within default role within cmdlet
    #Does role NAME exist within built-in name
    If($Rbac.'Role Definition' -in $CurrentRbacRoles.displayName){
        $PermissionsToSet = ($CurrentRbacRoles | Where displayName -eq $Rbac.'Role Definition').rolePermissions.actions
        $RoleName = $Rbac.'Role Definition'
        $UseTemplateRoles = $False
    }
    ElseIf($Rbac.'Role Definition' -in $DefaultRoleTemplates){
        $PermissionsToSet = $Rbac.'Role Definition'
        $RoleName = $Rbac.'Role Definition'
        $UseTemplateRoles = $True
    }
    ElseIf($Rbac.Role -in $DefaultRoleTemplates){
        $PermissionsToSet = $Rbac.Role
        $RoleName = $Rbac.Role
        $UseTemplateRoles = $True
    }
    Else{
        $PermissionsToSet = 'Read-Only-Operator'
        $RoleName = $PermissionsToSet
        $UseTemplateRoles = $True
    }
    #Build description from values
    $Description = ('Defined permissions based on [{0}] for region [{1}] in area [{2}]' -f $RoleName,$Rbac.Region,$Rbac.Area)

    ## ========================
    ## Get Role Tag Ids
    ## ========================
    #build Tag ids based on Included tag columns
    $ScopeTags = @()

    #Get all tags and build list
    Foreach($iTag in $Rbac.PSObject.Properties | Where {$_.Name -like 'Included Tag*'} ){
        $Tagid = $null
        #Check to see if tag has been created first
        If($iTag.Value -in $CurrentScopeTags.displayname)
        {
            #check if tag is within the filtered devices
            If($iTag.Value -Match $FilterRegex){
                $Tagid = ($CurrentScopeTags | Where displayname -eq $iTag.Value).id
                $ScopeTags += $Tagid
            }

        }
    }


    ## ========================
    ## Build RBAC Permissions
    ## ========================

    $RoleDefParams = @{}

    $RoleDefParams += @{
        DisplayName=$Rbac.Role
        Description=$Description
    }

    If($UseTemplateRoles){
        $RoleDefParams += @{
            PermissionSet=$PermissionsToSet
        }
    }Else{
        $RoleDefParams += @{
            rolePermissions=$PermissionsToSet
        }
    }

    If(!$SkipRoleTags){
        $RoleDefParams += @{
            ScopeTags=$ScopeTags
        }
    }

    Try{
        Write-Host ('Generating [{1}] permissions definition for role [{0}]...' -f $Rbac.Role,$RoleName) -NoNewline
        $RoleDefinition = New-IntuneRoleDefinitionBeta @RoleDefParams -AsJson -ErrorAction Stop
        Write-Host 'Done' -ForegroundColor Green
    }
    Catch{
        Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
        $FailedRoleDef += ('[{0}] :: {1}' -f $Rbac.Role,$_.exception.message)
        Continue
    }

    ## ========================
    ## Create RBAC Role
    ## ========================
    #check to see if name Role exist already
    If($Rbac.Role -notin $CurrentRbacRoles.displayName)
    {
        Try{
            Write-Host ('Creating Intune RBAC role [{0}]...' -f $Rbac.Role) -NoNewline
            $NewRoles += New-IntuneRole -JsonDefinition $RoleDefinition
            Write-Host 'Done' -ForegroundColor Green
        }
        Catch{
            Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
            $FailedNewRole += ('[{0}] :: {1}' -f $Rbac.Role,$_.exception.message)
        }
        Finally{
            #give azure time to process request
            Start-Sleep 10
        }
    }
    Else{
        #Write-Host ('Existing Intune RBAC role [{0}] cannot be updated with [{1}] definition. Please remove role and re-run script' -f $Rbac.Role,$RoleName) -ForegroundColor Red

        $RoleDetails = ($CurrentRbacRoles | Where displayName -eq $Rbac.Role)
        $date = Get-date -Format 'yyyy-MM-dd_Thh-mm-ss-tt'
        Try{
            Write-Host ('Editing Intune RBAC role [{0}]...' -f $Rbac.Role) -NoNewline
            $ExistingRoles += Set-IntuneRole -Id  $RoleDetails.id -JsonDefinition $RoleDefinition -Description ($RoleDetails.description + ' | updated:' + $date)
            Write-Host 'Done' -ForegroundColor Green
        }
        Catch{
            Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
            $FailedNewRole += ('[{0}] :: {1}' -f $Rbac.Role,$_.exception.message)
        }
        Finally{
            #give azure time to process request
            Start-Sleep 10
        }
    }

    ## ===========================
    ## Assign Roles to Azure group
    ## ===========================
    If($SkipRoleAssignment -eq $false)
    {
        #get the new role id
        $IntuneRoleID = (Get-IntuneRole -Name $Rbac.Role).id

        #get the member group for the Role; default to defined group if not specified
        If($Rbac.'Member Group'){
            $MemberGroup = $Rbac.'Member Group'
        }
        Else{
            $MemberGroup = $DefaultAdminAADGroup
        }

        #get member group id
        $MemberGroupId = (Get-IntuneRoleAadGroup -GroupName $MemberGroup).id
        #if member group does not exist in Azure AD, create it
        If(!$MemberGroupId)
        {
            Write-Host ('[{0}] group was not found in Azure AD' -f $MemberGroup) -ForegroundColor Yellow
            If($NoPrompts){
                $CreateMemberGroup = 'Y'
            }
            Else{
                $CreateMemberGroup = Read-host ("Would you like to create the Azure Ad group [{0}]? [Y or N]" -f $MemberGroup)
            }

            If($CreateMemberGroup -eq 'Y'){
                Write-Host ('Creating Azure AD user assigned group [{0}]...' -f $MemberGroup) -NoNewline
                Try{
                    $Result = New-IntuneAadGroup -DisplayName $MemberGroup -GroupType Unified -ErrorAction Stop
                    $MemberGroupId = $Result.id
                    Write-Host 'Done' -ForegroundColor Green -NoNewline
                    Write-Host (' ID: {0}' -f $Result.id) -ForegroundColor Yellow
                }
                Catch{
                    Write-Host ('Failed. {0}' -f ($_.exception.message | ConvertFrom-Json).error.message) -ForegroundColor Red
                    $MemberGroup = $DefaultAdminAADGroup
                }
            }
            Else{$MemberGroup = $DefaultAdminAADGroup}
        }

        #define AADGroups as an array first (that way count 1 will show in output)
        $AADGroups = @()
        #get targeted Azure group(s) from list
        $AADGroups += $FilteredTagAndAssignment | Where {$_.Region -eq $Rbac.Region -and $_.Area -eq $Rbac.Area} | Select 'Scope Groups','Scope Tags'

        $TargetGroupIds = @()
        #TEST $AADGroup = $AADGroups[0]
        #Loop through each group and grab its id.
        $g = 0
        Foreach($AADGroup in $AADGroups)
        {
            $g++
            Write-Host ("[{0} of {1}] Searching for Azure AD group [{2}]..." -f $g, $AADGroups.count, $AADGroup.'Scope Groups') -NoNewline
            $TargetGroupId = (Get-IntuneRoleAadGroup -GroupName $AADGroup.'Scope Groups').id
            If($TargetGroupId){
                Write-Host ("Added") -ForegroundColor Green
                Write-Verbose ("Azure AD group Id is: {0}" -f $TargetGroupId)
                $TargetGroupIds += $TargetGroupId
            }
            Else{
                Write-Host ("Not Added") -ForegroundColor Red
                Write-Verbose ("Azure AD group not found for the tag [{0}]"  -f $AADGroup.'Scope Tags')
                $FailedAadGrpId += ('[{0}] :: Missing AzureAD group [{1}]' -f $Rbac.Role, $AADGroup.'Scope Tags')
                Continue
            }
        }
        Write-Verbose ('  Found ({0} out of {1}) Azure AD group(s) to assign to Role [{2}]' -f $TargetGroupIds.count, $AADGroups.count,$Rbac.Role)

        If( ($TargetGroupIds.count -gt 0) -and $IntuneRoleID)
        {
            #generate descriptive assignment name
            If($DeviceFilter){
                $AssignmentName = ("{2} ({1}) {0} - {3}" -f $RoleName,$Rbac.Region,$Rbac.Area,($DeviceFilter -join '-'))
            }
            Else{
                $AssignmentName = ("{2} ({1}) {0} - All Devices" -f $RoleName,$Rbac.Region,$Rbac.Area)
            }

            Write-Host ('Assigning [{1}] Azure AD group(s) to Intune role [{0}] as [{2}]...' -f $Rbac.Role,$TargetGroupIds.count,$AssignmentName) -NoNewline
            $CurrentAssignments = @()
            $CurrentAssignments += (Get-IntuneRole -Name $Rbac.Role -Assignments).displayName
            If( $AssignmentName -notin $CurrentAssignments )
            {
                Try{
                    $Result = Invoke-IntuneRoleAssignment -Id $IntuneRoleID -DisplayName $AssignmentName -MemberGroupId $MemberGroupId -TargetGroupId $TargetGroupIds -ErrorAction Stop
                    If(!$SkipRoleTags){Invoke-IntuneRoleAssignmentScopeTag -AssignmentId $Result.Id -ScopeTagIds $ScopeTags -ErrorAction Stop}
                    $NewRolesAssign ++
                    Write-Host 'Done' -ForegroundColor Green
                }
                Catch{
                    $ErrorMsg = ($_.exception.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
                    Write-Host ('Failed. {0}' -f $ErrorMsg) -ForegroundColor Red
                    $FailedRoleAssign += ('[{0}] :: {1}' -f $AssignmentName,$ErrorMsg)
                    $Rbac | Add-Member NoteProperty 'Error Reason' -Value $ErrorMsg -Force
                    $Rbac | Export-Csv "$scriptRoot\$RbacListErrorReportCsv" -NoTypeInformation -Append
                }
            <#}
            TODO Check target group within assignment and update it
            ElseIf($null -ne (Compare-Object -ReferenceObject $TargetGroupIds -DifferenceObject (Get-IntuneRoleAssignmentGroups -DisplayName $AssignmentName).scopeMembers) )
            {
                Try{
                    $Result = Update-IntuneRoleAssignmentGroups -RoleDefinitionId $RoleDefinitionId -AssignmentId $RoleAssignmentId -MemberGroupIds $MemberGroupId -TargetGroupIds $TargetGroupIds -ErrorAction Stop
                    If(!$SkipRoleTags){Update-IntuneRoleAssignmentScopeTag -AssignmentId $Result.Id -ScopeTagIds $ScopeTags -ErrorAction Stop}
                    $UpdateRolesAssign ++
                    Write-Host 'Updated' -ForegroundColor Yellow
                }
                Catch{
                    $ErrorMsg = ($_.exception.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
                    Write-Host ('Failed. {0}' -f $ErrorMsg) -ForegroundColor Red
                    $FailedRoleAssign += ('[{0}] :: {1}' -f $AssignmentName,$ErrorMsg)
                    $Rbac | Add-Member NoteProperty 'Error Reason' -Value $ErrorMsg -Force
                    $Rbac | Export-Csv "$scriptRoot\$RbacListErrorReportCsv" -NoTypeInformation -Append
                }
            #>
            }
            Else{
                Write-Host ("Already assigned!") -ForegroundColor Cyan
            }
        }
        Else{
            Write-Host ("Unable to assign Azure AD groups to role; non exist") -ForegroundColor Red
        }
        Write-Host '-------------------------------------------------------------------'
    } # End -SkipRoleAssignment check
}


## =====================
## SUMMARY REPORT
## =====================
Write-Host
$stopwatch.Stop()
$totalSecs = [timespan]::fromseconds($stopwatch.Elapsed.TotalSeconds)
Write-Host ("Completed Intune Roles and tag generation [{0:hh\:mm\:ss}]" -f $totalSecs) -ForegroundColor Green
Write-Host '___________________________________________________________________' -ForegroundColor Green
Write-Host ("New Azure Ad groups created:     {0}" -f $NewAadGrp.count) -ForegroundColor Green
Write-Host ("Updated Azure Ad groups:         {0}" -f $UpdatedAadGrp) -ForegroundColor Yellow
Write-Host ("Failed created Azure Ad Groups:  {0}" -f $FailedNewAadGrp.count) -ForegroundColor Red
Write-Host
Write-Host ("New Scope Tags created:          {0}" -f $NewTags) -ForegroundColor Green
Write-Host ("New Scope Tags assigned          {0}" -f $NewTagsAssigned) -ForegroundColor Green
Write-Host ("Failed creating Scope Tags:      {0}" -f $FailedNewTags.count) -ForegroundColor Red
Write-Host ("Failed assigning Scope tags:     {0}" -f $FailedAssignTag.count) -ForegroundColor Red
Write-Host
Write-Host ("New Roles created:               {0}" -f $NewRoles.count) -ForegroundColor Green
Write-Host ("Failed Role definitions:         {0}" -f $FailedRoleDef.count) -ForegroundColor Red
Write-Host ("Failed create New Roles:         {0}" -f $FailedNewRole.count) -ForegroundColor Red
Write-Host
Write-Host ("New Roles assigned:              {0}" -f $NewRolesAssign) -ForegroundColor Green
#Write-Host ("Updated assigned roles:          {0}" -f $UpdateRolesAssign) -ForegroundColor Yellow
Write-Host ("Failed retrieving AAD group IDs: {0}" -f $FailedAadGrpId.count) -ForegroundColor Red
Write-Host ("Failed Assigning new Roles:      {0}" -f $FailedRoleAssign.count) -ForegroundColor Red
Write-Host '___________________________________________________________________' -ForegroundColor Green
Write-Host
