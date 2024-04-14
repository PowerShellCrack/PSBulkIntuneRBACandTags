
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

.PARAMETER RbacListPath
    Default value is '.\ManagementRoles.csv'

.PARAMETER TagAndAssignmentListPath
    Default value is '.\ScopeTagAndAssignments.csv'

.PARAMETER DefaultAdminEntraGroup
    Default value is 'SG-AZ-Intune-Admins'

.PARAMETER DeviceFilter
    Can be an Array eg. @('Windows') or @('Windows','Android')

.PARAMETER SkipRoleAssignment
    Skips the role assignment enumeration. No roles will be assigned to their respective Azure AD group

.PARAMETER SkipRoleTags
    Skips the tagging Roles and in the assignments. Tagging roles allows member to view Role and its assignment

.PARAMETER NoPrompts
    Ignores question on creating member groups and forces it

.EXAMPLE
    #Run script using default values
    .\IntuneRolesCreation.ps1

.EXAMPLE
    #Run script using default csv but assign Role members to specified Azure AAD group
    .\IntuneRolesCreation.ps1 -DefaultAdminEntraGroup "SG-FTE-Intune-Admins"

.EXAMPLE
    #Run script using specified csv files
    .\IntuneRolesCreation.ps1 -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv

.EXAMPLE
     #Run script using specified csv files and filter only groups with 'Windows' in the name
    .\IntuneRolesCreation.ps1 -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -DeviceFilter @('Windows')

.EXAMPLE
    #Run script using specified csv files but don't assign Roles to Azure AD groups
    .\IntuneRolesCreation.ps1 -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -SkipRoleAssignment

.EXAMPLE
    #Run script using specified csv files but don't assign tags to RBAC Roles
    .\IntuneRolesCreation.ps1 -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -SkipRoleTags

.EXAMPLE
    $RbacListPath = '.\ManagementRolesSample.csv'
    $TagAndAssignmentListPath = '.\ScopeTagAndAssignmentsSample.csv'
    $DefaultAdminEntraGroup = 'SG-AZ-Intune-Admins'
    .\IntuneRolesCreation.ps1 -RbacListPath $RbacListPath -TagAndAssignmentListPath $TagAndAssignmentListPath -NoPrompts
#>


[CmdletBinding()]
param (
    [ValidateScript({Test-Path $_})]
    $RbacListPath = '.\ManagementRoles.csv',

    [ValidateScript({Test-Path $_})]
    $TagAndAssignmentListPath = '.\ScopeTagAndAssignments.csv',

    $DefaultAdminEntraGroup = 'SG-AZ-Intune-Admins',

    [string[]]$DeviceFilter,

    [switch]$SkipRoleAssignment,

    [switch]$SkipRoleTags,

    [switch]$NoPrompts
)

Import-Module 'Microsoft.Graph.Authentication'
Import-Module 'Microsoft.Graph.Applications'
Import-Module 'Az.Accounts'
Install-Module 'IDMCmdlets' -MinimumVersion 1.0.2.4 -Force


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
function Get-ParameterOption {
    <#
    .NOTES
    
    #https://michaellwest.blogspot.com/2013/03/get-validateset-or-enum-options-in_9.html
    #>
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

## =======================================
#  MAIN
## =======================================
$stopwatch =  [system.diagnostics.stopwatch]::StartNew()
## =======================================
$Global:GraphEndpoint = 'https://graph.microsoft.com'
Connect-MgGraph 


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
$CurrentRbacRoles = Get-IDMRole -IncludeBuiltin

#collect default permission sets and make it a regex string
$DefaultRoleTemplates = (Get-ParameterOption -Command New-IDMRoleDefinition -Parameter PermissionSet)

#check if default group is created; if not create it
If(-Not(Get-IDMAzureGroup -GroupName $DefaultAdminEntraGroup) ){
    If($NoPrompts){
        Write-Host ('[{0}] group was not found in Azure AD. Creating group....' -f $DefaultAdminEntraGroup) -ForegroundColor Yellow
        $CreateDefaultGroup = 'Y'
    }
    Else{
        Write-Host ('[{0}] group was not found in Azure AD. Please specify an existing default Azure AD group for Member assignment' -f $DefaultAdminEntraGroup) -ForegroundColor Red
        $CreateDefaultGroup = Read-host ("Would you like to create the Azure Ad group [{0}]? [Y or N]" -f $DefaultAdminEntraGroup)
    }

    If($CreateDefaultGroup -eq 'Y'){
        Try{
            $Result = New-IDMAzureGroup -DisplayName $DefaultAdminEntraGroup -GroupType Unified -ErrorAction Stop
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
$NewAzureGrp = @()
$UpdatedAzureGrp = 0
$FailedNewAzureGrp = @()
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
    $ExistingAzureGroup = Get-IDMAzureGroup -GroupName $AzGroup.'Scope Groups'
    If(!$ExistingAzureGroup)
    {
        #create dynamic group
        Try{
            $NewAzureGrp += New-IDMAzureGroup -DisplayName $AzGroup.'Scope Groups' -Description $AzGroup.'Scope Tags' -RuleExpression $AzGroup.Criteria -GroupType DynamicMembership -ErrorAction Stop
            Write-Host 'Created' -ForegroundColor Green
        }
        Catch{
            $ErrorMsg = ($_.exception.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
            Write-Host ('Failed. {0}' -f $ErrorMsg) -ForegroundColor Red
            $FailedNewAzureGrp += ('[{0}] :: {1}' -f $tag.'Scope Tags',$ErrorMsg)
            $AzGroup | Add-Member NoteProperty 'Error Reason' -Value $ErrorMsg -Force
            $AzGroup | Export-Csv "$scriptRoot\$TagAndAssignmentErrorReportCsv" -NoTypeInformation -Append
            Continue
        }
    }
    #Check to see if the rules in list are equal to existing groups rule; if not, attempt to update them
    ElseIf($ExistingAzureGroup.membershipRule -ne $AzGroup.Criteria)
    {
        #update dynamic group rule expression
        Try{
            Update-IDMAzureDynamicGroup -DisplayName $AzGroup.'Scope Groups' -NewRuleExpression $AzGroup.Criteria -ErrorAction Stop
            $UpdatedAzureGrp ++
            Write-Host 'Updated Rule Expression' -ForegroundColor Yellow
        }
        Catch{
            $ErrorMsg = ($_.exception.message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
            Write-Host ('Failed. {0}' -f $ErrorMsg) -ForegroundColor Red
            $FailedNewAzureGrp += ('[{0}] :: {1}' -f $tag.'Scope Tags',$ErrorMsg)
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

    #grab all items in group with similar tags
    $GroupSet = ($TagGroup | Select -ExpandProperty Group)

    #grab just first item from selection to build the tag
    $Tag = $GroupSet[0]


    #Build description from values
    $TargetType = ($Tag.'Scope Tags').replace($Tag.Region,'').replace($Tag.Area,'').replace('-',' ').Trim()
    $Description = ('[{0}] devices assigned to the [{2}] area in [{1}] region' -f $TargetType,$Tag.Region,$Tag.Area)

    Write-Host ('Creating scope tag [{0}]...' -f $Tag.'Scope Tags') -NoNewline
    If(-Not(Get-IDMScopeTag -DisplayName $Tag.'Scope Tags')){
        Try{
            $TagId = New-IDMScopeTag -DisplayName $Tag.'Scope Tags' -Description $Description -ErrorAction Stop
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
        $TargetGroupIds += (Get-IDMAzureGroup -GroupName $Group.'Scope Groups').id
    }

    #get tag id
    $ScopeTagId = (Get-IDMScopeTag -DisplayName $Tag.'Scope Tags').id

    If($TargetGroupIds.count -gt 0)
    {
        $TagAssignments = Get-IDMScopeTagAssignment -ScopeTagId $ScopeTagId
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
                $TagAssignId = Invoke-IDMScopeTagAssignment -ScopeTagId $ScopeTagId -TargetGroupIds $TargetGroupIds -ErrorAction Stop
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
$CurrentScopeTags = Get-IDMScopeTag

##*=============================================
##* 4. Build Intune RBAC Roles
##*=============================================
$NewRoles = @()
$FailedRoleDef = @()
$FailedNewRole = @()
$FailedRoleAssign = @()
$FailedAzureGrpId =@()
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
        $RoleDefinition = New-IDMRoleDefinition @RoleDefParams -AsJson -ErrorAction Stop
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
            $NewRoles += New-IDMRole -JsonDefinition $RoleDefinition
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
            $ExistingRoles += Set-IDMRole -Id  $RoleDetails.id -JsonDefinition $RoleDefinition -Description ($RoleDetails.description + ' | updated:' + $date)
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
        $IntuneRoleID = (Get-IDMRole -Name $Rbac.Role).id

        #get the member group for the Role; default to defined group if not specified
        If($Rbac.'Member Group'){
            $MemberGroup = $Rbac.'Member Group'
        }
        Else{
            $MemberGroup = $DefaultAdminEntraGroup
        }

        #get member group id
        $MemberGroupId = (Get-IDMAzureGroup -GroupName $MemberGroup).id
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
                    $Result = New-IDMAzureGroup -DisplayName $MemberGroup -GroupType Unified -ErrorAction Stop
                    $MemberGroupId = $Result.id
                    Write-Host 'Done' -ForegroundColor Green -NoNewline
                    Write-Host (' ID: {0}' -f $Result.id) -ForegroundColor Yellow
                }
                Catch{
                    Write-Host ('Failed. {0}' -f ($_.exception.message | ConvertFrom-Json).error.message) -ForegroundColor Red
                    $MemberGroup = $DefaultAdminEntraGroup
                }
            }
            Else{$MemberGroup = $DefaultAdminEntraGroup}
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
            $TargetGroupId = (Get-IDMAzureGroup -GroupName $AADGroup.'Scope Groups').id
            If($TargetGroupId){
                Write-Host ("Added") -ForegroundColor Green
                Write-Verbose ("Azure AD group Id is: {0}" -f $TargetGroupId)
                $TargetGroupIds += $TargetGroupId
            }
            Else{
                Write-Host ("Not Added") -ForegroundColor Red
                Write-Verbose ("Azure AD group not found for the tag [{0}]"  -f $AADGroup.'Scope Tags')
                $FailedAzureGrpId += ('[{0}] :: Missing AzureAD group [{1}]' -f $Rbac.Role, $AADGroup.'Scope Tags')
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
            $CurrentAssignments += (Get-IDMRole -Name $Rbac.Role -Assignments).displayName
            If( $AssignmentName -notin $CurrentAssignments )
            {
                Try{
                    $Result = Invoke-IDMRoleAssignment -Id $IntuneRoleID -DisplayName $AssignmentName -MemberGroupId $MemberGroupId -TargetGroupId $TargetGroupIds -ErrorAction Stop
                    If(!$SkipRoleTags){Invoke-IDMRoleAssignmentScopeTag -AssignmentId $Result.Id -ScopeTagIds $ScopeTags -ErrorAction Stop}
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
            ElseIf($null -ne (Compare-Object -ReferenceObject $TargetGroupIds -DifferenceObject (Get-IDMRoleAssignmentGroups -DisplayName $AssignmentName).scopeMembers) )
            {
                Try{
                    $Result = Update-IDMRoleAssignmentGroups -RoleDefinitionId $RoleDefinitionId -AssignmentId $RoleAssignmentId -MemberGroupIds $MemberGroupId -TargetGroupIds $TargetGroupIds -ErrorAction Stop
                    If(!$SkipRoleTags){Update-IDMRoleAssignmentScopeTag -AssignmentId $Result.Id -ScopeTagIds $ScopeTags -ErrorAction Stop}
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
Write-Host ("New Azure Ad groups created:     {0}" -f $NewAzureGrp.count) -ForegroundColor Green
Write-Host ("Updated Azure Ad groups:         {0}" -f $UpdatedAzureGrp) -ForegroundColor Yellow
Write-Host ("Failed created Azure Ad Groups:  {0}" -f $FailedNewAzureGrp.count) -ForegroundColor Red
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
Write-Host ("Failed retrieving AAD group IDs: {0}" -f $FailedAzureGrpId.count) -ForegroundColor Red
Write-Host ("Failed Assigning new Roles:      {0}" -f $FailedRoleAssign.count) -ForegroundColor Red
Write-Host '___________________________________________________________________' -ForegroundColor Green
Write-Host
