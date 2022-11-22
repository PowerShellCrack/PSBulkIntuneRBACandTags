<#
# FULL RUN

.\IntuneRolesCreation.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -DeviceFilter @('Windows','SurfaceHub')
.\IntuneRolesCreation.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -DeviceFilter @('TeamsRoom','TeamsPhone')
.\IntuneRolesCreation.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -DeviceFilter @('iPad','MacOS')
.\IntuneRolesCreation.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -DeviceFilter @('Android','iPhone')

# SAMPLE RUN
# POPULATE Member Group in ManagementRolesSample.csv

.\IntuneRolesCreation.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -DeviceFilter @('Windows','SurfaceHub')

.\IntuneRolesCreation.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -DeviceFilter @('TeamsRoom','TeamsPhone')

.\IntuneRolesCreation.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -DeviceFilter @('iPad','MacOS')

.\IntuneRolesCreation.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -DeviceFilter @('Android','iPhone')

# CLEAN UP
.\IntuneRolesDeletion.ps1 -GraphAdminUPN admin@MSDx012170.onmicrosoft.com -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv

#>


<# SCRIPT TEST:Uxa603dMbR
$global:authToken = Get-AzureAuthToken -User 'admin@MSDx012170.onmicrosoft.com'
$global:authToken = Get-AzureAuthToken -User 'admin@M365x436969.onmicrosoft.com'
$TagAndAssignment = Import-Csv .\ScopeTagAndAssignmentsSample.csv
$TagAndAssignment = Import-Csv .\ScopeTagAndAssignmentsSample.old.csv
$RbacList = Import-Csv .\ManagementRolesSample.csv
$DeviceFilter = @('Windows')
$Tag = $TagAndAssignment[0]
$Tag = $FilteredTagAndAssignment[0]
$TagGroup = ($FilteredTagAndAssignment| Group 'Scope Tags')[0]
$TagGroup = ($FilteredTagAndAssignment | Group 'Scope Tags')[-1]
$AzGroup = $FilteredAzureADGroups[0]
$Rbac = $RbacList[0]
$Rbac = $RbacList[-2]
$TargetGroupId = (Get-IntuneRoleAadGroup -GroupName $Tag.'Scope Groups').id
$Group = $GroupSet[0]

#TEST $iTag = ($Rbac.PSObject.Properties | Where Name -like 'Included Tag*')[0]
#>

<#
#SAMPLE DATA SET 1
$GraphAdminUPN = 'admin@MSDx012170.onmicrosoft.com'
$RbacListPath = '.\ManagementRoles.csv'
$TagAndAssignmentListPath = '.\ScopeTagAndAssignments.csv'
$DefaultAdminAADGroup = 'SG-DMG-EndpointMgr-Admins'
$DeviceFilter = @('Windows')
$SkipRoleAssignment = $false
$SkipRoleTags = $true

#SAMPLE DATA SET 2
$GraphAdminUPN = 'admin@MSDx012170.onmicrosoft.com'
$DefaultAdminAADGroup = "SG-FTE-EndpointMgr-Admins"
$RbacListPath=.\ManagementRolesSample.csv
$TagAndAssignmentListPath=.\ScopeTagAndAssignmentsSample.csv
$DeviceFilter = @()
$SkipRoleAssignment = $false
$SkipRoleTags = $false
#>


#TEST $Rbac = $RbacList[0]
#TEST $Rbac = $RbacList[-2]


<# SAMPLE New-IntuneAadGroup
    $DisplayName = 'SG-AZ-DYN-DMG-WST-Northern California/Pacific-TeamsRoom-1'
    $DisplayName = 'SG-AZ-DYN-DMG-ALL-VirtualMachines'
    $DisplayName = 'SG-AZ-SEC-DMG-ALL-VirtualMachines-Users'
    $Description = 'All Users with Virtual Machines'
    $RuleExpression = '(device.deviceModel -eq "Virtual Machine") or (device.deviceModel -eq "VMware Virtual Platform") or (device.deviceModel -eq "VMware7,1")'
    $GroupType = 'Unified'
#>


<# SAMPLE New-IntuneAADDynamicGroup
    $DisplayName = 'SG-AZ-DYN-DMG-WST-Northern California/Pacific-TeamsRoom-1'
    $Description = 'All Virtual Machines / Vmware'
    $RuleExpression = '(device.deviceModel -eq "Virtual Machine") or (device.deviceModel -eq "VMware Virtual Platform") or (device.deviceModel -eq "VMware7,1")'
#>


<# SAMPLE Update-IntuneAADDynamicGroup
    $DisplayName = 'SG-AZ-DYN-DMG-WST-Northern California/Pacific-TeamsRoom-1'
    $Description = 'All Virtual Machines / Vmware'
    $RuleExpression = '(device.deviceModel -eq "Virtual Machine") or (device.deviceModel -eq "VMware Virtual Platform") or (device.deviceModel -eq "VMware7,1")'
#>

<# SAMPLE Invoke-IntuneRoleAssignmentAll
    $DisplayName = '[Windows VM] for AppsMgr in Region 1'
    $DisplayName = "[NE] Mid-Atlantic Read-Only-Operator's"
    $Description = '[Applications Manager] assignment for region [1] in area [North Carolina]'
    $Id = (Get-IntuneRole -Name 'Application Manager' -IncludeBuiltin).Id
    $Id = (Get-IntuneRole -Name 'DMG-NE-Mid-Atlantic-Read-Only-Operator').Id
    $TargetGroupIds = @()
    $TargetGroupIds += (Get-IntuneRoleAadGroup -GroupName 'DdSecGrp - AutoPilot: All Devices').id
    $TargetGroupIds += (Get-IntuneRoleAadGroup -GroupName 'SG-AZ-DYN-DMG-NE-Mid-Atlantic-Windows-1').id
    $MemberGroupIds = @()
    $MemberGroupIds += (Get-IntuneRoleAadGroup -GroupName 'SG-DMG-EndpointMgr-Admins').id
#>


<# SAMPLE New-IntuneScopeTag
    $DisplayName = 'Powershell / Scripts'
    $Description = 'Powershell Scopetag'
#>

<# SAMPLE Invoke-IntuneRoleAssignment
    $AzureADGroupId = (Get-IntuneRoleAadGroup -GroupName 'SG-AZ-DYN-DMG-NE-Mid-Atlantic-Windows-1').id
    $TargetGroupId = @()
    $TargetGroupId += $AzureADGroupId
    $ID = (Get-IntuneRole -Name 'Application Manager' -IncludeBuiltin).Id
    $id = '5029386e-30ce-4e73-893f-19841cf3c36b'
    $DisplayName = '[Windows VM] for AppsMgr in Region 1'
    $DisplayName = "[NE] Mid-Atlantic Read-Only-Operator's"
    $Description = '[Applications Manager] assignment for region [1] in area [North Carolina]'
    $MemberGroupId = '8da5a66a-dfd8-406d-b1fd-c1cfc5c7a631'

#>

<# SAMPLE Invoke-IntuneRoleAssignmentScopeTag
    #Run sample for Invoke-IntuneRoleAssignment
    $AssignmentId = $Result.Id
    $ScopeTagIds = @()
    $ScopeTagIds += (Get-IntuneScopeTag).id
#>


<#SAMPLE Get-IntuneRoleAssignmentScopeTag
    Run cmdlet Get-IntuneRole
    Run cmdlet Get-IntuneRole -Assignments
    $roleDefinitionId = 'e8b4d266-087d-45b0-be19-590435ffa020'
    $roleAssignmentId = '7207bde2-930d-4ec9-a55c-668ecca55488'
#>


<# SAMPLE Invoke-IntuneScopeTagAssignment
    $ScopeTagId = (Get-IntuneScopeTag).id[1]
    $TargetGroupIds = @()
    $TargetGroupIds += (Get-IntuneRoleAADGroup -GroupName SG-FTE-EndpointMgr-Admins).id
#>
