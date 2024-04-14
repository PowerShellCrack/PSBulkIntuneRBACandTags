# Bulk Intune RBAC Role and Tag creation script

This script is written using Microsoft Graph api calls to creates and assign Azure Entra groups and Tags to Intune RBAC Roles.

## Requirements

### Modules

- Microsoft.Graph.Authentication
- Microsoft.Graph.Applications
- Az.Accounts
- IDMCmdlets

### Site list

Site Code|Region|Area
|--|--|--|
|Required (a)|Required (a)|Required (a)|

### Scope Tag with Assignment List

- Must be in csv format. Can be generated using _GenerateScopeGroups.ps1_ script. Columns used are:

Region|Area|Device Type|Scope Tags|Scope Groups|Criteria
|--|--|--|--|--|--|
|Required (a)|Required (a)|Optional (f)|Required|Required|Required (c)|


### RBAC list

- Must be in csv format. Can be exported using from _CBP Intune Management Tags Groups Roles.xlsx_. Columns used are:

Org|Region|Area|Role Definition|Role|Included Tag #|Scope Tags|Member Group|
|--|--|--|--|--|--|--|--|
|Required|Required (a)|Required (a)|Optional (d)|Required|Required (b)|Required|Optional (e)|


### Key

- (a) --> Used to match corresponding role with tag
- (b) --> At least one tag is needed, increment column # (eg. Included Tag 1, Included Tag 2, etc)
- (c) --> Length cannot be more that 3072 characters (Azure limitation)
- (d) --> If defined, will use that for permissions set, vs looking at Role
- (e) --> If not provided, will default to scripts parameter _DefaultAdminAADGroup_
- (f) --> Specifying a device type will align with device filter; otherwise filter will look in Scope tag for matches

## Scripts

- __GenerateScopeGroups.ps1__ --> Export a the ScopeTagAndAssignments.csv based on Site data
- __IntuneRolesCreation.ps1__ --> Creates and assigns Azure Entra groups, Tags and Intune RBAC Roles based comma-delimited list
- __IntuneRolesDeletion.ps1__ --> Deletes Azure Entra groups, Tags and Intune RBAC Roles based comma-delimited list


### Parameters

|Parameter | Value Type | Explanation | Creation Script | Deletion Script | Generate Script|
|--|--|--|--|--|--|
| GraphAdminUPN| UPN | Provides UPN to authenticate to Graph. MFA/Password screen may popup behind script | x | x ||
| RbacListPath | CSV | Default value is _.\ManagementRoles.csv_. Specify full path to csv file | x | x ||
| TagAndAssignmentListPath | CSV | Default value is _.\ScopeTagAndAssignments.csv_. Specify full path to csv file | x | x | x |
| SourceListPath | CSV | Specify full path to csv file for Site data ||| x |
| DefaultAdminAADGroup | string | Default value is 'SG-AZ-EndpointMgr-Admins'. If group is not found in Azure Entra, script will prompt to create it as user assigned type | x | ||
| DeviceFilter | array | Must be an Array _eg. @('Windows'), @('Windows','Android')_.<br>- Values that can be used are: _'Windows','macOS','iPhone','iPad','Android','SurfaceHub','TeamsRoom','TeamsPhone'_.<br>-  Values should corresponding with ending of Tags and ending of Azure Entra groups in csv lists. This will filter the creation of Azure Entra groups as well as assigning tags.<br> __See Work Around__ | x ||
| SkipRoleAssignment | switch |  Skips the role assignment enumeration. No roles will be assigned to their respective Azure Entra group |x|||
| SkipRoleTags | switch | Skips the tagging Roles and in the assignments. Tagging roles allows member to view Role and its assignment |x|||
| NoPrompt | switch | Does not ask to create Azure Entra member groups; would prompt for DefaultAdminAADGroup and when 'Member Group' column is populated |x|||
| NoAction | switch | Does nothing and simulates action using _Whatif_ like output ||x||
| Verbose | switch | Very noisy but does output additional information | x | x | x |


### Example Calls

```powershell
# GENERATE EXAMPLE 1
#Run script using SiteList.sample.csv
.\GenerateScopeGroups.ps1 -DataListPath '.\SampleData\SiteList.sample.csv'

# CREATE EXAMPLE 1
#Run script using default values (graph UPN required)
.\IntuneRolesCreation.ps1 -GraphAdminUPN 'admin@yourdomain.onmicrosoft.com'

# CREATE EXAMPLE 2
#Run script using default csv but assign Role members to specified Azure AAD group
.\IntuneRolesCreation.ps1 -GraphAdminUPN 'admin@yourdomain.onmicrosoft.com' -DefaultAdminAADGroup "SG-FTE-EndpointMgr-Admins"

# CREATE EXAMPLE 3
#Run script using specified csv files
.\IntuneRolesCreation.ps1 -GraphAdminUPN 'admin@yourdomain.onmicrosoft.com' -RbacListPath '.\SampleData\ManagementRolesSample.csv' -TagAndAssignmentListPath '.\ScopeTagAndAssignmentsSample.csv'

# CREATE EXAMPLE 4
#Run script using specified csv files and filter only groups with 'Windows' in the name
.\IntuneRolesCreation.ps1 -GraphAdminUPN 'admin@yourdomain.onmicrosoft.com' -RbacListPath '.\SampleData\ManagementRolesSample.csv' -TagAndAssignmentListPath '.\SampleData\ScopeTagAndAssignmentsSample.csv' -DeviceFilter @('Windows')

# CREATE EXAMPLE 5
#Run script using specified csv files but don't assign Roles to Azure Entra groups
.\IntuneRolesCreation.ps1 -GraphAdminUPN 'admin@yourdomain.onmicrosoft.com' -RbacListPath '.\SampleData\ManagementRolesSample.csv' -TagAndAssignmentListPath '.\SampleData\ScopeTagAndAssignmentsSample.csv' -SkipRoleAssignment

# CREATE EXAMPLE 6
#Run script using specified csv files but don't assign tags to RBAC Roles
.\IntuneRolesCreation.ps1 -GraphAdminUPN 'admin@yourdomain.onmicrosoft.com' -RbacListPath '.\SampleData\ManagementRolesSample.csv' -TagAndAssignmentListPath '.\SampleData\ScopeTagAndAssignmentsSample.csv' -SkipRoleTags
```

### Outputs

- Displays status of each group tag and role.
- Displays simple report at end of run
- If error happens during _Role_ Creation; an error csv file will be created (name will follow csv name with appended date)
- If error happens during _Tag_ Creation; an error csv file will be created (name will follow csv name with appended date)
- If error happens during _Azure Entra group_ Creation; an error csv file will be created (name will follow csv name with appended date)


## Known Issues & Work Around

|Issue | Work Around |
|--|--|
|Script can take a while to generate object in Azure and Intune; Graph token may expire during script and cause failures| Mitigation's have been added to check expiration time during every item creation. If it exceeds expiration the script attempt re-authorization|
|By default all device type groups will be assign to Role as one assignment.|Running the script per device will group each assignment in their respective assignment name in the Roles|

## Notes

- Designed to be ran __ONCE__; however it can be ran multiple times to add missing roles, tags, groups, and/or assignments. It will check for already created objects and attempt to update them except for assigned Roles
- For further script changes and details, see [CHANGELOG.md](./CHANGELOG.md)

## DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  **THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE**.  We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.

This posting is provided "AS IS" with no warranties, and confers no rights. Use of included script samples are subject to the terms specified at https://www.microsoft.com/en-us/legal/copyright.
