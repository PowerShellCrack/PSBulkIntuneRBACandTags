
<#
.SYNOPSIS
    Deletes Azure Entra groups, Tags and Intune RBAC Roles based comma-delimited list

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

.PARAMETER RbacListPath
    Default value is '.\ManagementRoles.csv'

.PARAMETER TagAndAssignmentListPath
    Default value is '.\ScopeTagAndAssignments.csv'

.PARAMETER NoAction
    Simulates action using Whatif output. No deletion will occur

.EXAMPLE
    .\IntuneRolesDeletion.ps1

.EXAMPLE
    .\IntuneRolesDeletion.ps1 -NoAction

.EXAMPLE
    .\IntuneRolesDeletion.ps1 -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv

.EXAMPLE
    .\IntuneRolesDeletion.ps1 -RbacListPath .\ManagementRolesSample.csv -TagAndAssignmentListPath .\ScopeTagAndAssignmentsSample.csv -NoAction
#>


[CmdletBinding()]
param (
    [ValidateScript({Test-Path $_})]
    $RbacListPath = '.\ManagementRoles.csv',

    [ValidateScript({Test-Path $_})]
    $TagAndAssignmentListPath = '.\ScopeTagAndAssignments.csv',

    [switch]$NoAction
)


Import-Module 'Microsoft.Graph.Authentication'
Import-Module 'Microsoft.Graph.Applications'
Import-Module 'Az.Accounts'
Install-Module 'IDMCmdlets' -MinimumVersion 1.0.2.4 -Force


## =======================================
#  MAIN
## =======================================
#region Authentication
$stopwatch =  [system.diagnostics.stopwatch]::StartNew()
## =======================================
$Global:GraphEndpoint = 'https://graph.microsoft.com'
Connect-MgGraph

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

    If(Get-IDMScopeTag -DisplayName $Tag.'Scope Tags')
    {
        Write-Host ("Found") -ForegroundColor Green

        If(!$NoAction)
        {
            Write-Host ('  Removing scope tag [{0}]...' -f $Tag.'Scope Tags') -NoNewline
            Try{
                $Result = Remove-IDMScopeTag -DisplayName $Tag.'Scope Tags'
                Write-Host 'Done' -ForegroundColor Green
            }
            Catch{
                Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
            }
        }
        Else{
            Write-Host ('  What if: Performing the operation "Remove-IDMScopeTag" on target "{0}"' -f $Tag.'Scope Tags') -ForegroundColor Cyan
        }
    }
    Else{
        Write-Host ("doesn't exist!") -ForegroundColor Yellow
    }
    Write-Host '-------------------------------------------------------------------'
}


## ==============
## Remove Roles
## ==============
Foreach($Rbac in $RbacList)
{
    Write-Host ('Searching for Intune RBAC role [{0}]...' -f $Rbac.Role) -NoNewline
    If(Get-IDMRole -Name $Rbac.Role)
    {
        Write-Host ("Found") -ForegroundColor Green

        If(!$NoAction)
        {
            Write-Host ('  Removing Intune RBAC role [{0}]...' -f $Rbac.Role) -NoNewline
            Try{
                $Result = Remove-IDMRole -DisplayName $Rbac.Role
                Write-Host 'Done' -ForegroundColor Green
            }
            Catch{
                Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
            }
        }
        Else{
            Write-Host ('  What if: Performing the operation "Remove-IDMRole" on target "{0}"' -f $Rbac.Role) -ForegroundColor Cyan
        }
    }
    Else{
        Write-Host ("doesn't exist!") -ForegroundColor Yellow
    }
    Write-Host '-------------------------------------------------------------------'
}

## ==============================
## Remove Azure Azure Device groups
## ==============================
Foreach($AzureGroup in $TagAndAssignment)
{
    Write-Host ('Searching for Azure Entra Group [{0}]...' -f $AzureGroup.'Scope Groups') -NoNewline
    If(Get-IDMAzureGroup -GroupName $AzureGroup.'Scope Groups')
    {
        Write-Host ("Found") -ForegroundColor Green

        If(!$NoAction)
        {
            Write-Host ('  Removing Azure Entra Group [{0}]...' -f $AzureGroup.'Scope Groups') -NoNewline
            Try{
                $Result = Remove-IDMAzureGroup -GroupName $AzureGroup.'Scope Groups'
                Write-Host 'Done' -ForegroundColor Green
            }
            Catch{
                Write-Host ('Failed. {0}' -f $_.exception.message) -ForegroundColor Red
                Continue
            }
        }
        Else{
            Write-Host ('  What If: Performing the operation "Remove-IDMAzureGroup" on target "{0}"' -f $AzureGroup.'Scope Groups') -ForegroundColor Cyan
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
