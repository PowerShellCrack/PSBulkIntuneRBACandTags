
<#
.SYNOPSIS
    Generates data based on Site information

.OUTPUTS
	ScopeTagAndAssignments.csv

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

.PARAMETER SourceListPath
    Must be in csv format

.PARAMETER TagAndAssignmentListPath
    Specify .csv extension

.EXAMPLE
	#Run script using default input/output
	.\GenerateScopeGroups.ps1
.EXAMPLE
	#Run script using specified Site data to populate data and output file
	.\GenerateScopeGroups.ps1 -SourceListPath '.\NetworkData.csv' -TagAndAssignmentListPath '.\ScopeTagAndAssignments.csv'
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory=$false)]
	[string]$AzureGroupPrefix = 'SG-DD',

	[Parameter(Mandatory=$false)]
	[string]$JoinChar = '-',

	[Parameter(Mandatory=$false)]
	[ValidateSet("Windows","macOS","iPhone","iPad","Android","SurfaceHub","TeamsRoom","TeamsPhone")]
	[string[]]$DeviceTypes = @("Windows","macOS","iPhone","iPad","Android","SurfaceHub","TeamsRoom","TeamsPhone"),

	[Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_})]
    $SourceListPath = '.\SiteData.csv',

	[Parameter(Mandatory=$false)]
	$TagAndAssignmentListPath = '.\ScopeTagAndAssignments.csv'
)

#Load the Site data - from the Reference tab, includes columns:
#Device Prefix, Region, Area, Component, Site Status (the last two are not used currently)
$data = Import-Csv $SourceListPath

#Iterate the Regions
#Inside each Region, Iterate the Areas
#Inside each area, build the Query with the Sites

$taglist = @{}

#build tag list based on device types
Foreach($OStype in $DeviceTypes | Select -Unique){
	$taglist += @{$OStype = ("{0}" -f $OStype.ToString().replace('OS','').ToLower())}
}

#Build the query structure
$start = "device.deviceOSType -contains """
$contop1 = """ -and ("
$prefix = "device.displayName -startsWith """
$suffix = """"
$contop2 = " -or "
$end = ")"

$resultset = @()

#Get Unique Regions
$regions = ($data | select Region -Unique).Region

#TEST $region = $regions[0]
foreach($region in $regions)
{
	#Build Region Query
	$rdata = ($data | ? {$_.Region -eq $region});
	Write-Host ("Iterating region [{0}]. Device prefix count is {1}" -f $region,$rdata.count)

	#Get Unique Areas
	$areas = ($rdata | select Area -Unique).Area

	#TEST $area = $areas[0]
	foreach($area in $areas)
	{
		#Build Area Query
		$adata = ($data | ? {$_.Region -eq $region -and $_.Area -eq $area});
		Write-Host ("Iterating area [{0}]. Device prefix count is {1}" -f $area,$adata.count)

		$q = ($adata.'Device Prefix');
		$al_q = (new-object System.Collections.ArrayList);
		$q | % {$al_q.Add($_)} | Out-Null
		Write-Host ("Generating a query with {0} device prefixes based on {1} device types:" -f $q.count,$taglist.count) -ForegroundColor Cyan

		#Determine if Group Split is needed
		$div = 2;
		$splitgroup = $false

		if($q.count -gt 60) {
			#find the correct divisor
			while(($($q.count) / $div) -gt 60) {$div += 1};
			Write-Host ("Splitting query into [{0}] groups due to size..." -f $div) -ForegroundColor Yellow
			$splitgroup = $true
		}

		if (!$splitgroup)
		{
			foreach ($deviceOS in $DeviceTypes | Select -Unique)
			{
				$query = $null;
				$query += $start + $($taglist["$deviceOS"]) + $contop1
				$al_q | % {$query += $prefix + $($_) + $suffix + $contop2};
				$query = $query.TrimEnd(" -or ")
				$query += $end

				#Build naming convention
				$scopegroups = [System.String]::Concat($AzureGroupPrefix,$JoinChar,$region,$JoinChar,$area,$JoinChar,$deviceOS)
				$scopetags = [System.String]::Concat($region,$JoinChar,$area,$JoinChar,$deviceOS)

				Write-Host ("  Group named [") -ForegroundColor Green -NoNewLine
				Write-Host ("{0}" -f $scopegroups) -ForegroundColor White -NoNewLine
				Write-Host ("] has a query expression length of ") -ForegroundColor Green -NoNewLine
				Write-Host ("{0}" -f $query.length) -ForegroundColor Yellow -NoNewLine
				Write-Host (" characters") -ForegroundColor Green

				$properties = [ordered] @{
					"Region" = $region
					"Area" = $area
					"Device Type" = $deviceOS
					"Scope Groups" = $scopegroups
					"Scope Tags" = $scopetags
					"Criteria" = $query
				}

				$foo = New-Object -TypeName PSCustomObject -Property $properties
				$resultset += $foo;
			}
		}
		else
		{
			Write-Host ("Splitting Groups for area [{0}]" -f $area) -ForegroundColor Yellow
			$dcount = $q.count;
			$dnum = 1
			$begin = 1
			$finish = 60

			do {

				Write-Verbose ("DCOUNT = {0}, DNUM = {1}" -f $dcount,$dnum)
				$finish = $begin + 59
				if($finish -gt $($q.count)) {$finish = $($q.count)}

				Write-Verbose ("BEGIN = {0}, FINISH = {1}" -f $begin,$finish)

				foreach ($deviceOS in $DeviceTypes | Select -Unique)
				{
					#Prep Group Enum
					$num = $dnum;

					$query = $null;
					$query += $start + $($taglist["$deviceOS"]) + $contop1
					$al_q[$begin..$finish] | % {$query += $prefix + $($_) + $suffix + $contop2};
					$query = $query.TrimEnd(" -or ")
					$query += $end

					#Build naming convention
					$scopegroups = [System.String]::Concat($AzureGroupPrefix,$JoinChar,$region,$JoinChar,$area,$JoinChar,$deviceOS,$JoinChar,$num.ToString())
					$scopetags = [System.String]::Concat($region,$JoinChar,$area,$JoinChar,$deviceOS)

					Write-Host ("  Group named [") -ForegroundColor Green -NoNewLine
					Write-Host ("{0}" -f $scopegroups) -ForegroundColor White -NoNewLine
					Write-Host ("] has a query expression length of ") -ForegroundColor Green -NoNewLine
					Write-Host ("{0}" -f $query.length) -ForegroundColor Yellow -NoNewLine
					Write-Host (" characters") -ForegroundColor Green

					$properties = [ordered] @{
						"Region" = $region
						"Area" = $area
						"Device Type" = $deviceOS
						"Scope Groups" = $scopegroups
						"Scope Tags" = $scopetags
						"Criteria" = $query
					}

					$foo = New-Object -TypeName PSCustomObject -Property $properties
					$resultset += $foo;
				}

				$dcount -= 60;
				$dnum +=1
				$begin += 60;
			} while ($dcount -gt 0);

		}
	}#end area loop
}#end region loop

write-host ("Created {0} entries for Scope tags and assignments" -f $resultset.count) -ForegroundColor Cyan

#Run this to export the results to file
$resultset | Export-CSV -Path $TagAndAssignmentListPath -NoTypeInformation -Force

#$resultset | ConvertTo-Csv -NoTypeInformation -Delimiter "," |
#foreach { $_ -replace '^"|"$|"(?=,)|(?<=,)"','' } | Out-File -Encoding utf8 ".\ScopeTagAndAssignments.csv"
