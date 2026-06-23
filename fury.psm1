<#
	FURYSCRIPT PowerShell Module v25.0618
#>

# ======== VARIABLE DEFINITION ========
$MinPowerShellVersion = 5.0
$SettingsFile = ".\Settings.json"

# ========= END VARIABLE DEFINITION ===========

# ============= SCRIPT CONSTANTS ==============

$ScriptName = $(if ($MyInvocation.PSCommandPath) { (Split-Path -Leaf $MyInvocation.PSCommandPath) -replace ".ps1","" } else { "Unscripted" })
$global:ScriptExecutionTimestamp = Get-Date -Format "yyyy-MM-dd HH-mm-ss"
$TranscriptFileName = "PS Transcript - $ScriptExecutionTimestamp.log"

$global:CredSplat = @{} # Credential splat
$global:WhatIfSplat = @{}
$global:aDWSSplat = @{} # AD Web Services requirement (when finding a DC using certain template functions)
$global:EaSplat = @{ ErrorAction = "Stop" } # Error Action splat

$global:Settings = @{} # Populated during the Import-Settings function
$global:Variables = @{} # Populated during the Import-Settings function

$global:AllDCs = @() # Used as a cache for Get-AllDCs

$TotalErrors = $TotalWarnings = 0

$TextCulture = (Get-Culture).TextInfo # Used for camel case conversion

# ========== END SCRIPT CONSTANTS =============

# ======== TEMPLATE FUNCTIONS ========

function Convert-FileTime {
	param(
		[Parameter(ValueFromPipeline=$true)][Int64]$Time
	)
	return [DateTime]::FromFileTime($Time)
}

function ConvertFrom-ADSIValue {
	<#
		Converts a raw DirectorySearcher ResultPropertyValueCollection into friendly PowerShell values:
		objectSid/objectGUID byte arrays become their canonical string forms, Integer8/FileTime date
		attributes become [DateTime] (or $null for "never" sentinels), and other binary blobs become
		Base64. Returns a scalar for single-valued attributes, an array for multi-valued ones, and
		$null when the attribute is absent.
	#>
	param(
		[string]$Name,
		$Values
	)

	# Integer8 attributes stored as Windows FILETIME ticks (100ns since 1601-01-01 UTC).
	$dateAttributes = @("pwdlastset","lastlogon","lastlogontimestamp","accountexpires","badpasswordtime","lastlogoff","lockouttime")
	$lowerName = $Name.ToLower()

	$converted = foreach ($value in $Values) {
		switch ($true) {
			($value -is [byte[]]) {
				switch ($lowerName) {
					"objectsid"  {
						(New-Object System.Security.Principal.SecurityIdentifier($value, 0)).Value
						break
					}
					{ @("ms-DS-ConsistencyGuid", "objectguid") -contains $_ } {
						(New-Object System.Guid(,$value)).ToString()
						break
					}
					default {
						[System.Convert]::ToBase64String($value)
					}
				}
			}
			($lowerName -in $dateAttributes -and $value -is [Int64]) {
				# 0 = never set; 0x7FFFFFFFFFFFFFFF (Int64.MaxValue) = "never expires".
				if ($value -le 0 -or $value -eq [Int64]::MaxValue) {
					$null
				} else {
					[DateTime]::FromFileTimeUtc($value)
				}
				break
			}
			default {
				# Note: userAccountControl and msDS-User-Account-Control-Computed are returned as their
				# raw integers. Decode their individual flags (Enabled, PasswordNeverExpires, LockedOut,
				# etc.) at projection time so a single attribute can drive multiple friendly columns.
				$value
			}
		}
	}

	$converted = @($converted)
	if ($converted.Count -eq 0) {
		return $null
	} elseif ($converted.Count -eq 1) {
		return $converted[0]
	} else {
		return $converted
	}
}

function Exit-Script {
    param(
        [switch]$Failed
   )

	Write-Log "Exiting script...`r`n"

	try {
		[void](Stop-Transcript)
	} catch {}
    
	if ($script:TotalErrors) {
		Write-Log "This script generated errors during execution." -Level WARNING

		if ($global:Settings["EmailErrorReport"]) {
			Write-Log "Sending log as email to $($EmailRecipients -join ",")"
			New-Email -From $global:Settings["ErrorsEmailFromAddress"] -Recipients $global:Settings["ErrorsEmailRecipients"] -AttachLogFile -SmtpServer $global:Settings["ErrorsEmailSmtpServer"]
		}
	}
	
	Clear-Variable -Name "Settings","Variables" -Scope Global -Force
	Remove-Module fury -Force

    if ($Failed) {
		exit -1
	} else {
        exit 0
    }
}

function Get-ADSIObject {
	[CmdletBinding()]
	param(
		[Parameter()][ValidateSet("User","Group","Computer","Other")]$ObjectType = "User", # if "Other", the LdapFilter MUST be included and can/should include the objectClass
		[Parameter()][string[]]$Properties,
		[Parameter()][string[]]$LdapFilter,
		[Parameter()][string]$SearchBase,
		[Parameter()][ValidateSet("Base","OneLevel","Subtree")][string]$SearchScope = "Subtree",
		[Parameter()][string]$Server,
		[Parameter()][int]$PageSize = 1000,
		[Parameter()][int]$SizeLimit = 0,
		[Parameter()][switch]$FindOne
	)

	# Per-type base filter; "Other" relies entirely on the caller-supplied -LdapFilter.
	$typeFilter = switch ($ObjectType) {
		"User" { "(&(objectCategory=person)(objectClass=user))" }
		"Group" { "(objectCategory=group)" }
		"Computer" { "(objectCategory=computer)" }
		"Other" { $null }
	}

	if ($ObjectType -eq "Other" -and -not $LdapFilter) {
		Write-Log "Get-ADSIObject: -ObjectType 'Other' requires an -LdapFilter (including the objectClass/objectCategory)." -Level ERROR
		return
	}

	$clauses = @()
	if ($typeFilter) { $clauses += $typeFilter }
	if ($LdapFilter) { $clauses += $LdapFilter }

	if ($clauses.Count -gt 1) {
		$filter = "(&" + ($clauses -join "") + ")"
	} elseif ($clauses.Count -eq 1) {
		$filter = $clauses[0]
	} else {
		$filter = "(objectClass=*)"
	}

	$searchRoot = $null
	try {
		if (-not $SearchBase) {
			$rootDsePath = "LDAP://" + $(if ($Server) { "$Server/" }) + "RootDSE"
			$rootDse = New-DirectoryEntry -Path $rootDsePath @CredSplat
			$SearchBase = $rootDse.Properties["defaultNamingContext"][0]
			$rootDse.Dispose()
		}

		$rootPath = "LDAP://" + $(if ($Server) { "$Server/" }) + $SearchBase
		$searchRoot = New-DirectoryEntry -Path $rootPath @CredSplat
	} catch {
		Write-Log "Get-ADSIObject: failed to bind to the directory ($rootPath). The specific error is: $_" -Level ERROR
		if ($searchRoot) { $searchRoot.Dispose() }
		return
	}

	$searcher = New-Object System.DirectoryServices.DirectorySearcher
	$searcher.SearchRoot = $searchRoot
	$searcher.Filter = $filter
	$searcher.SearchScope = $SearchScope
	$searcher.PageSize = $PageSize
	$searcher.SizeLimit = $SizeLimit

	if ($Properties) {
		[void]$searcher.PropertiesToLoad.AddRange($Properties)
	}

	Write-Log "Get-ADSIObject: searching '$($searchRoot.Path)' (scope=$SearchScope, page=$PageSize) with filter $filter" -Level VERBOSE

	$rawResults = $null
	try {
		if ($FindOne) {
			$rawResults = @($searcher.FindOne())
		} else {
			$rawResults = $searcher.FindAll()
		}
	} catch {
		Write-Log "Get-ADSIObject: search failed. The specific error is: $_" -Level ERROR
		$searcher.Dispose()
		$searchRoot.Dispose()
		return
	}

	$output = foreach ($result in $rawResults) {
		if (-not $result) { continue }

		$obj = [ordered]@{}

		$propNames = $(if ($Properties) { $Properties } else { $result.Properties.PropertyNames })

		foreach ($prop in $propNames) {
			$obj[$prop] = ConvertFrom-ADSIValue -Name $prop -Values $result.Properties[$prop]
		}

		[pscustomobject]$obj
	}

	if ($rawResults -is [System.DirectoryServices.SearchResultCollection]) { $rawResults.Dispose() }
	$searcher.Dispose()
	$searchRoot.Dispose()

	return $output
}

function Get-DC {
	param(
		[string]$Domain,
		[switch]$ReturnDCNameOnly
	)

	if (-not $Domain -or $Domain -eq "Root") {
		$Domain = (Get-ADForest).RootDomain
	}

	$DC = Get-ADDomainController -Discover -ForceDiscover -DomainName $Domain @aDWSSplat
	Write-Log "Using domain controller $($DC.HostName[0]) for $Domain" -Level "VERBOSE"

	if ($ReturnDCNameOnly) {
		return $DC.HostName[0]
	} else {
		return $DC
	}
}

function Get-AllDCs {
	param (
		[array]$Domains = (Get-ADDomain).DNSRoot,
		$ADSites,
		[switch]$ForestWide,
		[switch]$DCNamesOnly,
		[switch]$UseCachedData,
		[switch]$DirectReturn
	)

	if ($UseCachedData -and $global:AllDCs.Count) {
		if ($DirectReturn){
			foreach ($Domain in $Scope.Keys){
				$global:AllDCs += $Scope.$Domain
			}

			$global:Scope = $Null

			return $global:AllDCs
		}
	} else { $global:AllDCs = $null }

	if (-not $global:Scope) {
		$global:Scope = @{}
	}

	if ($ForestWide) {
		$ForestRoot = (Get-ADDomain $Domains[0]).Forest
		$Domains = (Get-ADForest $ForestRoot).Domains
		Write-Log "Enumerating DCs in forest $ForestRoot"
	} else {
		Write-Log "Enumerating DCs in $Domains..."
	}

	foreach ($Domain in $Domains) {
		for ($i = 1; $i -le 3; $i++) {
			try {
				$ConnectionDC = (Get-ADDomainController -DomainName $Domain -ForceDiscover -Discover @aDWSSplat).HostName[0]
				Write-Log "Using DC $ConnectionDC for enumeration" -Level "VERBOSE"
				[array]$DomainDCs = Get-ADDomainController -Filter * -Server $ConnectionDC @eaSplat
				if ($ADSites) {
					if ($ADSites -is [array]) {
						if ($($ADSites -join " ").ToCharArray() -contains "*") {
							Write-Log "if multiple AD sites are specified, wildcards may not be used." -Level "ERROR"
							Throw "Invalid -ADSites parameter. Do not use wildcards if specifying an array of site names."
						}
						$DomainDCs = $DomainDCs | Where-Object { $ADSites -contains $_.Site }
					} else {
						$DomainDCs = $DomainDCs | Where-Object { $_.Site -like $(if ($ADSites.ToCharArray() -contains "`*") { $ADSites } else { "$ADSites*" }) }
					}
				}

				if ($DCNamesOnly){
					$DomainDCs = $DomainDCs.HostName
				}

				$global:Scope.Add($Domain, $DomainDCs)
				Write-Log "Found $(($Scope.$Domain).Count) domain controllers in $Domain"
				break
			} catch {
				Write-Log "Could not enumerate DCs in $Domain... Attempt $i of 3" -Level "ERROR"
				Write-Log $_ -Level "ERROR"
				if ($i -eq 3) {
					Write-Log "$Domain is being skipped..." -Level "ERROR"
					break
				}
			}
		}
	}

	if ($DirectReturn){
		foreach ($Domain in $Scope.Keys){
			$global:AllDCs += $Scope.$Domain
		}

		$global:Scope = $Null

		return $global:AllDCs
	}
}

function Get-ComputerADSite {
	param([string[]]$Computers)

	if ($Computers) {
		$pinvoke = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class NetApi32 {
    private class unmanaged {
        [DllImport("NetApi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
        internal static extern UInt32 DsGetSiteName([MarshalAs(UnmanagedType.LPTStr)]string ComputerName, out IntPtr SiteNameBuffer);

        [DllImport("NetApi32.dll", SetLastError=true)]
        internal static extern int NetApiBufferFree(IntPtr Buffer);
    }

    public static string DsGetSiteName(string ComputerName) {
        IntPtr siteNameBuffer = IntPtr.Zero;
        UInt32 hResult = unmanaged.DsGetSiteName(ComputerName, out siteNameBuffer);
        string siteName = Marshal.PtrToStringAuto(siteNameBuffer);
        unmanaged.NetApiBufferFree(siteNameBuffer);
        if(hResult == 0x6ba) { throw new Exception("Site information not found"); }
        return siteName;
    }
}
"@
		Add-Type -TypeDefinition $pinvoke

		$siteMap = @()

		foreach ($computer in $Computers) {
			try {
				$siteName = [NetApi32]::DsGetSiteName($computer)
			} catch {
				Write-Log "Failed to retrieve the AD site for $computer" -Level ERROR
			}
			$siteMap += [pscustomobject][ordered]@{"Computer" = $computer; "SiteName" = $siteName}
		}

		if ($siteMap.Count -gt 1) {
			return $siteMap
		} else {
			return $siteMap[0].SiteName
		}
	} else {
		try {
			[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
		} catch {
			Write-Log "Failed to detect the local machine's AD site. The specific error is: $_" -Level ERROR
		}
	}
}

function Get-Confirmation {
	param(
		[string]$Message,
		[switch]$ExitOnNo,
		[switch]$DefaultToYes,
		[string]$CustomOptions
	)

	if ($CustomOptions) {
		if ($CustomOptions -cmatch "[A-Z]") {
			$DefaultOption = $Matches[0]
		}
		$Options = $CustomOptions -split ","

		$confirmation = Read-Host "$Message`n[$($Options -join "/")]"

		if ($DefaultOption -and ($confirmation -eq "")) {
			return $DefaultOption
		}

		while ($Options -notcontains $confirmation) {
			$confirmation = Read-Host "Invalid option. `n$Message`n[$($Options -join " / ")]"
		}
		return $confirmation
	} else {
		if ($DefaultToYes) { $YesVar = "Y" } else { $YesVar = "y" }

		do {
			$confirmation = Read-Host "$Message [$YesVar/n]"

			switch ($confirmation) {
				"n" {
					if ($ExitOnNo) {
						Write-Log "User declined confirmation." -Level "ERROR" -Fatal
					} else {
						return $false
					}
					break
				}
				"y" {
					return $true
				}
				default {
					if ($DefaultToYes -and ($confirmation -eq "")) { return $true }
				}
			}
		} while (-not $validInput)
	}
}

function Get-CurrentDirectory {
	$Invocation = (Get-Variable MyInvocation -Scope 1).Value;

	if ($Invocation.PSScriptRoot) {
		$Invocation.PSScriptRoot;
	} elseif ($Invocation.MyCommand.Path) {
		Split-Path $Invocation.MyCommand.Path
	} else {
		$Invocation.InvocationName.Substring(0,$Invocation.InvocationName.LastIndexOf("\"));
	}
}

function Get-Events {
	param(
		[Parameter(ParameterSetName="IDFilter")][int]$EventID,
		[ValidateSet("Verbose","Info", "Warning", "Error", "Critical")][Parameter(ParameterSetName="LevelFilter")]$EventLevel = "Error",
		[string]$LogName = "Application",
		[int]$DaysToParse = 7,
		[array]$Computers
	)

	if ($Computer[0] -is [Microsoft.ActiveDirectory.Management.ADAccount]) {
		$Computers = $Computers.DNSHostName
		break
	}

	$FilterHash = @{ LogName = $LogName; StartTime = (Get-Date).AddDays(-$DaysToParse); }
	if ($EventID) {
		$FilterHash.Add("ID", $EventID)
	} else {
		$EventID = "All events"
	}

	$LevelIDs = @{
		"Verbose" = 5;
		"Info" = 4;
		"Warning" = 3;
		"Error" = 2;
		"Critical" = 1;
	}
	$FilterHash.Add("Level", $LevelIDs[$EventLevel])

	foreach ($computer in $Computers) {
		try {
			$Events = Get-WinEvent -ComputerName $computer -FilterHashtable $FilterHash @global:CredSplat -ErrorAction SilentlyContinue -Verbose:$false | Select-Object MachineName,Id,Message,ProviderName
			foreach ($eventLog in $Events) {
				Write-Data -Record $eventLog -Output "EventLogs - $EventID.csv"
			}
		} catch {
			Write-Log "Could not parse the event logs on $computer." -Level "ERROR"
			Write-Log $_ -Level "ERROR"
			continue
		}
	}
}

function Get-FileName {
	param(
		[string]$CustomFileType,
		[switch]$AllFiles
	)

	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") > $null

	$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	# $OpenFileDialog.InitialDirectory = $initialDirectory
	if ($CustomFileType) {
		$OpenFileDialog.Filter = "Custom File Type (*.$CustomFileType)| *.$CustomFileType|All Files (*.*)| *.*"
	} else {
		$OpenFileDialog.Filter = "CSV Files (*.csv)| *.csv|All Files (*.*)| *.*"
	}
	$OpenFileDialog.ShowHelp = $true
	[void]($OpenFileDialog.ShowDialog())

	return $OpenFileDialog.FileName
}

function Get-IPAddress {
	Param ($Computer)
	$return = @()

	foreach ($target in $Computer) {
		if ($Computer[0] -is [System.String]) {
			$ComputerName = $target
		} elseif ($Computer[0] -match [Microsoft.ActiveDirectory.Management.ADComputer]$temp) {
			$ComputerName = $target.Name
		}

		$result = [pscustomobject]@{ ComputerName = $ComputerName; IPAddress = [System.Net.Dns]::GetHostByName($ComputerName).AddressList[0].IPAddressToString }
		$return += $result
	}

	return $return
}

function Get-SecurityPrincipalBySID {
	param($SID)

	try {
		if ($SID -isnot [System.Security.Principal.SecurityIdentifier]) {
			$SID = New-Object System.Security.Principal.SecurityIdentifier($SID)
		}
		$User = $SID.Translate([System.Security.Principal.NTAccount])
		$Username = $User.Value
	} catch {
		Write-Log "Could not resolve $SID to a username" -Level "WARNING"
		$Username = "UNKNOWN ($SID)"
	}

	return $Username
}

function Get-RandomString {
	param(
		[Parameter()][int]$Length = 10,
		[Parameter()][switch]$NumbersOnly,
		[Parameter()][switch]$AlphaOnly,
		[Parameter()][switch]$AlphaNumeric,
		[Parameter(ParameterSetName="Password")][switch]$Password,
		[Parameter(ParameterSetName="Password")][switch]$HumanFriendly,
		[Parameter(ParameterSetName="Passphrase")][switch]$Passphrase,
		[Parameter(ParameterSetName="Password")][Parameter(ParameterSetName="Passphrase")][switch]$ExtraHard,
		[Parameter(ParameterSetName="Password")][switch]$AsSecureString
	)

	[string]$Random = $null
	
	$WordApiEndpoint = "https://random-word-api.herokuapp.com/word"
	
	$uppercase = (65..90) | ForEach-Object { [char][byte]$_	}
	$lowercase = (97..122) | ForEach-Object { [char][byte]$_ }
	$specials = (33,35,36,37,38,40,41,42,43,60,61,62,63,64,94,123,125,126) | ForEach-Object { [char][byte]$_ }
	$numerals = (0..9)
	
	if ($Password) {
		if ($HumanFriendly) {
			if ($ExtraHard -and $Length -lt 14) {
				$Length = 18
			}

			$Segments = @()
			$segmentLength = ($Length - 3) / 3
			$remainder = ($Length - 3) % 3

			$uppercase,$lowercase,$numerals | ForEach-Object {
				$segment = $null
				for ($i=0; $i -le $segmentLength; $i++) {
					$segment += $_ | Get-Random
				}

				if ($ExtraHard) {
					$segment += $specials | Get-Random
				}
				
				$Segments += ,$segment
			}
			
			if ($remainder) {
				for ($i=0; $i -lt $remainder; $i++) {
					$Segments[2] += $numerals | Get-Random
				}
			}

			$Random = $Segments -join "-"
		} else {
			if ($ExtraHard -and $Length -lt 14) {
				$Length = 14
			}

			$sourcedata = $uppercase + $lowercase + $numerals + $specials
			for ($loop = 1; $loop -le $Length; $loop++) {
				$Random += ($sourcedata | Get-Random)
			}
		}
	} elseif ($Passphrase) {
		(1..3) | ForEach-Object {
			$word = (Invoke-RestMethod -Method Get -Uri $WordApiEndpoint)
			$segment = $word.Substring(0,1).ToUpper() + $word.Substring(1)
			if ($ExtraHard) {
				$segment += $specials | Get-Random
			}
			$Segments += ,$segment
		}

		$Random = $Segments -join "-"
	} else {
		switch ($true) {
			$NumbersOnly {
				$sourcedata = $numerals
				break;
			}
			$AlphaOnly {
				$sourcedata = $uppercase + $lowercase
				break;
			}
			$AlphaNumeric {
				$sourcedata = $uppercase + $lowercase + $numerals
				break;
			}
			default {
				$sourcedata = $uppercase + $lowercase + $numerals + $specials
			}
		}
		
		for ($loop = 1; $loop -le $Length; $loop++) {
			$Random += ($sourcedata | Get-Random)
		}
	}

	if ($AsSecureString) {
		return (ConvertTo-SecureString -AsPlainText -Force -String $Random)
	} else {
		return $Random
	}
}

function Import-Settings {

	$DeferredLoggingEnabled = $false # This is a hack, but the idea is to disable the actual enablement of logging until the settings file has been fully imported, since the settings may specify to use a subfolder, etc. and that will affect naming.

	if ((Test-Path -Path $SettingsFile)) {
		Write-Log "Settings file $SettingsFile found. Attempting to import settings..." -Level INFO
	} else {
		Write-Log "Settings file $SettingsFile not found. Specify a file path using the -SettingsFile argument" -Level INFO
		return 1
	}

	try {
		# Cleans up the file before converting it to JSON. Specifically, removes all "comments" and then makes sure that any commented-out items don't create dangling commas
		$SettingsJson =  ((Get-Content -Raw -Path $SettingsFile) -replace "//.*?\n","`n") -replace ",\n}","\n}"
		$SettingsData = ConvertFrom-Json -InputObject $SettingsJson -ErrorAction Stop
	} catch {
		Write-Log "Error attempting to import a JSON settings file ($SettingsFile). The specific error is: $_" -Level ERROR
		return 1
	}

	if ($SettingsData.settings) {
		Write-Log "Now reading in settings from $SettingsFile"

		foreach ($setting in ($SettingsData.settings | Get-Member -Name * -MemberType NoteProperty).Name) {
			if ($setting -eq "LogsEnabled") {
				$DeferredLoggingEnabled = $SettingsData.settings.$setting
				continue
			}
			
			try {
				$global:Settings[$setting] = $SettingsData.settings.$setting
				Write-Log "Set setting `$global:Settings[$setting] to $($SettingsData.settings.$setting)" -Level "VERBOSE"
			} catch {
				Write-Log "Could not configure setting $setting. Check the $SettingsFile file and try again. $_" -Level "ERROR"
			}
		}
	}

	if ($SettingsData.variables) {
		Write-Log "Now reading in variable values from $SettingsFile."
		foreach ($variable in ($SettingsData.variables | Get-Member -Name * -MemberType NoteProperty).Name) {
			try {
				$global:Variables[$variable] = $SettingsData.variables.$variable
				Write-Log "Set variable `$global:Variables[$variable] to $($SettingsData.variables.$variable)" -Level "VERBOSE"
			} catch {
				Write-Log "Could not set variable $variable. Check the $SettingsFile file and try again. $_" -Level "ERROR"
			}
		}
	}

	if ($DeferredLoggingEnabled) {
		Write-Log "Enabling logging as specified in settings file." -HostOnly
		$global:Settings["LogsEnabled"] = $true
	}
}

function Initialize-Module {
	# Clear the error log
	$Error.Clear()

	# Foremost, see if there's a Settings.json file and load it.
	if (Test-Path $SettingsFile) {
		Import-Settings
	} else {
		Write-Log "No settings file found at $SettingsFile. Using default settings." -Level "INFO"
		$global:Settings = @{
			"LogsEnabled" = $true;
			"LogsInSubdirectory" = $true;
			"OutputInSubdirectory" = $true
		}
	}

	if ($global:Settings["TranscriptionEnabled"]) {
		Start-Transcript -Path $TranscriptFileName
		Write-Host "Transcription started. Transcript file is $TranscriptFileName"
	}

	if ($Settings["LogsEnabled"]) {
		$LogfileName = "$ScriptName $ScriptExecutionTimestamp.log"

		if ($Settings["LogsInSubdirectory"]) {
			if (-not (Test-Path ".\LOG\")) {
				[void](New-Item -ItemType Directory -Path ".\LOG")
			}
			$LogFilePath = ".\LOG\"
		}

		$script:LogFile = "$LogFilePath$LogFileName"
	}

	Write-Log "Initializing $ScriptName..."

	if ($MinPowerShellVersion -and $PSVersionTable.PSVersion.ToString() -lt $MinPowerShellVersion) {
		Write-Log "This script requires Microsoft PowerShell version $MinPowerShellVersion or later to run. Please install the latest version of the Windows Management Framework or the PowerShell standalone component and run this script again. Sowwy." -Fatal
	}

	foreach ($module in $global:Settings["RequiredModules"]) {
		if (-not (Get-Module $module)) {
			try {
				Import-Module $module -ErrorAction Stop
				Write-Log "Loaded module $module." -Level "VERBOSE"
			} catch {
				Write-Log "Could not load $module`: $_" -Level "ERROR" -Fatal
			}
		}
	}

	# Check if alternate admin credentials are to be used
	if ($global:Settings["UseAdminCredential"]) {
		if ($global:Settings["AdminCredentialPassFile"]) {
			try {
				$AdminPass = Get-Content $global:Settings["AdminCredentialPassFile"] | ConvertTo-SecureString -ErrorAction Stop
			} catch [PSArgumentException] {
				Write-Log "The specified admin credential password file ($global:Settings['AdminCredentialPassFile']) does not contain a valid secure string. If you are using a password file, it must contain a secure string generated by ConvertTo-SecureString *on the same machine as this script*. For example: 'ConvertTo-SecureString -AsPlainText -Force -String `"YourPassword`" | Out-File AdminPassword.txt'" -Level "ERROR" -Fatal
			}

			try {
				$AdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $global:Settings["AdminUsername"],$AdminPass
			} catch {
				Write-Log "Could not create a PSCredential object from the specified username and password file. The specific error is: $_" -Level "ERROR" -Fatal
			}
		} else {
			Write-Host "Please provide admin credentials to use for the script." -ForegroundColor Yellow
			$AdminCredential = Get-Credential -Message "Please specify an administrator account to use"
		}

		Write-Log "Using admin credential $($AdminCredential.UserName) as specified in the Settings file"
		$global:CredSplat['Credential'] = $AdminCredential
	}

	# Check whether to set the -Whatif parameter on cmdlets that support it (custom functions should use the $Settings["DryRun"] variable directly to determine whether to make changes)
	if ($global:Settings["DryRun"]) {
		$WhatIfSplat["Whatif"] = $true
	}

	# Get current user. You know, for accountability
	$Executor = [Environment]::UserName
	Write-Log "Welcome, $Executor. Your actions are being logged. You know, for accountability."
	Start-Sleep -Seconds 1

	# if there are any logs, pause for review
	if ($Error.Count) {
		Write-Log "Initialization errors encountered." -Level "ERROR"
		if (Get-Confirmation "Continue loading the script?") {
			return
		} else {
			Exit-Script
		}
	}
}

function New-DirectoryEntry {
	# Thin wrapper that builds a System.DirectoryServices.DirectoryEntry, binding with the supplied
	# PSCredential when one is provided and otherwise using the caller's current security context.
	param(
		[Parameter(Mandatory=$true)][string]$Path,
		[System.Management.Automation.PSCredential]$Credential
	)

	if ($Credential) {
		return New-Object System.DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
	} else {
		return New-Object System.DirectoryServices.DirectoryEntry($Path)
	}
}

function New-Email {
	param(
		[string]$From,
		$Recipients,
		$CCRecipients,
		$BCCRecipients,
		[string]$Subject,
		[string]$MessageHeader,
		[string]$MessageBody,
		[string]$CustomFullBody,
		[string]$SmtpServer,
		[switch]$AttachLogFile,
		[array]$AdditionalAttachments,
		$Attachments
	)

	$DefaultSubject = "$ScriptName Email - $(Get-Date -Format "yyyy/MM/dd hh:mm:ss tt")"
	$DefaultBody = @"
<div style="font-family: Calibri, sans-serif !important; color: #606060 !important;">
	<h1>$MessageHeader</h1>
	<p>$MessageBody</p>
</div>
"@
	$MessageParams = @{
		From = $From;
		To = $Recipients;
		SmtpServer = $SmtpServer;
		#UseSSL = $true;
		Subject = $(if ($Subject) { $Subject } else { $DefaultSubject });
		Body = $(if ($CustomFullBody) { $CustomFullBody } else { $DefaultBody })
		BodyAsHtml = $true;
	}

	if ($CCRecipients) {
		if ($CCRecipients -is [string]) {
			$CCRecipients = $CCRecipients -split ";"
		}
		$MessageParams.Add("Cc", $CCRecipients)
	}
	if ($BCCRecipients) {
		if ($BCCRecipients -is [string]) {
			$BCCRecipients = $BCCRecipients -split ";"
		}
		$MessageParams.Add("Bcc", $BCCRecipients)
	}

	switch ($true) {
		$AttachLogFile { $Attachments += ,(Get-Item -Path $LogFile).FullName }
		$AdditionalAttachments.Count { if ($AdditionalAttachments[0] -is [string]) { $Attachments += $AdditionalAttachments } else { $Attachments += $AdditionalAttachments.FullName } }
	}
	if ($Attachments) { $MessageParams.Add("Attachments", $Attachments) }

	try {
		Write-Log "Emailing report to $($Recipients -join ",")..."
		Send-MailMessage @MessageParams @CredSplat
	} catch {
		Write-Log "Could not send report email. Check the parameters for the next iteration of the script." -Level "ERROR"
		Write-Log "Line $($_.InvocationInfo.ScriptLineNumber) - $_" -Level "ERROR"
	}
}


function Test-Connectivity {
	param(
		[string]$ComputerName,
		[int]$Port
	)

	if ($Port) {
		try {
			return (New-Object System.Net.Sockets.TCPClient -ArgumentList $ComputerName, $Port -ErrorAction SilentlyContinue).Connected
		} catch {
			return $false
		}
	} else {
		return [bool](Test-Connection -ComputerName $ComputerName -Count 2 -ErrorAction SilentlyContinue)
	}
}

function Set-OutputLevel {
	param(
		[Parameter(Mandatory=$True)][ValidateSet("Normal","Verbose","Debug")]$Level
	)

	switch ($Level) {
		"Normal" {
			Write-Log "Disabling verbose output and stopping the transcription, if it is enabled"
			$global:VerbosePreference = "Ignore"
			try {
				[void](Stop-Transcript -ErrorAction Stop)
			} catch {}
		}
		"Verbose" {
			Write-Log "Enabling verbose output for all cmdlets and stopping the transcription, it if is enabled"
			$global:VerbosePreference = "Continue"
			try {
				[void](Stop-Transcript -ErrorAction Stop)
			} catch {}
		}
		"Debug" {
			Write-Log "Enabling verbose output for all cmdlets and transcribing all output to $($pwd.Path)\Debug.log"
			$global:VerbosePreference = "Continue"
			Start-Transcript -Path "./Debug.log" -Append
		}
	}
}

function Split-CamelCaseString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$String,
		[Parameter()][switch]$ReturnArray,
		[Parameter()][switch]$CapitalizeEachWord
    )

    process {
        # Split pattern breaks down into 4 conditions:
        # 1. Lowercase followed by Uppercase: (?<=[a-z])(?=[A-Z])
        # 2. Letter followed by a Number: (?<=[a-zA-Z])(?=[0-9])
        # 3. Number followed by a Letter: (?<=[0-9])(?=[a-zA-Z])
        # 4. An acronym's last uppercase letter followed by lowercase: (?<=[A-Z])(?=[A-Z][a-z])
        $pattern = '(?<=[a-z])(?=[A-Z])|(?<=[a-zA-Z])(?=[0-9])|(?<=[0-9])(?=[a-zA-Z])|(?<=[A-Z])(?=[A-Z][a-z])'
        
        # Split using the case-sensitive split operator
        $words = $String -csplit $pattern | Where-Object { $_ -ne '' }
        
		if ($CapitalizeEachWord) {
			$words = $words | ForEach-Object {$TextCulture.ToTitleCase($_)}
		}

		if ($ReturnArray) {
        	return $words
		} else {
			return $words -join " "
		}
    }
}

function Start-ConfirmationTimer {
	param(
		[string]$Message,
		[int]$SecondsToWait = 10,
		[Switch]$OnlyShowDots
	)

	Write-Host -NoNewline "$Message"

	while ($SecondsToWait -ge 0) {
		if (-not [console]::KeyAvailable) {
			if ($OnlyShowDots) {
				Write-Host -NoNewLine "."
			} else {
				Write-Host -NoNewline " $SecondsToWait..."
			}

			Start-Sleep -Seconds 1

			$SecondsToWait--
		} else {
			return $false
		}
	}
	return $true # NO intervention
}
function Wait-Input {
	param([string]$Message="Press any key to continue...")

	if ($psISE) { # The "ReadKey" functionality is not supported in Windows PowerShell ISE
		Write-Host "`n$Message`n"
		$Shell = New-Object -ComObject "WScript.Shell"
		$Shell.Popup($Message, 0, "Script Paused", 0)
		return
	}

	Write-Host $Message -ForegroundColor Cyan

	$Ignore = 16,17,18,20,91,92,93,144,145,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183

	while ($null -eq $KeyInfo.VirtualKeyCode -or $Ignore -contains $KeyInfo.VirtualKeyCode) {
			$KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
	}
}

function Write-Data {
	[CmdletBinding()]param(
		[Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)]$Record,
		[Parameter(Mandatory=$true, Position=2)]$OutputFile,
		[Parameter(Mandatory=$false, Position=3)][ValidateSet("csv","text","json")]$WriteType = "csv",
		[Parameter(Mandatory=$false, Position=4)][bool]$Force = $false
	)

	begin {		
		if ($Settings["OutputInSubdirectory"]) {
			$OutputFile = ".\OUTPUT\$OutputFile"
		}

		if (-not (Test-Path $OutputFile)) {
			Write-Log "Output file $OutputFile did not exist. Creating..." -Level "VERBOSE"
			if ($OutputFile -like "*\*") {
				$ParentPath = Split-Path $OutputFile
				if (-not (Test-Path "$ParentPath\")) {
					try {
						New-Item -ItemType Directory -Path $ParentPath -Force | Out-Null
					} catch {
						Write-Log $_
						Write-Log "Could not create parent path for output file" -Level "ERROR" -Fatal
					}
				}
			}
		}
	}

	process {
		switch ($WriteType) {
			"csv" {
				[pscustomobject]$Record | Export-Csv -Append -Path $OutputFile -NoTypeInformation -Force -Encoding utf8
			}
			"text" {
				[pscustomobject]$Record | Out-File -FilePath $OutputFile -Append -Encoding utf8
			}
			"json" {
				ConvertTo-Json $Record -Depth 10 | Out-File -FilePath $OutputFile -Append -Encoding utf8
			}
		}
	}
}

function Write-Log {
	param(
		[Parameter()]$Message,
		[Parameter()][ValidateSet("INFO","WARNING","ERROR","VERBOSE")][string]$Level = "INFO",
		[Parameter()][switch]$Silent,
		[Parameter()][switch]$HostOnly,
		[Parameter()][switch]$Fatal,
		[Parameter()][switch]$Separator
	)

	# Ignore VERBOSE entries if the "Verbose" flag is not set
	if ($Level -eq "VERBOSE" -and $VerbosePreference -ne "Continue") { return }

	if ($Separator) {
		"`r`n--------------------`r`n" | Add-Content $LogFile
		return
	}

	$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

	if ($Message -is [System.Management.Automation.ErrorRecord]) {
		if ($Level -eq "INFO") {
			$Level = "ERROR"
		}
		$Output = "$Level`t: $Message at line $($Message.InvocationInfo.ScriptLineNumber)"
	} else {
		$Output = "$Level`t: $Message"
	}

	if (-not $Silent) {
		# Set the color for the console output and update counters
		switch ($Level) {
			"WARNING" { $Color = "Yellow"; $TotalWarnings++; break }
			"ERROR" { $Color = "Red"; $TotalErrors++; break }
			"VERBOSE" { $Color = "Gray"; break }
			default { $Color = "White" }
		}

		Write-Host $Output -Fore $Color
	}

	if ($global:Settings["LogsEnabled"] -and -not $HostOnly) {
		"$Timestamp`t$Output" | Add-Content $script:LogFile
	}

	if ($Level -eq "ERROR" -and $global:Settings["ErrorThreshold"] -and $global:TotalErrors -gt $global:Settings["ErrorThreshold"]) {
		"ERROR THRESHOLD EXCEEDED: The script has encountered more than $($global:Settings["ErrorThreshold"]) errors and will now terminate." | Add-Content $script:LogFile
		Exit-Script -Failed
	}

	if ($Fatal) {
		"FATAL: The previous error was fatal. The script will now exit." | Add-Content $script:LogFile
		Write-Host "FATAL: The previous error was fatal. The script will now exit." -Fore Red
		Exit-Script -Failed
	}
}

Initialize-Module

Export-ModuleMember -Function *