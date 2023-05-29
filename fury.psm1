<#
	FURYSCRIPT PowerShell Module v23.0306
#>

[CmdletBinding()]
param(
	[Parameter(Mandatory=$false)][string]$InputFile,
	[Parameter(Mandatory=$false)][string]$OutputFile,
	[Parameter(Mandatory=$false)][string]$LogFile,
	[Parameter(Mandatory=$false)][switch]$TestRun,
	[Parameter(Mandatory=$false)][switch]$UseAdminCredential,
	[Parameter(Mandatory=$false)]$AdminCredential = [System.Management.Automation.PSCredential]::Empty,
	[Parameter(Mandatory=$false)]$AdminCredentialPassFile,
	[Parameter(Mandatory=$false)][int]$MinPowerShellVersion = 3,
	[Parameter(Mandatory=$false)][string]$SettingsFile = 'settings.json',
	[Parameter(Mandatory=$false)][switch]$SuperDebug
)

# ======== VARIABLE DEFINITION ========

# Used to pre-populate the headers in the output file, to make sure they are not constrained to the headers of the first record
$OutputHeaders = @(
	"Column1",
	"Column2"
)

# Set to $true to always use verbose logging, without requiring the script to have the -Verbose parameter
$DefaultToVerbose = $false

$NeedsModules = @() # An array of PS module names to load

$ScriptGeneratesOutputFile = $true # Whether an output file is generated (the log file is ALWAYS generated)

$ScriptNeedsInputFile = $true # Whether the script requires a file to be specified using the -InputFile parameter
$ScriptInputFileType = "" # Leave blank for .csv, or specify the extension type (excluding the "."). Use "*" for all files
$MinPowerShellVersion = 5.0

# ========= END VARIABLE DEFINITION ===========

# ============= SCRIPT CONSTANTS ==============

$ScriptName = $MyInvocation.MyCommand.Name -replace ".ps1",""
$ScriptExecutionTime = Get-Date
$ScriptExecutionTimestamp = Get-Date -Format "yyyy-MM-dd HH-mm-ss"
$TranscriptFileName = "PS Transcript - $ScriptExecutionTimestamp.log"

switch ($null) {
	$Logfile {
		if (-not (Test-Path ".\LOG\")) {
			New-Item -ItemType Directory -Path ".\LOG" | Out-Null
		}
		$global:Logfile = ".\LOG\$ScriptName $ScriptExecutionTimestamp.log"
	}
	$OutputFile {
		if ($ScriptGeneratesOutputFile) {
			if (-not (Test-Path ".\OUTPUT\")) {
				New-Item -ItemType Directory -Path ".\OUTPUT" | Out-Null
			}
			$global:OutputFile = ".\OUTPUT\$ScriptName $ScriptExecutionTimestamp.csv"
		}
	}
}

$credSplat = @{} # Credential splat
$aDWSSplat = @{} # AD Web Services requirement (when finding a DC using certain template functions)
$eaSplat = @{ ErrorAction = "Stop" } # Error Action splat
$testSplat = @{}

$global:Settings = @() # Populated during the Import-Settings function
$global:Variables = @() # Populated during the Import-Settings function

$TotalErrors = $TotalWarnings = 0
$ErrorsLogged = $false

# ========== END SCRIPT CONSTANTS =============

# ======== TEMPLATE FUNCTIONS ========

function Convert-FileTime {
	param(
		[Parameter(ValueFromPipeline=$true)][Int64]$Time
	)
	return [DateTime]::FromFileTime($Time)
}

function Exit-Script {
    param(
        [switch]$Failed
   )

	Write-Log "Exiting script...`r`n"

	try {
		[void](Stop-Transcript)
	} catch {}
    
	if ($global:ErrorsLogged -and $global:Settings["EmailErrorReport"]) {
		Write-Log "Sending log as email to $($EmailRecipients -join ",")"
		New-Email -From $global:Settings["ErrorsEmailFromAddress"] -Recipients $global:Settings["ErrorsEmailRecipients"] -AttachLogFile -SmtpServer $global:Settings["ErrorsEmailSmtpServer"]
	}

    if ($Failed) {
        exit -1
    }

	exit
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
		[switch]$DirectReturn
	)

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
			$DCs += $Scope.$Domain
		}

		$global:Scope = $Null

		return $DCs
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

	if($Invocation.PSScriptRoot) {
		$Invocation.PSScriptRoot;
	} elseif($Invocation.MyCommand.Path) {
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
			$Events = Get-WinEvent -ComputerName $computer -FilterHashtable $FilterHash @credSplat -ErrorAction SilentlyContinue -Verbose:$false | Select-Object MachineName,Id,Message,ProviderName
			foreach ($event in $Events) {
				Write-Data -Record $event -Output "EventLogs - $EventID.csv"
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
	param(
		[Parameter(Mandatory=$false)][ValidateSet("JSON","XML")]$FileFormat = "JSON"
	)

	if (-not (Test-Path -Path $SettingsFile)) {
		Write-Log "Settings file $SettingsFile not found. Specify a file path using the -SettingsFile argument" -Level ERROR
		return 1
	}

	switch ($FileFormat) {
		"JSON" {
			try {
				# Cleans up the file before converting it to JSON. Specifically, removes all "comments" and then makes sure that any commented-out items don't create dangling commas
				$SettingsJson =  ((Get-Content -Raw -Path $SettingsFile) -replace "//.*?\n","`n") -replace ",\n}","\n}"
				$SettingsData = ConvertFrom-Json -InputObject $SettingsJson -ErrorAction Stop
			} catch {
				Write-Log "Error attempting to import a JSON settings file ($SettingsFile). The specific error is: $_" -Level ERROR
				return 1
			}
		}
		"XML" {
			Write-Log "XML settings files are not yet supported. Just use JSON, weirdo."
		}
	}

	if ($SettingsData.settings) {
		Write-Log "Now reading in settings from $SettingsFile"
		$global:Settings = @{}
		foreach ($setting in ($SettingsData.settings | Get-Member -Name * -MemberType NoteProperty).Name) {
			try {
				$global:Settings[$setting] = $SettingsData.settings.$setting
				Write-Log "Set setting `$Settings[$setting] to $(Get-Variable $setting -ValueOnly)" -Level "VERBOSE"
			} catch {
				Write-Log "Could not configure setting $setting. Check the $SettingsFile file and try again" -Level "ERROR"
			}
		}
	}

	if ($SettingsData.variables) {
		Write-Log "Now reading in variable values from $SettingsFile."
		$global:Variables = @{}
		foreach ($variable in ($SettingsData.variables | Get-Member -Name * -MemberType NoteProperty).Name) {
			try {
				$global:Variables[$variable] = $SettingsData.variables.$variable
				Write-Log "Set variable `$Variables[$variable] to $(Get-Variable $variable -ValueOnly)" -Level "VERBOSE"
			} catch {
				Write-Log "Could not set variable $variable. Check the $SettingsFile file and try again" -Level "ERROR"
			}
		}
	}
}

function Initialize-Module {
	# Clear the error log
	$Error.Clear()

	if ($SuperDebug) {
		Start-Transcript -Path $TranscriptFileName
	}

	# Foremost, see if there's a Settings.json file and load it.
	if (Test-Path $SettingsFile) {
		Import-Settings
	}

	# Check if the log file already exists; if not, create it
	if (-not (Test-Path $LogFile)) {
		New-Item -Path $LogFile -ItemType File -Force | Out-Null
	}

	Write-Log "Initializing $ScriptName..."

	if ($MinPowerShellVersion -and $PSVersionTable.PSVersion.ToString() -lt $MinPowerShellVersion) {
		Write-Log "This script requires Microsoft PowerShell version $MinPowerShellVersion or later to run. Please install the latest version of the Windows Management Framework or the PowerShell standalone component and run this script again. Sowwy." -Fatal
	}

	# Check for the input file, if one is specified in the script
	if ($ScriptNeedsInputFile) {
		if (-not $InputFile) {
			$iftSplat = @{}
			if ($ScriptInputFileType) {
				$iftSplat["CustomFileType"] = $ScriptInputFileType
			}
			$global:InputFile = Get-FileName @iftSplat
		}
	}

	# Check if the output path already exists; if not, create it
	if (-not (Test-Path ".\OUTPUT\")) {
		try {
			Write-Host "Creating log file..."
			New-Item -Path $LogFile -ItemType file | Out-Null
		} catch {
			Write-Host "Failed to create the log file. The specific error is:"
			$_
			Read-Host "Press a key to exit"
			exit
		}
	}

	# Check if the output file already exists; if so, prompt to overwrite.
	if ($ScriptGeneratesOutputFile) {
		if (Test-Path $OutputFile) {
			if ((Read-Host "Specified output file $OutputFile exists. Overwrite? [Y/N]") -ne "Y") {
				Write-Log "Specified output file exists" -Level "ERROR" -Fatal
			} else {
				Write-Log "Overwriting output file '$OutputFile'"
			}
		}
		New-Item -Path $OutputFile -ItemType File | Out-Null
		"`"" + $($OutputHeaders -join "`",`"") + "`"" | Out-File $OutputFile -Encoding UTF8 # Pre-populate the headers in the output file, to make sure they are not constrained to the headers of the first record
	}


	foreach ($module in $NeedsModules) {
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
	if ($UseAdminCredential) {
		switch ($true) {
			($AdminCredentialPassFile) {
				$AdminPass = Get-Content $AdminCredentialPassFile | ConvertTo-SecureString
			}
			($AdminCredential -isnot [System.Management.Automation.PSCredential]) {
				Write-Log "if using the -AdminCredential parameter, please pass a PSCredential object. Or omit the -AdminCredential parameter to be prompted for credentials" -Level "ERROR" -Fatal
				break
			}
			($AdminCredential -eq [System.Management.Automation.PSCredential]::Empty) {
				if ($AdminPass) {
					$AdminUsername = Read-Host "Password read from $AdminCredentialPassFile. Please specify the username to use"
					$AdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $AdminUsername,$AdminPass
				} else {
					$AdminCredential = Get-Credential -Message "Please specify an administrator account to use"
				}
				Write-Log "Admin credentials loaded for $($AdminCredential.UserName)" -Level "VERBOSE"
			}
		}

		$global:credSplat['Credential'] = $AdminCredential
	}

	# Check whether to set the -Whatif parameter on cmdlets that support it (custom functions should use the $TestRun variable directly to determine whether to make changes)
	if ($TestRun) {
		$testSplat["Whatif"] = $true
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
		[switch]$AttachOutputFile,
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
		$AttachOutputFile { $Attachments += ,(Get-Item -Path $OutputFile).FullName }
	}
	if ($Attachments) { $MessageParams.Add("Attachments", $Attachments) }

	try {
		Write-Log "Emailing report to $($Recipients -join ",")..."
		Send-MailMessage @MessageParams @credSplat
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

function Start-ConfirmationTimer {
	param(
		[string]$Message,
		[int]$secondsToWait = 10,
		[Switch]$OnlyShowDots
	)

	Write-Host -NoNewline "$Message"

	while ($secondsToWait -ge 0) {
		if (-not [console]::KeyAvailable) {
			if ($OnlyShowDots) {
				Write-Host -NoNewLine "."
			} else {
				Write-Host -NoNewline " $secondsToWait..."
			}

			Start-Sleep -Seconds 1

			$secondsToWait--
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
		[Parameter(Mandatory=$false, Position=2)][ValidateSet("csv","text","json")]$WriteType = "csv",
		[Parameter(Mandatory=$false, Position=2)]$Output = $OutputFile,
		[Parameter(Mandatory=$false, Position=3)][bool]$Force = $false
	)

	if ($Record -is [hashtable]) {
		$Record = [pscustomobject]$Record
	}

	if (-not (Test-Path $Output)) {
		Write-Log "Output file $Output did not exist. Creating..." -Level "VERBOSE"
		if ($Output -like "*\*") {
			$ParentPath = Split-Path $Output
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

	switch ($WriteType) {
		"csv" {
			$Record | Export-Csv -Append -Path $Output -NoTypeInformation -Force -Encoding ASCII
		}
		"text" {
			$Record | Out-File -FilePath $Output -Append -Encoding ASCII
		}
		"json" {
			ConvertTo-Json $Record | Out-File -FilePath $Output -Append -Encoding utf8
		}
	}
}

function Write-Log {
	param(
		[Parameter()]$Message,
		[Parameter()][ValidateSet("INFO","WARNING","ERROR","VERBOSE")][string]$Level = "INFO",
		[Parameter()][switch]$Silent,
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
			"ERROR" { $Color = "Red"; $ErrorsLogged = $true; $TotalErrors++; break }
			"VERBOSE" { $Color = "Gray"; break }
			default { $Color = "White" }
		}

		Write-Host $Output -Fore $Color
	}

	"$Timestamp`t$Output" | Add-Content $LogFile

	if ($Level -eq "ERROR" -and $global:Settings["ErrorThreshold"] -and $global:TotalErrors -gt $global:Settings["ErrorThreshold"]) {
		"ERROR THRESHOLD EXCEEDED: The script has encountered more than $($global:Settings["ErrorThreshold"]) errors and will now terminate." | Add-Content $LogFile
		Exit-Script -Failed
	}

	if ($Fatal) {
		"FATAL: The previous error was fatal. The script will now exit." | Add-Content $LogFile
		Write-Host "FATAL: The previous error was fatal. The script will now poop the bed." -Fore Red
		Exit-Script -Failed
	}
}

Initialize-Module

Export-ModuleMember -Function *