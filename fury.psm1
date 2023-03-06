﻿<#
	FURYSCRIPT TEMPLATE v22.0831

	Recent Changelog:
	- 22.0831 : Updated Write-Log to be a little more efficient and to provide a ValidateSet on the -Level parameter
	- 22.0824 : Switched to a new versioning scheme. Updated capitalization of PowerShell language keywords because I have a sickness that demands accuracy even where none is required.
	- 3.38 : Added -Separator parameter to Write-Log to create a gap in a log file, and -Failed parameter to Exit-Script, which will return an exit code of -1. Write-Log -Fatal has been updated to include the -Failed parameter when it exits the script
	- 3.37 : Forced creation of logfile, in case the specified parent path does not exist it will not be created.
	- 3.36 : Get-RandomString is AMAZING now.
	- 3.35 : Leeeetle tweaks. Doesn't matter.
	- 3.34 : Update Get-RandomString to support -AsSecureString parameter to directly return a secure string. Smashing!
	- 3.33 : Updated Send-Email to allow specifying custom body header and content without needing HTML. Added support for getting local computer's site membership. Improved Write-Log a little.
	- 3.32 : Updated Get-RandomString to include -Password and -ExtraHard parameters for generating secure, friendly passwords
	- 3.31 : Fixed Get-Events to filter on event level. Optimized Import-Settings to only be called if $ScriptHasSettingsFile is $true (previously always ran and then checked the variable)
	- 3.3  : Added -SuperDebug argument to run a PS transcript of the script execution, added -Silent to Write-Log to allow some events to not be written to the screen
	- 3.2  : Updated Get-Confirmation to support custom options rather than just yes/no, Updated Start-ConfirmationTimer to actually work, additional minor cleanup. Added $DefaultToVerbose variable to allow setting Verbose logging without the runtime -Verbose argument
	- 3.1.2: Renamed the Pause function to Wait-Input and Timed-Confirmation to Start-ConfirmationTimer, to adhere to Microsoft's approved verbs
	- 3.1.1: Updated Import-Settings to define both $Settings and $Variables arrays (Rather than adding variables to the $Settings array), each filled with their respective values. Also added a ValidateSet to Write-Data to define the permitted data types
	- 3.1  : Removed Impersonation Context Code, because I never used it, and updated Input File variable to allow custom file types for the File Picker
	- 3.0  : Added Import-Settings, Convert-FileTime function, and some other stuff who cares fuck this.
	- 2.99 : Added the Resolve-SID function
	- 2.98 : Little more cleanup, and added CC and BCC support to Send-Email function, and override for Write-Log to write an ErrorRecord object as only a "WARNING" level entry
	- 2.97 : Standardized formatting and some minor code cleanup
	- 2.96 : Updated the Get-Confirmation function to include the "DefaultToYes" parameter
	- 2.955: Updated the Write-Data function to create the parent directory for a specified output file, if it didn't exist
	- 2.947: Updated the Write-Log function to not write the timestamp to the screen, because who really cares? Also added Timed-Confirmation
	- 2.941: Updated the Write-Log function to include a tab character after the "Level", to make the log more uniform
	- 2.94 : Updated the Write-Data function to not suck!
	- 2.93 : Added option to specify an AdminCredentialPassFile for using stored credentials!
	- 2.92 : Added optional "Output" switch to the Write-Data function!
	- 2.91 : Life is pain.
	- 2.9  : Added the Get-Events function!
	- 2.87 : Re-worked the output file creation to prevent creating a blank first record!
	- 2.86 : Added MinPowerShellVersion argument!
	- 2.85 : Added the Get-IPAddress function!
	- 2.84 : Added the TestRun variable!
	- 2.83 : Improved Write-Log function to recognize Error objects and style them appropriately
	- 2.82 : Updated Initialize-Script to check for PowerShell version 3 or greater
	- 2.81 : Updated Get-FileName to more reliably show the dialog box
	- 2.8  : Added ScriptGeneratesOutputFile variable!
	- 2.7  : Added ScriptNeedsInputFile variable!
	- 2.6  : Added Get-RandomString function!
	- 2.5  : Added Get-CurrentDirectory function!
	- 2.4  : Added custom filters to Get-FileName function!
	- 2.3  : Added Exchange Management Shell support!
#>

[CmdletBinding()]
Param(
	[Parameter(Mandatory=$false)][string]$InputFile,
	[Parameter(Mandatory=$false)][string]$OutputFile,
	[Parameter(Mandatory=$false)][string]$LogFile,
	[Parameter(Mandatory=$false)][switch]$TestRun,
	[Parameter(Mandatory=$false)][switch]$UseAdminCredential,
	[Parameter(Mandatory=$false)]$AdminCredential = [System.Management.Automation.PSCredential]::Empty,
	[Parameter(Mandatory=$false)]$AdminCredentialPassFile,
	[Parameter(Mandatory=$false)][int]$MinPowerShellVersion = 3,
	[Parameter(Mandatory=$false)][string]$SettingsFile = 'Settings.json',
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

$ScriptHasSettingsFile = $true # Whether the script requires a Settings.json file to define parameters and variables
$ScriptGeneratesOutputFile = $true # Whether an output file is generated (the log file is ALWAYS generated)

$ScriptNeedsInputFile = $true # Whether the script requires a file to be specified using the -InputFile parameter
$ScriptInputFileType = "" # Leave blank for .csv, or specify the extension type (excluding the "."). Use "*" for all files
$MinPowerShellVersion = 5.0

# ========= END VARIABLE DEFINITION ===========

# ============= SCRIPT CONSTANTS ==============

$ScriptName = $MyInvocation.MyCommand.Name -replace ".ps1",""
$ScriptExecutionTime = Get-Date
$ScriptExecutionTimestamp = Get-Date -Format "yyyy-MM-dd HH-mm-ss"

switch ( $Null ) {
	$Logfile {
		if ( -not ( Test-Path ".\LOG\" ) ) {
			New-Item -ItemType Directory -Path ".\LOG" | Out-Null
		}
		$script:Logfile = ".\LOG\$ScriptName $ScriptExecutionTimestamp.log"
	}
	$OutputFile {
		if ( $ScriptGeneratesOutputFile ) {
			if ( -not ( Test-Path ".\OUTPUT\" ) ) {
				New-Item -ItemType Directory -Path ".\OUTPUT" | Out-Null
			}
			$script:OutputFile = ".\OUTPUT\$ScriptName $ScriptExecutionTimestamp.csv"
		}
	}
}

$credSplat = @{} # Credential splat
$aDWSSplat = @{} # AD Web Services requirement (when finding a DC using certain template functions)
$eaSplat = @{ ErrorAction = "Stop" } # Error Action splat
$testSplat = @{}

$Settings = @() # Populated during the Load-Variables function

$TotalProcessed = $TotalErrors = $TotalWarnings = 0

# ========== END SCRIPT CONSTANTS =============

# ======== TEMPLATE FUNCTIONS ========

function Convert-FileTime {
	Param(
		[Parameter(ValueFromPipeline=$true)][Int64]$Time
	)
	return [DateTime]::FromFileTime($Time)
}

function Exit-Script {
    Param(
        [switch]$Failed
    )

	Write-Log "Exiting script...`r`n"

	if ( $SuperDebug ) {
		Stop-Transcript
	}
    
    if ( $Failed ) {
        exit -1
    }

	exit
}

function Get-DC {
	Param(
		[string]$Domain,
		[switch]$ReturnDCNameOnly
	)

	if ( -not $Domain -or $Domain -eq "Root" ) {
		$Domain = (Get-ADForest).RootDomain
	}

	$DC = Get-ADDomainController -Discover -ForceDiscover -DomainName $Domain @aDWSSplat
	Write-Log "Using domain controller $( $DC.HostName[0] ) for $Domain" -Level "VERBOSE"

	if ( $ReturnDCNameOnly ) {
		return $DC.HostName[0]
	} else {
		return $DC
	}
}

function Get-AllDCs {
	Param (
		[array]$Domains = (Get-ADDomain).DNSRoot,
		$ADSites,
		[switch]$ForestWide,
		[switch]$DCNamesOnly,
		[switch]$DirectReturn
	)

	if ( -not $script:Scope ) {
		$script:Scope = @{}
	}

	if ( $ForestWide ) {
		$ForestRoot = ( Get-ADDomain $Domains[0] ).Forest
		$Domains = ( Get-ADForest $ForestRoot ).Domains
		Write-Log "Enumerating DCs in forest $ForestRoot"
	} else {
		Write-Log "Enumerating DCs in $Domains..."
	}

	foreach ( $Domain in $Domains ) {
		for ( $i = 1; $i -le 3; $i++ ) {
			try {
				$ConnectionDC = ( Get-ADDomainController -DomainName $Domain -ForceDiscover -Discover @aDWSSplat ).HostName[0]
				Write-Log "Using DC $ConnectionDC for enumeration" -Level "VERBOSE"
				[array]$DomainDCs = Get-ADDomainController -Filter * -Server $ConnectionDC @eaSplat
				if ( $ADSites ) {
					if ( $ADSites -is [array] ) {
						if ( $($ADSites -join " ").ToCharArray() -contains "*" ) {
							Write-Log "if multiple AD sites are specified, wildcards may not be used." -Level "ERROR"
							Throw "Invalid -ADSites parameter. Do not use wildcards if specifying an array of site names."
						}
						$DomainDCs = $DomainDCs | Where-Object { $ADSites -contains $_.Site }
					} else {
						$DomainDCs = $DomainDCs | Where-Object { $_.Site -like $( if ( $ADSites.ToCharArray() -contains "`*" ) { $ADSites } else { "$ADSites*" } ) }
					}
				}

				if ( $DCNamesOnly ){
					$DomainDCs = $DomainDCs.HostName
				}

				$script:Scope.Add( $Domain, $DomainDCs )
				Write-Log "Found $( ($Scope.$Domain).Count ) domain controllers in $Domain"
				break
			} catch {
				Write-Log "Could not enumerate DCs in $Domain... Attempt $i of 3" -Level "ERROR"
				Write-Log $_ -Level "ERROR"
				if ( $i -eq 3 ) {
					Write-Log "$Domain is being skipped..." -Level "ERROR"
					break
				}
			}
		}
	}

	if ( $DirectReturn){
		foreach ( $Domain in $Scope.Keys ){
			$DCs += $Scope.$Domain
		}

		$script:Scope = $Null

		return $DCs
	}
}

function Get-ComputerSite {
	Param( [string]$Computer )

	if ($Computer) {
		$site = nltest /server:$Computer /dsgetsite 2 > $null
		if ( -not $LASTEXITCODE ) { $site[0] } else { "ERROR" }
	} else {
		try {
			[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
		} catch {
			"ERROR"
		}
	}
}

function Get-Confirmation {
	Param(
		[string]$Message,
		[switch]$ExitOnNo,
		[switch]$DefaultToYes,
		[string]$CustomOptions
	)

	if ( $CustomOptions ) {
		if ( $CustomOptions -cmatch "[A-Z]") {
			$DefaultOption = $Matches[0]
		}
		$Options = $CustomOptions -split ","

		$confirmation = Read-Host "$Message`n[$( $Options -join "/")]"

		if ( $DefaultOption -and ($confirmation -eq "") ) {
			return $DefaultOption
		}

		while ( $Options -notcontains $confirmation ) {
			$confirmation = Read-Host "Invalid option. `n$Message`n[$( $Options -join " / ")]"
		}
		return $confirmation
	} else {
		if ( $DefaultToYes ) { $YesVar = "Y" } else { $YesVar = "y" }

		do {
			$confirmation = Read-Host "$Message [$YesVar/n]"

			switch ( $confirmation ) {
				"n" {
					if ( $ExitOnNo ) {
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
					if ( $DefaultToYes -and ($confirmation -eq "") ) { return $true }
				}
			}
		} while ( -not $validInput )
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
	Param(
		[Parameter(ParameterSetName="IDFilter")][int]$EventID,
		[ValidateSet("Verbose","Info", "Warning", "Error", "Critical")][Parameter(ParameterSetName="LevelFilter")]$EventLevel = "Error",
		[string]$LogName = "Application",
		[int]$DaysToParse = 7,
		$Computer
	)

	$Computers = @()
	switch ( $true ) {
		( $Computer -is [System.String] ) {
			$Computers += $Computer
			break
		}
		( $Computer -is [Microsoft.ActiveDirectory.Management.ADAccount] ) {
			$Computers += $Computer.DNSHostName
			break
		}
		( $Computer -is [System.Array] ) {
			if ( $Computer[0] -is [System.String] ) {
				$Computer | ForEach-Object{ $Computers += $_ }
			} elseif ( $Computer[0] -is [Microsoft.ActiveDirectory.Management.ADAccount] ) {
				$Computer | ForEach-Object{ $Computers += $_.DNSHostName }
			}
		}
	}

	$FilterHash = @{ LogName = $LogName; StartTime = (Get-Date).AddDays(-$DaysToParse); }
	if ( $EventID ) {
		$FilterHash.Add( "ID", $EventID )
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
	$FilterHash.Add( "Level", $LevelIDs[$EventLevel] )

	foreach ( $computer in $Computers ) {
		try {
			$Events = Get-WinEvent -ComputerName $computer -FilterHashtable $FilterHash @credSplat -ErrorAction SilentlyContinue -Verbose:$false | Select-Object MachineName,Id,Message,ProviderName
			foreach ( $event in $Events ) {
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
	Param(
		[string]$CustomFileType,
		[switch]$AllFiles
	)

	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") > $null

	$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	# $OpenFileDialog.InitialDirectory = $initialDirectory
	if ( $CustomFileType ) {
		$OpenFileDialog.Filter = "Custom File Type (*.$CustomFileType)| *.$CustomFileType|All Files (*.*)| *.*"
	} else {
		$OpenFileDialog.Filter = "CSV Files (*.csv)| *.csv|All Files (*.*)| *.*"
	}
	$OpenFileDialog.ShowHelp = $true
	$OpenFileDialog.ShowDialog() > $null
	return $OpenFileDialog.FileName
}

function Get-IPAddress {
	Param ( $Computer )
	$return = @()

	foreach ( $target in $Computer ) {
		if ( $Computer[0] -is [System.String] ) {
			$ComputerName = $target
		} elseif ( $Computer[0] -match [Microsoft.ActiveDirectory.Management.ADComputer]$temp ) {
			$ComputerName = $target.Name
		}

		$result = [pscustomobject]@{ ComputerName = $ComputerName; IPAddress = [System.Net.Dns]::GetHostByName($ComputerName).AddressList[0].IPAddressToString }
		$return += $result
	}

	return $return
}

function Get-RandomString {
	Param(
		[int]$Length = 10,
		[switch]$NumbersOnly,
		[switch]$AlphaOnly,
		[switch]$AlphaNumeric,
		[switch]$Password,
		[switch]$Complex,
		[switch]$ExtraHard,
		[switch]$AsSecureString
	)

	[string]$Random = $null

	$SpecialCharacters = (33,35,36,37,38,40,41,42,43,60,61,62,63,64,94,123,125,126) | ForEach-Object { [char]$_ }

	switch ( $true ) {
		$NumbersOnly {
			$sourcedata = (0..9)
			break;
		}
		$AlphaOnly {
			$sourcedata = $null
			for ( $a = 65 ; $a –le 90; $a++ ) {
				$sourcedata += ,[char][byte]$a
			}
			break;
		}
		$AlphaNumeric {
			$sourcedata = (0..9)
			for ( $a = 65 ; $a –le 90; $a++ ) {
				$sourcedata += ,[char][byte]$a
			}
			break;
		}
		$Password {
			$sourcedata = (0..9)
			for ( $a = 65 ; $a –le 90; $a++ ) {
				$sourcedata += ,[char][byte]$a
			}
			for ( $a = 97 ; $a –le 122; $a++ ) {
				$sourcedata += ,[char][byte]$a
			}
			break;
		}
		default {
			$sourcedata = $null
			for ( $a = 33; $a –le 126; $a++ ) {
				$sourcedata += ,[char][byte]$a
			}
		}
	}

	if ( $Password ) {
		if ( $ExtraHard ) {
			if ( $Length -lt 14 ) { $Length = 14 }
			$Length -= 4
		} else {
			$Length -= 2
		}
		for ( $loop = 1; $loop –le $Length; $loop++ ) {
			$Random += ( $sourcedata[10..61] | Get-Random )
		}
		for ( $loop = 1; $loop –le 2; $loop++ ) {
			$Random += ( $sourcedata[0..9] | Get-Random )
		}
	} else {
		for ( $loop = 1; $loop –le $Length; $loop++ ) {
			$Random += ( $sourcedata | Get-Random )
		}
	}

	if ( $ExtraHard -or $Complex ) {
		(1..2) | ForEach-Object { $Random += (Get-Random $SpecialCharacters) }
	}

	if ( $AsSecureString ) {
		return (ConvertTo-SecureString -AsPlainText -Force -String $Random)
	} else {
		return $Random
	}
}
function Import-Settings {
	try {
		# Cleans up the file before converting it to JSON. Specifically, removes all "comments" and then makes sure that any commented-out items don't create dangling commas
		$SettingsJson =  ( (Get-Content -Raw -Path $SettingsFile) -replace "//.*?\n","`n" ) -replace ",\n}","\n}"
		$SettingsData = ConvertFrom-Json -InputObject $SettingsJson -ErrorAction Stop
	} catch {
		Write-Log "This script is configured to use a Settings file ($SettingsFile), but it wasn't found or it is not formatted properly." -Fatal
		exit
	}

	if ( $SettingsData.settings ) {
		Write-Log "Now reading in settings from $SettingsFile"
		$Script:Settings = @{}
		foreach ( $setting in ($SettingsData.settings | Get-Member -Name * -MemberType NoteProperty).Name ) {
			Try{
				$Script:Settings[$setting] = $SettingsData.settings.$setting
				Write-Log "Set variable $setting to $(Get-Variable $setting -ValueOnly)" -Level "VERBOSE"
			} catch {
				Write-Log "Could not configure setting $setting. Check the $SettingsFile file and try again" -Level "ERROR"
			}
		}
	}

	if ( $SettingsData.variables ) {
		Write-Log "Now reading in variable values from $SettingsFile."
		$Script:Variables = @{}
		foreach ( $variable in ($SettingsData.variables | Get-Member -Name * -MemberType NoteProperty).Name ) {
			Try{
				$Script:Variables[$variable] = $SettingsData.variables.$variable
				Write-Log "Set variable $variable to $(Get-Variable $variable -ValueOnly)" -Level "VERBOSE"
			} catch {
				Write-Log "Could not set variable $variable. Check the $SettingsFile file and try again" -Level "ERROR"
			}
		}
	}
}

function Initialize-Script {
	# Clear the error log
	$Error.Clear()

	# Foremost, see if there's a Settings.json file and load it.
	if ( $ScriptHasSettingsFile ) {
		Import-Settings
	}

	# Check if the log file already exists; if not, create it
	if ( -not ( Test-Path $LogFile ) ) {
		New-Item -Path $LogFile -ItemType File -Force | Out-Null
	}

	Write-Log "Initializing $ScriptName..."

	if ($MinPowerShellVersion -and $PSVersionTable.PSVersion.ToString() -lt $MinPowerShellVersion ) {
		Write-Log "This script requires Microsoft PowerShell version $MinPowerShellVersion or later to run. Please install the latest version of the Windows Management Framework or the PowerShell standalone component and run this script again. Sowwy." -Fatal
	}

	# Check for the input file, if one is specified in the script
	if ( $ScriptNeedsInputFile ) {
		if ( -not $InputFile ) {
			$iftSplat = @{}
			if ( $ScriptInputFileType ) {
				$iftSplat["CustomFileType"] = $ScriptInputFileType
			}
			$script:InputFile = Get-FileName @iftSplat
		}
	}

	# Check if the output path already exists; if not, create it
	if ( -not ( Test-Path ".\OUTPUT\" ) ) {
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
	if ( $ScriptGeneratesOutputFile ) {
		if ( Test-Path $OutputFile ) {
			if ( ( Read-Host "Specified output file $OutputFile exists. Overwrite? [Y/N]" ) -ne "Y" ) {
				Write-Log "Specified output file exists" -Level "ERROR" -Fatal
			} else {
				Write-Log "Overwriting output file '$OutputFile'"
			}
		}
		New-Item -Path $OutputFile -ItemType File | Out-Null
		"`"" + $( $OutputHeaders -join "`",`"" ) + "`"" | Out-File $OutputFile -Encoding UTF8 # Pre-populate the headers in the output file, to make sure they are not constrained to the headers of the first record
	}


	foreach ( $module in $NeedsModules ) {
		if ( -not (Get-Module $module) ) {
			try {
				Import-Module $module -ErrorAction Stop
				Write-Log "Loaded module $module." -Level "VERBOSE"
			} catch {
				Write-Log "Could not load $module`: $_" -Level "ERROR" -Fatal
			}
		}
	}

	# Check if alternate admin credentials are to be used
	if ( $UseAdminCredential ) {
		switch ( $true ) {
			( $AdminCredentialPassFile ) {
				$AdminPass = Get-Content $AdminCredentialPassFile | ConvertTo-SecureString
			}
			( $AdminCredential -isnot [System.Management.Automation.PSCredential] ) {
				Write-Log "if using the -AdminCredential parameter, please pass a PSCredential object. Or omit the -AdminCredential parameter to be prompted for credentials" -Level "ERROR" -Fatal
				break
			}
			( $AdminCredential -eq [System.Management.Automation.PSCredential]::Empty ) {
				if ( $AdminPass ) {
					$AdminUsername = Read-Host "Password read from $AdminCredentialPassFile. Please specify the username to use"
					$AdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $AdminUsername,$AdminPass
				} else {
					$AdminCredential = Get-Credential -Message "Please specify an administrator account to use"
				}
				Write-Log "Admin credentials loaded for $($AdminCredential.UserName)" -Level "VERBOSE"
			}
		}

		$script:credSplat['Credential'] = $AdminCredential
	}

	# Check whether to set the -Whatif parameter on cmdlets that support it (custom functions should use the $TestRun variable directly to determine whether to make changes)
	if ( $TestRun ) {
		$testSplat["Whatif"] = $true
	}

	# Get current user. You know, for accountability
	$Executor = [Environment]::UserName
	Write-Log "Welcome, $Executor. Your actions are being logged. You know, for accountability."
	Start-Sleep -Seconds 1

	# if there are any logs, pause for review
	if ( $Error.Count ) {
		Write-Log "Initialization errors encountered." -Level "ERROR"
		if ( Get-Confirmation "Continue loading the script?" ) {
			return
		} else {
			Exit-Script
		}
	}
}

function Resolve-SID {
	Param( $SID )

	try {
		if ( $SID -isnot [System.Security.Principal.SecurityIdentifier] ) {
			$SID = New-Object System.Security.Principal.SecurityIdentifier( $SID )
		}
		$User = $SID.Translate( [System.Security.Principal.NTAccount] )
		$Username = $User.Value
	} catch {
		Write-Log "Could not resolve $SID to a username" -Level "WARNING"
		$Username = "UNKNOWN ($SID)"
	}

	return $Username
}

function Send-Email {
	Param(
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

	$DefaultSubject = "$ScriptName Email - $( Get-Date -Format "yyyy/MM/dd hh:mm:ss tt" )"
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
		Subject = $( if ( $Subject ) { $Subject } else { $DefaultSubject } );
		Body = $( if ( $CustomFullBody ) { $CustomFullBody } else { $DefaultBody } )
		BodyAsHtml = $true;
	}

	if ( $CCRecipients ) {
		if ( $CCRecipients -is [string] ) {
			$CCRecipients = $CCRecipients -split ";"
		}
		$MessageParams.Add( "Cc", $CCRecipients )
	}
	if ( $BCCRecipients ) {
		if ( $BCCRecipients -is [string] ) {
			$BCCRecipients = $BCCRecipients -split ";"
		}
		$MessageParams.Add( "Bcc", $BCCRecipients )
	}

	switch ( $true ) {
		$AttachLogFile { $Attachments += ,(Get-Item -Path $LogFile).FullName }
		$AttachOutputFile { $Attachments += ,(Get-Item -Path $OutputFile).FullName }
	}
	if ( $Attachments ) { $MessageParams.Add( "Attachments", $Attachments ) }

	try {
		Write-Log "Emailing report to $( $Recipients -join "," )..."
		Send-MailMessage @MessageParams @credSplat
	} catch {
		Write-Log "Could not send report email. Check the parameters for the next iteration of the script." -Level "ERROR"
		Write-Log "Line $( $_.InvocationInfo.ScriptLineNumber ) - $_" -Level "ERROR"
	}
}

function Test-Connectivity {
	Param(
		[string]$ComputerName,
		[int]$Port
	)

	if ( $Port ) {
		try {
			return ( New-Object System.Net.Sockets.TCPClient -ArgumentList $ComputerName, $Port -ErrorAction SilentlyContinue ).Connected
		} catch {
			return $false
		}
	} else {
		return [bool]( Test-Connection -ComputerName $ComputerName -Count 2 -ErrorAction SilentlyContinue )
	}
}

function Start-ConfirmationTimer {
	Param(
		[string]$Message,
		[int]$secondsToWait = 10,
		[Switch]$OnlyShowDots
	)

	Write-Host -NoNewline "$Message"

	while ( $secondsToWait -ge 0 ) {
		if ( -not [console]::KeyAvailable ) {
			if ( $OnlyShowDots ) {
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
	Param( [string]$Message="Press any key to continue..." )

	if ( $psISE ) { # The "ReadKey" functionality is not supported in Windows PowerShell ISE
		Write-Host "`n$Message`n"
		$Shell = New-Object -ComObject "WScript.Shell"
		$Shell.Popup($Message, 0, "Script Paused", 0)
		return
	}

	Write-Host $Message -ForegroundColor Cyan

	$Ignore = 16,17,18,20,91,92,93,144,145,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183

	while ( $null -eq $KeyInfo.VirtualKeyCode -or $Ignore -contains $KeyInfo.VirtualKeyCode) {
			$KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
	}
}

function Write-Data {
	[CmdletBinding()]Param(
		[Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)]$Record,
		[Parameter(Mandatory=$false, Position=2)][ValidateSet("csv","text","json")]$WriteType = "csv",
		[Parameter(Mandatory=$false, Position=2)]$Output = $OutputFile,
		[Parameter(Mandatory=$false, Position=3)][bool]$Force = $false
	)

	if ( $Record -is [hashtable] ) {
		$Record = [pscustomobject]$Record
	}

	if ( -not (Test-Path $Output) ) {
		Write-Log "Output file $Output did not exist. Creating..." -Level "VERBOSE"
		if ( $Output -like "*\*") {
			$ParentPath = Split-Path $Output
			if (-not (Test-Path "$ParentPath\") ) {
				try {
					New-Item -ItemType Directory -Path $ParentPath -Force | Out-Null
				} catch {
					Write-Log $_
					Write-Log "Could not create parent path for output file" -Level "ERROR" -Fatal
				}
			}
		}
	}

	switch ( $WriteType ) {
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
	Param(
		[Parameter()]$Message,
		[Parameter()][ValidateSet("INFO","WARNING","ERROR","VERBOSE")][string]$Level = "INFO",
		[Parameter()][switch]$Silent,
		[Parameter()][switch]$Fatal,
		[Parameter()][switch]$Separator
	)

	# Ignore VERBOSE entries if the "Verbose" flag is not set
	if ( $Level -eq "VERBOSE" -and $VerbosePreference -ne "Continue" ) { return }

	if ( $Separator ) {
		"`r`n--------------------`r`n" | Add-Content $LogFile
		return
	}

	$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

	if ( $Message -is [System.Management.Automation.ErrorRecord] ) {
		if ( $Level -eq "INFO" ) {
			$Level = "ERROR"
		}
		$Output = "$Level`t: $Message at line $($Message.InvocationInfo.ScriptLineNumber)"
	} else {
		$Output = "$Level`t: $Message"
	}

	if ( -not $Silent ) {
		# Set the color for the console output and update counters
		switch ( $Level ) {
			"WARNING" { $Color = "Yellow"; $TotalWarnings++; break }
			"ERROR" { $Color = "Red"; $TotalErrors++; break }
			"VERBOSE" { $Color = "Gray"; break }
			default { $Color = "White" }
		}

		Write-Host $Output -Fore $Color
	}

	"$Timestamp`t$Output" | Add-Content $LogFile

	if ( $Fatal ) {
		"FATAL: The previous error was fatal. The script will now exit." | Add-Content $LogFile
		Write-Host "FATAL: The previous error was fatal. The script will now poop the bed." -Fore Red
		Exit-Script -Failed
	}
}

# ======== END SCRIPT TEMPLATE ==========

# ======== CUSTOM FUNCTION DEFINITION ========

# ======== END CUSTOM FUNCTION DEFINITION ========


# ======== THE MAGIC ========

if ( $DefaultToVerbose ) {
	$VerbosePreference = continue
}

if ( $SuperDebug ) {
	Start-Transcript -Path "Debug.log"
	$DebugPreference = continue
}

Initialize-Script

#INSERT MAGIC HERE

Exit-Script
# ======== END THE MAGIC ========