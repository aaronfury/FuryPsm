# FuryPsm
A PowerShell Module with useful functions

# Changelog
- 24.0309 : It lives! Cleaned up some irrelevant code, added more parameters for handling log and output files.
- 23.0529 : Reintroduced settings file support. This whole thing still needs a lot of work to be a module. For now, consider it a code reference...
- 23.0306 : This is now a module!
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

# Planned Improvements
- Split up the module into sub-modules
- Better documentation of functions
- Remove/rework things that made sense as a script template but not as a module
- See what can/should be changed for PS7+