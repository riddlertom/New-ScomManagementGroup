#Requires -Version 7 -RunAsAdministrator
<#
.SYNOPSIS
    # Installs a sql server for use by scom on a server.

.DESCRIPTION

    $FEATURES:
        SQLEngine - for use as an Operations and/or DatawarehouseDW backend server. Note: Fulltext feature is auto-added here as well.
        RS - Installs SSRS instance for SCOM reporting
        ManagementTools - Will attempt to install the latest powershell module 'SQLServer', and Management Studio (SSMS)
        UpdateToLatest - After feature installations, will download and apply latest CU update for SQL roles
        RSInit - Initializes and creates the post-install db script for Reporting Services
        setSQLServerPort - Allows you to change the sql server listening port on all IPs (automatically called by 'SQLEngine' operation)

.NOTES
    Author: Tom Riddle
.LINK
    https://github.com/riddlertom/New-ScomManagementGroup

#>
param(
    # Service name. Mandatory, by default MSSQLSERVER
    [ValidateSet('SQLEngine','RS','ManagementTools','UpdateToLatest','RSInit')]
    [string[]]$FEATURES,

    # Contains the settings used by this file
    [string]$configFilePath = "$PSScriptRoot\_config.ps1"
)


#add config file.

#region: INIT

    $nullme = new-item -Path "$PSScriptRoot\Logs" -ItemType Directory -Force
    Start-Transcript -Path ("$PSScriptRoot\Logs\$($script:MyInvocation.MyCommand.name).{0:MM-dd-yyyy_hh.mm.ss.mm}.log" -f (get-date))

    if( !(Test-Path $configFilePath) ){write-error "Unable to find config file: $configFilePath"; pause;return;}else{
        . $configFilePath
    }
    
    write-host "Checking/Installing DBA module prereqs"
    #order of import-module is key here to avoid error 'Microsoft.Data.SqlClient.dll | Assembly with same name is already loaded'
    $dbamodule = get-module -ListAvailable dbatools
    if(!$dbamodule){$dbamodule = install-module dbatools -Force -PassThru}
    if(!$dbamodule){Write-Error "Unable to install needed module: dbatools";pause;return}
    Import-Module dbatools

    $sqltoolsModule = get-Module SQLServer -ListAvailable
    if(!$sqltoolsModule ){ $sqltoolsModule = Install-Module SQLServer -Force -PassThru}
    if(!$sqltoolsModule){Write-Error "Unable to install needed module: SQLServer";pause;return}
    try{Import-Module SQLServer -ea 0}catch{continue} #supress scary dll conflicts
    
    
#endregion



###########################
#region: Functions

Function set_SQLServerPort {
    #updates sqlserver to listen on specified port on all ipaddresses 
    #taken mostly from https://github.com/rajendragp/RajendraScripts/blob/master/PSScriptForSettingStaticPort.PS1
    param(
        $computerName = $env:COMPUTERNAME,
        $instanceName = 'MSSQLSERVER', #instance to connect to
        $port = 1433
    )
    
    $smo = 'Microsoft.SqlServer.Management.Smo.'
    $wmi = New-Object ($smo + 'Wmi.ManagedComputer')

    # For the named instance, on the current computer, for the TCP protocol,
    # loop through all the IPs and configure them to use the standard port
    # of 1433.
    $uri = "ManagedComputer[@Name='$($wmi.name)']/ ServerInstance[@Name='$instanceName']/ServerProtocol[@Name='Tcp']"

    try{
        $Tcp = $wmi.GetSmoObject($uri)
        foreach ($ipAddress in $Tcp.IPAddresses)
        {
            $ipAddress.IPAddressProperties["TcpDynamicPorts"].Value = ""
            $ipAddress.IPAddressProperties["TcpPort"].Value = "$port"  #Specify the SQL port number to set 
            Write-Output "SQL Server static port set: $($ipAddress.name)"
        }
        write-host "Applying changes..."
        $Tcp.Alter()
        
        Invoke-Command -ComputerName $computerName -ScriptBlock {
            Get-Service -displayname "SQL Server ($($using:instanceName))" | restart-service -force -Verbose
        }

    }catch{
        write-error $_
    }
}

Function Install-SQLServerManagementStudio {
    #will install SSMS
    param(
        $InstallDir = $env:TEMP # Path where we find SSMS-Setup-ENU.exe. Downloading saves there.
    )
    
    $Installer = "SSMS-Setup-ENU.exe"
    $URL = "https://aka.ms/ssmsfullsetup"

    if(!(test-path "$InstallDir\$Installer")){
        # Download SSMS
        Write-Host "Downloading SQL Server Management Studio..."
        Invoke-WebRequest $URL -OutFile "$InstallDir\$Installer"
    }else{
        write-host "Using previously downloaded file: $InstallDir\$Installer"
    }

    Write-Host "Installing SQL Server Management Studio..."
    write-host "SSMS Setup Logs at: $env:LOCALAPPDATA\Temp\SsmsSetup\"
    Start-Process -FilePath "$InstallDir\$Installer" -ArgumentList "/install /quiet" -Wait

    dir "$env:LOCALAPPDATA\Temp\SsmsSetup\" | sort LastWriteTime | select -Last 1 | %{cat $_ -Last 100}
    
}

Function Install-SqlServer {
    <#
    .SYNOPSIS
        MS SQL Server silent installation script

    .DESCRIPTION
        This script installs MS SQL Server unattended from the ISO image.
        Transcript of entire operation is recorded in the log file.

        The script lists parameters provided to the native setup but hides sensitive data. See the provided
        links for SQL Server silent install details.
    .NOTES
        Version: 1.1

    .LINK
        https://raw.githubusercontent.com/majkinetor/Install-SqlServer/master/Install-SqlServer.ps1
    #>
    param(
        # Path to ISO file, if empty and current directory contains single ISO file, it will be used.
        [string] $IsoPath = $ENV:SQLSERVER_ISOPATH,

        # Sql Server features, see https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-2016-from-the-command-prompt#Feature
        [ValidateSet('SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase', 'AdvancedAnalytics', 'AS', 'RS', 'DQC', 'IS', 'MDS', 'SQL_SHARED_MR', 'Tools', 'BC', 'BOL', 'Conn', 'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB')]
        [string[]] $Features = @('SQLEngine'),

        # Specifies a nondefault installation directory
        [string] $InstallDir,

        # Data directory, by default "$Env:ProgramFiles\Microsoft SQL Server"
        [string] $DataDir,

        # Service name. Mandatory, by default MSSQLSERVER
        [ValidateNotNullOrEmpty()]
        [string] $InstanceName = 'MSSQLSERVER',

        # sa user password. If empty, SQL security mode (mixed mode) is disabled
        [string] $SaPassword = "P@ssw0rd",

        # Username for the service account, see https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-2016-from-the-command-prompt#Accounts
        # Optional, by default 'NT Service\MSSQLSERVER'
        [string] $ServiceAccountName, # = "$Env:USERDOMAIN\$Env:USERNAME"

        # Password for the service account, should be used for domain accounts only
        # Mandatory with ServiceAccountName
        [string] $ServiceAccountPassword,

        # List of system administrative accounts in the form <domain>\<user>
        # Mandatory, by default current user will be added as system administrator
        [string[]] $SystemAdminAccounts = @("$Env:USERDOMAIN\$Env:USERNAME"),

        # Product key, if omitted, evaluation is used unless VL edition which is already activated
        [string] $ProductKey,

        # Use bits transfer to get files from the Internet
        [switch] $UseBitsTransfer,

        # Enable SQL Server protocols: TCP/IP, Named Pipes
        [switch] $EnableProtocols,

        #Non-default DataDir-specific directories
        [string]$SQL_SQLUSERDBDIR,
        [string]$SQL_SQLUSERDBLOGDIR,
        [string]$SQL_SQLTEMPDBDIR,
        [string]$SQL_SQLTEMPDBLOGDIR,
        [string]$SQL_SQLBACKUPDIR
    )

    $ErrorActionPreference = 'STOP'
    $scriptName = (Split-Path -Leaf $PSCommandPath).Replace('.ps1', '')

    $start = Get-Date
    Start-Transcript "$PSScriptRoot\$scriptName-$($start.ToString('s').Replace(':','-')).log"

    if (!$IsoPath) {
        Write-Host "SQLSERVER_ISOPATH environment variable not specified, using defaults"
        $IsoPath = "https://download.microsoft.com/download/7/c/1/7c14e92e-bdcb-4f89-b7cf-93543e7112d1/SQLServer2019-x64-ENU-Dev.iso"

        $saveDir = Join-Path $Env:TEMP $scriptName
        New-item $saveDir -ItemType Directory -ErrorAction 0 | Out-Null

        $isoName = $isoPath -split '/' | Select-Object -Last 1
        $savePath = Join-Path $saveDir $isoName

        if (Test-Path $savePath){
            Write-Host "ISO already downloaded, checking hashsum..."
            $hash    = Get-FileHash -Algorithm MD5 $savePath | % Hash
            $oldHash = Get-Content "$savePath.md5" -ErrorAction 0
        }

        if ($hash -and $hash -eq $oldHash) { Write-Host "Hash is OK" } else {
            if ($hash) { Write-Host "Hash is NOT OK"}
            Write-Host "Downloading: $isoPath"

            if ($UseBitsTransfer) {
                Write-Host "Using bits transfer"
                $proxy = if ($ENV:HTTP_PROXY) { @{ ProxyList = $ENV:HTTP_PROXY -replace 'http?://'; ProxyUsage = 'Override' }} else { @{} }
                Start-BitsTransfer -Source $isoPath -Destination $saveDir @proxy
            }  else {
                Invoke-WebRequest $IsoPath -OutFile $savePath -UseBasicParsing -Proxy $ENV:HTTP_PROXY
            }

            Get-FileHash -Algorithm MD5 $savePath | % Hash | Out-File "$savePath.md5"
        }

        $IsoPath = $savePath
    }

    Write-Host "`IsoPath: " $IsoPath

    $volume = Mount-DiskImage $IsoPath -StorageType ISO -PassThru | Get-Volume
    $iso_drive = if ($volume) {
        $volume.DriveLetter + ':'
    } else {
        # In Windows Sandbox for some reason Get-Volume returns nothing, so lets look for the ISO description
        Get-PSDrive | ? Description -like 'sql*' | % Root
    }
    if (!$iso_drive) { throw "Can't find mounted ISO drive" } else { Write-Host "ISO drive: $iso_drive" }

    Get-ChildItem $iso_drive | ft -auto | Out-String

    Get-CimInstance win32_process | ? { $_.commandLine -like '*setup.exe*/ACTION=install*' } | % {
        Write-Host "Sql Server installer is already running, killing it:" $_.Path  "pid: " $_.processId
        Stop-Process $_.processId -Force
    }

    $cmd =@(
        "${iso_drive}setup.exe"
        '/Q'                                # Silent install
        '/INDICATEPROGRESS'                 # Specifies that the verbose Setup log file is piped to the console
        '/IACCEPTSQLSERVERLICENSETERMS'     # Must be included in unattended installations
        '/ACTION=install'                   # Required to indicate the installation workflow
        '/UPDATEENABLED=false'              # Should it discover and include product updates.

        "/INSTANCEDIR=""$InstallDir"""
        "/INSTALLSQLDATADIR=""$DataDir"""

        "/FEATURES=" + ($Features -join ',')

        #Security
        "/SQLSYSADMINACCOUNTS=""$SystemAdminAccounts"""
        '/SECURITYMODE=SQL'                 # Specifies the security mode for SQL Server. By default, Windows-only authentication mode is supported.
        "/SAPWD=""$SaPassword"""            # Sa user password

        "/INSTANCENAME=$InstanceName"       # Server instance name

        "/SQLSVCACCOUNT=""$ServiceAccountName"""
        "/SQLSVCPASSWORD=""$ServiceAccountPassword"""

        # Service startup types
        "/SQLSVCSTARTUPTYPE=automatic"
        "/AGTSVCSTARTUPTYPE=automatic"
        "/ASSVCSTARTUPTYPE=manual"

        "/SQLCOLLATION=SQL_Latin1_General_CP1_CI_AS"
        "/PID=$ProductKey"

        "/SQLUSERDBDIR=$SQL_SQLUSERDBDIR"
        "/SQLUSERDBLOGDIR=$SQL_SQLUSERDBLOGDIR"
        "/SQLTEMPDBDIR=$SQL_SQLTEMPDBDIR"
        "/SQLTEMPDBLOGDIR=$SQL_SQLTEMPDBLOGDIR"
        "/SQLBACKUPDIR=$SQL_SQLBACKUPDIR"
    )

    # remove empty arguments
    $cmd_out = $cmd = $cmd -notmatch '/.+?=("")?$'

    # show all parameters but remove password details
    Write-Host "Install parameters:`n"
    'SAPWD', 'SQLSVCPASSWORD' | % { $cmd_out = $cmd_out -replace "(/$_=).+", '$1"****"' }
    $cmd_out[1..100] | % { $a = $_ -split '='; Write-Host '   ' $a[0].PadRight(40).Substring(1), $a[1] }
    Write-Host

    "$cmd_out"
    Invoke-Expression "$cmd"
    if ($LastExitCode) {
        if ($LastExitCode -ne 3010) { throw "SqlServer installation failed, exit code: $LastExitCode" }
        Write-Warning "SYSTEM REBOOT IS REQUIRED"
    }

    if ($EnableProtocols) {
        function Enable-Protocol ($ProtocolName) { $sqlNP | ? ProtocolDisplayName -eq $ProtocolName | Invoke-CimMethod -Name SetEnable }

        Write-Host "Enable SQL Server protocols: TCP/IP, Named Pipes"

        $sqlCM = Get-CimInstance -Namespace 'root\Microsoft\SqlServer' -ClassName "__NAMESPACE"  | ? name -match 'ComputerManagement' | Select-Object -Expand name
        $sqlNP = Get-CimInstance -Namespace "root\Microsoft\SqlServer\$sqlCM" -ClassName ServerNetworkProtocol

        Enable-Protocol 'TCP/IP'
        Enable-Protocol 'Named Pipes'

        Get-Service -displayname "SQL Server ($InstanceName)" | Restart-Service -Force
    }

    "`nInstallation length: {0:f1} minutes" -f ((Get-Date) - $start).TotalMinutes

    Dismount-DiskImage $IsoPath
    Stop-Transcript
    #trap { Stop-Transcript; if ($IsoPath) { Dismount-DiskImage $IsoPath -ErrorAction 0 } }
}

Function Get-SqlCU{
    #https://github.com/andreasjordan/demos/blob/master/dbatools/Get-CU.ps1
    [CmdletBinding()]
    param (
        [ValidateSet('2022', '2019', '2017', '2016', '2014')]
        [string[]]$Version = @('2022', '2019', '2017'),
        [int]$Last = 1,
        [string]$Path = '.',
        [switch]$UpdateBuildReference = $true
    )

    function Get-CU {
        param(
            [Parameter(Mandatory)]
            [ValidateSet('2022', '2019', '2017', '2016', '2014')]
            [string]$Version,
            [regex]$BuildBaseRegex,
            [int]$Last = 1,
            [string[]]$Exclude,
            [string]$Path = '.'
        )
        if ($null -eq $BuildBaseRegex) {
            $BuildBaseRegex = switch ($Version) {
                '2022' { '^16' }
                '2019' { '^15' }
                '2017' { '^14' }
                '2016' { '^13.0.5' }  # Based on SP2
                '2014' { '^12.0.6' }  # Based on SP3
            }
        }
        if ($Version -eq '2019') { 
            $Exclude += 'CU7'  # CU7 is not available any more
        }
        $buildrefFile = Join-Path -Path (Get-DbatoolsConfigValue -Name 'Path.DbatoolsData') -ChildPath "dbatools-buildref-index.json"
        $buildrefData = (Get-Content -Path $buildrefFile -Raw | ConvertFrom-Json).Data
        $cuData = $buildrefData | 
            Where-Object -FilterScript { $_.Version -match $BuildBaseRegex -and $_.CU -ne $null -and $_.CU -notin $Exclude } |
            Sort-Object -Property KBList |
            Select-Object -Last $Last
        foreach ($cu in $cuData) {
            $kbNr = $cu.KBList
            $cuName = $cu.CU
            $filePath = Join-Path -Path $Path -ChildPath "SQLServer$Version-KB$kbNr-$cuName-x64.exe"
            if (-not (Test-Path -Path $filePath)) {
                Write-Progress -Activity "Downloading Cumulative Updates for SQL Server" -Status "Downloading KB $kbNr for SQL Server $Version to $filePath"
                Save-DbaKbUpdate -Name $kbNr -FilePath $filePath 
            }else{
                $filePath
            }
        }
    }


    if ($UpdateBuildReference) {
        Write-Progress -Activity "Downloading Cumulative Updates for SQL Server" -Status "Updating build reference"
        Update-DbaBuildReference
    }

    foreach ($ver in $Version) {
        Get-CU -Version $ver -Last $Last -Path $Path
    }

    Write-Progress -Activity "Downloading Cumulative Updates for SQL Server" -Completed


    <# Other usage examples:

    Get-CU -Version 2019 -Path 'C:\SQLServerPatches'
    Get-CU -Version 2017 -Path 'C:\SQLServerPatches' -Last 5
    Get-CU -Version 2016 -Path 'C:\SQLServerPatches' -Last 5
    Get-CU -Version 2014 -Path 'C:\SQLServerPatches'
    # KB4583462 - Security update for SQL Server 2014 SP3 CU4: January 12, 2021
    Save-DbaKbUpdate -Name 4583462 -FilePath 'C:\SQLServerPatches\SQLServer2014-KB4583462-CU4-Security-x64.exe'
    # KB4583465 - Security update for SQL Server 2012 SP4 GDR: January 12, 2021
    Save-DbaKbUpdate -Name 4583465 -FilePath 'C:\SQLServerPatches\SQLServer2012-KB4583465-GDR-Security-x64.exe'
    # Check for new versions at: https://sqlserverbuilds.blogspot.com/
    # KB5003830 - New CU that is not yet known by dbatools
    Save-DbaKbUpdate -Name 5003830 -FilePath 'C:\SQLServerPatches\SQLServer2017-KB5003830-CU25-x64.exe'

    #>
}

Function priv_AddDomainUsertoGroup($domain, $username, $groupname, $computer="localhost"){
	#Run as administratator
		$objOUgrp = [ADSI]"WinNT://$computer/$groupname,group"
		
		$objOUgrp.psbase.Invoke("Add",([ADSI]"WinNT://$domain/$username").path) 
}

Function priv_RemoveDomainUsertoGroup($domain, $username, $groupname, $computer="localhost"){
	#Run as administratator
		$objOUgrp = [ADSI]"WinNT://$computer/$groupname,group"
		
		$objOUgrp.psbase.Invoke("Remove",([ADSI]"WinNT://$domain/$username").path) 
}

Function priv_configureSSRSPostInstall {	
	#Helper to autosetup your freshly-installed, non-configured SSRS instance.
	#https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/AutomatedLab/AutomatedLab%20-%20SCOM%202019%20-%20all-in-one%20installer%20(unattended).ps1
	param(
        $connStr
	)



    $sqltoolsModule = get-Module SQLServer -ListAvailable
    if(!$sqltoolsModule ){ $sqltoolsModule = Install-Module SQLServer -Force -PassThru}
    if(!$sqltoolsModule){Write-Error "Unable to install needed module: SQLServer";pause;return}
    Import-Module SQLServer
	
    #help 2016 work
    $versionName = powershell -command {gwmi -Namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS" __Namespace | select -expand name}
    if($versionName.count -gt 1){write-error "Unable to determine namespace path. Possibly mutltiple SSRS installation present."; return}
	function Get-ConfigSet {
        param(
            $versionName = "v14"
        )
		
		#return Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v15\Admin" -class MSReportServer_ConfigurationSetting -ComputerName localhost
		return Get-CimInstance -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\$versionName\Admin" -class MSReportServer_ConfigurationSetting -ComputerName localhost
	}
	
	function setMaxEnvelopeSizeKb {
		#helper function for when using CIM methods in PS7
		param(
			$sizeKB = 8192 #default is 500
		)
			
		try{			
			$currentSize = get-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Force
			if($currentSize -and $currentSize.Value -lt $sizeKB){
				Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value $sizeKB -force
				write-host "Set MaxEnvelopeSizeKb from '$($currentSize.Value)' to: $sizeKB"
				return $sizeK
			}else{
				return $currentSize.Value
			}
		}catch{write-error $_}		
	}
	$nullme = setMaxEnvelopeSizeKb
	
	# Allow importing of sqlps module
	#Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
	
	# Retrieve the current configuration
	$configset = Get-ConfigSet -versionName $versionName
	if(!$configset){write-error "Unable to query SSRS namespace.";return}
	If (!$configset.IsInitialized)
	{
		
		# Import the SQL Server PowerShell module
		#Import-Module sqlps -DisableNameChecking | Out-Null
		
		# Establish a connection to the database server (localhost)
		$conn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection -ArgumentList $connStr
		$conn.ApplicationName = "SSRS Configuration Script"
		$conn.StatementTimeout = 0
		$conn.Connect()
		$smo = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList $conn



		# Get the ReportServer and ReportServerTempDB creation script
		#[string]$dbscript = $configset.GenerateDatabaseCreationScript("ReportServer", 1033, $false).Script
		$dbscript0 = $configset|Invoke-CimMethod -MethodName "GenerateDatabaseCreationScript" -Arguments @{'DatabaseName'="ReportServer";'IsSharePointMode'=$false;'Lcid'=1033;}
		$dbscript = $dbscript0.Script
		
		# Create the ReportServer and ReportServerTempDB databases
		$db = $smo.Databases["master"]
		$db.ExecuteNonQuery($dbscript)
		
		
		
		# Set permissions for the databases
		#$dbscript = $configset.GenerateDatabaseRightsScript($configset.WindowsServiceIdentityConfigured, "ReportServer", $false, $true).Script
		#$dbscript = $configset.GenerateDatabaseRightsScript($configset.WindowsServiceIdentityConfigured, "ReportServer", $false, $true).Script
		$dbscript0=$configset|Invoke-CimMethod -MethodName 'GenerateDatabaseRightsScript' -Arguments @{'UserName'=[string]$configset.WindowsServiceIdentityConfigured;'DatabaseName'=[string]'ReportServer';'IsRemote'=[bool]$false;'IsWindowsUser'=[bool]$true;}
		$dbscript = $dbscript0.Script
		$db.ExecuteNonQuery($dbscript)
		
		# Set the database connection info
		#$configset.SetDatabaseConnection("$env:ComputerName\$SQLInstanceName", "ReportServer", 2, "", "")
		$configset|Invoke-CimMethod -MethodName 'SetDatabaseConnection' -Arguments @{'Server'=[string]"$connStr";'DatabaseName'=[string]'ReportServer';'CredentialsType'=[Int32]2;'UserName'=[string]'';'Password'=[string]'';}
		
		#$configset.SetVirtualDirectory("ReportServerWebService", "ReportServer", 1033)
		$configset|Invoke-CimMethod -MethodName 'SetVirtualDirectory' -Arguments @{'Application'=[string]'ReportServerWebService';'VirtualDirectory'=[string]'ReportServer';'Lcid'=[Int32]1033;}
		
		#$configset.ReserveURL("ReportServerWebService", "http://+:80", 1033)
		$configset|Invoke-CimMethod -MethodName 'ReserveURL' -Arguments @{'Application'=[string]'ReportServerWebService';'UrlString'=[string]"http://+:80";'Lcid'=[Int32]1033;}
		
		
		
		# For SSRS 2016-2017 only, older versions have a different name
		#$configset.SetVirtualDirectory("ReportServerWebApp", "Reports", 1033)
		$configset|Invoke-CimMethod -MethodName 'SetVirtualDirectory' -Arguments @{'Application'=[string]'ReportServerWebApp';'VirtualDirectory'=[string]'Reports';'Lcid'=[Int32]1033;}
		
		#$configset.ReserveURL("ReportServerWebApp", "http://+:80", 1033)
		$configset|Invoke-CimMethod -MethodName 'ReserveURL' -Arguments @{'Application'=[string]'ReportServerWebApp';'UrlString'=[string]"http://+:80";'Lcid'=[Int32]1033;}
		
		
		try
		{
			#$configset.InitializeReportServer($configset.InstallationID)
			$configset|Invoke-CimMethod -MethodName 'InitializeReportServer' -Arguments @{'InstallationID'=[string]$configset.InstallationID;}
		}
		catch
		{
			throw (New-Object System.Exception("Failed to Initialize Report Server $($_.Exception.Message)", $_.Exception))
		}
		
		# Re-start services?
		#$configset.SetServiceState($false, $false, $false)
		$configset|Invoke-CimMethod -MethodName 'SetServiceState' -Arguments @{'EnableWindowsService'=[bool]$false;'EnableWebService'=[bool]$false;'EnableReportManager'=[bool]$false;}
		
		Restart-Service $configset.ServiceName
		
		#$configset.SetServiceState($true, $true, $true)
		$configset|Invoke-CimMethod -MethodName 'SetServiceState' -Arguments @{'EnableWindowsService'=[bool]$true;'EnableWebService'=[bool]$true;'EnableReportManager'=[bool]$true;}
		
		# Update the current configuration
		$configset = Get-ConfigSet -versionName $versionName
		

		#$inst = Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v15" -class MSReportServer_Instance -ComputerName localhost
		$inst = Get-CimInstance -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\$versionName" -class MSReportServer_Instance -ComputerName localhost
		
		$inst|Invoke-CimMethod -MethodName 'GetReportServerUrls'

	}else{
		
		write-host "SSRS is already configured as IsInitialized=$($configset.IsInitialized)"
	}
	
		# Output to screen
		#$($configset.ListReportServersInDatabase())
		#$($configset.ListReservedUrls())
		
		write-host "
		IsReportManagerEnabled=$($configset.IsReportManagerEnabled)
		IsInitialized=$($configset.IsInitialized)
		IsWebServiceEnabled=$($configset.IsWebServiceEnabled)
		IsWindowsServiceEnabled=$($configset.IsWindowsServiceEnabled)
		$($configset|Invoke-CimMethod -MethodName 'ListReportServersInDatabase' | out-string)
		$($configset|Invoke-CimMethod -MethodName 'ListReservedUrls' | out-string)
		"
}

#region: Functions
###########################

$connobj = priv_getSQLConnStr

#separate out our custom "feature"
$UpdateToLatest = $FEATURES -contains 'UpdateToLatest'
[string[]]$FEATURES = $FEATURES | ?{$_ -ne 'UpdateToLatest'}


if($FEATURES -contains 'ManagementTools'){
    
    $FEATURES = $FEATURES | ?{$_ -ne 'ManagementTools'}

   
    Install-SQLServerManagementStudio -InstallDir $SSMSexeDir
    
}

if($FEATURES){

    if($FEATURES -contains 'SQLEngine'){

            [string[]]$FEATURES += "FullText" #ensure full text is enabled
            try{
                #open common sql ports in advance
                write-host "Setting firewall rules"
                $nullme = Set-NetFirewallRule -Name WMI-WINMGMT-In-TCP -Enabled True -ea 0
                $nullme = New-NetFirewallRule -Name "SQL DB" -DisplayName "SQL Database" -Profile Domain -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow -ea 0
                $nullme = New-NetFirewallRule -Name "SQL Server Admin Connection" -DisplayName "SQL Admin Connection" -Profile Domain -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow -ea 0
                $nullme = New-NetFirewallRule -Name "SQL Browser" -DisplayName "SQL Browser" -Profile Domain -Direction Inbound -LocalPort 1434 -Protocol UDP -Action Allow -ea 0
                $nullme = New-NetFirewallRule -Name "SQL Instance Custom Port" -DisplayName "SQL Instance Custom Port" -Profile Domain -Direction Inbound -LocalPort $connobj.portToUse -Protocol TCP -Action Allow -ea 0
                $nullme = New-NetFirewallRule -Name "SQL Server 445" -DisplayName "SQL Server 445" -Profile Domain -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow -ea 0
                $nullme = New-NetFirewallRule -Name "SQL Server 445 client" -DisplayName "SQL Server 445" -Profile Domain -Direction Outbound -LocalPort 445 -Protocol TCP -Action Allow -ea 0
                $nullme = New-NetFirewallRule -Name "SQL Server 135" -DisplayName "SQL Server 135" -Profile Domain -Direction Inbound -LocalPort 135 -Protocol TCP -Action Allow -ea 0

                write-host "adding to local admins: $SQLUser"
                priv_RemoveDomainUsertoGroup -domain $NetBiosDomainName -username $SQLUser -groupname "Administrators" -computer "localhost"
                priv_AddDomainUsertoGroup -domain $NetBiosDomainName -username $SQLUser -groupname "Administrators" -computer "localhost"
            }catch{}
    


        $config = @{
            'IsoPath' = $SQLServerISO;
            'Features' = $FEATURES;
            'InstanceName' = $connobj.instanceNametoUse;
            'SaPassword' = $SQLUserPass;
            'ServiceAccountName' = "$NetBiosDomainName\$SQLUser";
            'ServiceAccountPassword' = $SQLUserPass;
            'EnableProtocols' = $true;
            'ProductKey' = $SQLProductKey;

            'InstallDir' = $SQL_INSTANCEDIR;                
            'DataDir' = $SQL_INSTALLSQLDATADIR;
            'SQL_SQLUSERDBDIR'=$SQL_SQLUSERDBDIR;
            'SQL_SQLUSERDBLOGDIR'=$SQL_SQLUSERDBLOGDIR;
            'SQL_SQLTEMPDBDIR'=$SQL_SQLTEMPDBDIR;
            'SQL_SQLTEMPDBLOGDIR'=$SQL_SQLTEMPDBLOGDIR;
            'SQL_SQLBACKUPDIR'=$SQL_SQLBACKUPDIR;
        }
        
        #try{
        Install-SqlServer @config
        #}catch{write-error $_;continue}

        #we set this asap so all other operations work in the script
        set_SQLServerPort -computerName $connobj.serverNameToUse -instanceName $connobj.instanceNametoUse -port $connobj.portToUse

        try{
            $SQLLogin = Add-SqlLogin -ServerInstance $connobj.connStr -LoginName "$NetBiosDomainName\$SCOMDataAccessAccount" -LoginType "WindowsUser" -Enable
            $SQLLogin.AddToRole("sysadmin")
            write-host "Added user to sysadmin: $NetBiosDomainName\$SCOMDataAccessAccount"
        }catch{write-error "Error granting sysadmin to account: $SCOMDataAccessAccount "}

        try{
            $server = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList $connobj.connStr # $Env:COMPUTERNAME
            $perms = New-Object -TypeName "Microsoft.SqlServer.Management.Smo.ServerPermissionSet"
            $perms.ConnectSql = $true
            $server.Grant($perms, $SQLLogin.name)
            
            write-host "Enabled remote connections too account: $SCOMDataAccessAccount "
        }catch{write-error $_}


    }
    

    if($FEATURES -contains 'RS'){ #open reporting firewall ports in advance

        try{
            New-NetFirewallRule -Name "SQL SRRS (HTTP)" -DisplayName "SQL SRRS (HTTP)" -Profile Domain -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow -ea 0 
            New-NetFirewallRule -Name "SQL SRRS (SSL)" -DisplayName "SQL SRRS (SSL)" -Profile Domain -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow -ea 0
        }catch{}

        if(!(test-path $SsrsExeLocation)){
            write-host "No SSRS binary found at config var 'SsrsExeLocation', with value: $SsrsExeLocation"
            write-host "Download and set a source from https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/install-reporting-services"
             return
        }

        <#
        /log file specifies the setup log file location. By default log files are created under %TEMP%.
        Example: /log log.txt
        /InstallFolder sets the install folder.
        Default: "C:\Program Files\Microsoft SQL Server Reporting Services"
        Example: choco install -y ssrs-2019 --package-parameters='"/InstallFolder:"'C:\Program Files\SSRS'""'
        /PID sets the custom license key.
        Example: choco install -y ssrs-2019 --package-parameters='"/PID:12345-12345-12345-12345-12345"'
        /Edition sets the custom free edition. Options are Dev, Eval, or ExprAdv.
        Default: Eval
        Example: choco install -y ssrs-2019 --package-parameters='"/Edition:Dev"'
        /EditionUpgrade upgrades the edition of the installed product. Required /PID or /Edition flag.
        Example: choco install -y ssrs-2019 --package-parameters='"/EditionUpgrade /Edition:Dev"'
        Example: choco install -y ssrs-2019 --package-parameters='"/EditionUpgrade /PID:PID:12345-12345-12345-12345-12345"'
       
        New-Item -Path  "$SSRS_InstallDir\touch" -Force | out-null
        $shortPath0 = (New-Object -ComObject Scripting.FileSystemObject).GetFile("$SSRS_InstallDir\touch").ShortPath
        $shortPath = $shortPath0 | Split-Path
         #>

        $installStr = "/quiet /IAcceptLicenseTerms /Edition=Eval" #/InstallFolder='$shortPath'
        if($SSRSProductKey){$installStr = "$installStr /PID=$SSRSProductKey"}
        
        write-host "SSRS Setup Logs at: $env:LOCALAPPDATA\Temp\SSRS"
        Start-Process -FilePath $SsrsExeLocation -ArgumentList $installStr -Wait

        dir "$env:LOCALAPPDATA\Temp\SSRS" | sort LastWriteTime | select -Last 1 | %{cat $_ -Last 50}
            
    }

}


if($UpdateToLatest){
 

    #get sql version
    #$Sqlcred = [pscredential]::new("$SQLUser@$FQDNDomainName",(convertto-securestring $SQLUserPass -asplaintext -force))


    write-host "
    A Note On Updating SSRS: Just download the latest package manually and install it.
    If you try to update SSRS 2017 or later, using a SQL Server service pack media or Cumulative Update (CU), the installer will not be finding any SQL Server components/features to update.
    So, in order to update SSRS 2017 or later, you just need to download the latest SSRS installer from Microsoft, and run the installation process on the SSRS server to be updated. 
    Then, after running the installer, you will be asked whether you want to proceed with updating the existing SSRS installation or not.
    -https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/install-reporting-services
    "

    $sqlsourceDir = split-path $SQLServerISO -Parent
    write-host "Updating to latest Patch Level..."
    try{

        #$vObj = invoke-SqlCmd -ServerInstance "." -Query "SELECT @@VERSION"  -trustServerCertificate
        #$regex=[regex]::Match($vObj.Column1,"Microsoft SQL Server (....)")
        #[int]$ServerYear = $regex.Groups[-1].Value 
        
        #$res1 = Get-SqlCU -Version $ServerYear -Path $sqlsourceDir -Last 1 -UpdateBuildReference #may be empty if previously downloaded.
        #if(!$res1){write-error "Could not determine latest KB to save"}

         # Easy to inspect version tables at: https://sqlserverbuilds.blogspot.com/
        $res2 = Update-DbaInstance -ComputerName $connobj.serverNameToUse -InstanceName $connobj.instanceNametoUse -Path $sqlsourceDir -Confirm:$false -Type All -ArgumentList "/SkipRules=RebootRequiredCheck" -Download #-credential $OScred -ArgumentList (,"/Q") 

    }catch{
        write-error $_
    }


}

if($FEATURES -contains 'RSInit'){

    write-host "Now running the SSRS post-config script..."
    #$r1 = Start-Process -FilePath "$env:ProgramFiles\Microsoft SQL Server Reporting Services\Shared Tools\rsconfig.exe" -ArgumentList "-c -s localhost -d ReportServer -a Windows -i SSRS" -Wait

    priv_configureSSRSPostInstall -connStr $connobj.connStr
    # Retrieve the current configuration
}

Stop-Transcript