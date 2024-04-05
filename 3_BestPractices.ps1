#Requires -Version 7 -RunAsAdministrator
<#
.SYNOPSIS
    Sets various best practices/fixes for SQL and SCOM


.DESCRIPTION

    $Operation:
    
        On Allservers:
        setTimeZone - Sets the timezone. Recommend UTC time as it can affect database entries. Run on all Management Servers and Gateways, and databases
        setSystemLocaleENUS - Uncommon. Sets the system locale to enus. Solves certain problems if not set. Run on all Management Servers and Gateways and databases

        Datawarehouse:
        PreSizeSCOMOpsDB - Alters SCOM OperationsManager DB and LOG larger sizes to increase performance/avoid FILEGROUP FULL errors
        PreSizeSCOMOpsDWH - Alters SCOM OperationsManagerDW DB and LOG larger sizes to increase performance/avoid FILEGROUP FULL errors
        EnableOpsDBAutoGrowth - Alters SCOM OperationsManager DB and LOG sizes to allow for autogrowth (please separate your dbs onto different drives using calculator or run out of space)
        EnableAgentDefaultProxying - Enables SCOM agents --BY DEFAULT-- to having proxying enabled. (OperationsManager Module has this unexposed, must use the old snapin SCOM2016-2019 tested)
        SetSqlHighPerfPowerPlan - Tells windows to use the high performance power plan on the Sql servers.
        
        GetDbsDOPRecommend - Runs the "tempdb + Degree of Parallism" sql script to determine what DOP|Tempdb values [are set/to set] for Opsdb/opsdw SqlServers. Inspect the change script if any.
        OpsDBEnableBroker - Checks if the broker is enabled on the OPSDb and enables it if not.
        OpsDBEnableCLR - Checks if CLR is enabled on the OPSDb node and enables it if not. Needed in SQL AlwaysOn scenarios. Run on all clustered nodes.
        SetDbsSqlMaintPlan - Installs hallengren's SQL maintenance plan that creates jobs you then MANUALLY schedule & configure for reindexing,stats,integrity, and backups 
        
        On All MS/Gateways:
        SetHealthServiceRegTweaks - Adds performance tweaks for large environments. Run on all Management Servers and Gateways.
        EnforceTls12 - For higher security environments. Sets up prereqs and restricts communications to tls12 vs insecure lower versions. Run on all Management,Gateway,MsSql,Webconsole servers.

        On RMS:        
        AutoApproveNewWinAgents - Tells SCOM to let manually-installed SCOM agents report in without manual approval
        InitTLSSupport - Lets SCOM console talk to MP Catalog
        ImportLogonasServicePack - This runs on all windows agents to enable the logonasservice right for action accounts if it is not present already.
        ImportSelfMaintenanceMP - TODO:Helps with standard scom admin maintenance tasks by importing Kevin Holman's selfMaintenance pack.

        EnableScomLinuxMonitoring - Generates and imports certs for SCX monitoring. Also imports Unix MPs from setup media.
        addScomSDKSPNs - registers SCOM sdk account spns for all non-gateway management servers in activedirectory.

        SetWebBindingSSL - Enables port 443 ssl for IIS's "Default Web Site" 

        

.NOTES
    Makes heavy use of windowsPowershell remoting and SCOM "OperationsManager" modules
    The latest CU should be applied before alot of these fixes.

.LINK


#>
param(
    # Service name. Mandatory, by default MSSQLSERVER
    [ValidateSet('EnableScomLinuxMonitoring','AutoApproveNewWinAgents','InitTLSSupport','PreSizeSCOMOpsDB','PreSizeSCOMOpsDWH','EnableOpsDBAutoGrowth','EnableAgentDefaultProxying','ImportLogonasServicePack','ImportSelfMaintenanceMP','SetSqlHighPerfPowerPlan','SetHealthServiceRegTweaks','setTimeZone','setSystemLocaleENUS','addScomSDKSPNs','OpsDBEnableBroker','OpsDBEnableCLR','GetDbsDOPRecommend','EnforceTls12','SetDbsSqlMaintPlan','SetWebBindingSSL')]
    [string[]]$Operation,

    [string]$configFilePath = "$PSScriptRoot\_config.ps1"
)

#region: Functions
###########################

Function priv_expandSCOMsetup {

    #returns a path to the setup.exe folder after expanding
    if( !(test-path "$SCOMSetupLocalFolder\setup.exe") ){

        if( !(test-path $SCOMEXELocation) ){Write-Error "No SCOM setup.exe files were found.";return $null;}
        
        try{
            write-host "Expanding SCOM setup at: $SCOMSetupLocalFolder\setup.exe"
            $ArgumentList = @(
                "/dir=`"$SCOMSetupLocalFolder`" `"/silent`""
            )        
            $res1 = Start-Process -FilePath $SCOMEXELocation -ArgumentList $ArgumentList -Wait
            write-host "Finished Expanding SCOM setup"
        }catch{write-error $_}
        if( !(test-path "$SCOMSetupLocalFolder\setup.exe") ){Write-Error "No SCOM setup.exe was extracted";return $null;}else{
            return "$SCOMSetupLocalFolder\setup.exe"
        }

    }else{
        return "$SCOMSetupLocalFolder\setup.exe"
    }
}

###########################
#endregion


#region: INIT

$nullme = new-item -Path "$PSScriptRoot\Logs" -ItemType Directory 
Start-Transcript -Path ("$PSScriptRoot\Logs\$($script:MyInvocation.MyCommand.name).{0:MM-dd-yyyy_hh.mm.ss.mm}.log" -f (get-date))

$currentDir = $PSScriptRoot.clone()

#$domainJoinCred = New-Object System.Management.Automation.PsCredential($domainUser,$secstring)
if( !(Test-Path $configFilePath) ){write-error "Unable to find config file: $configFilePath"; return;}
. $configFilePath



if( !(test-path "$SCOMSetupLocalFolder\setup.exe")){

	if( !(test-path "$SCOMEXELocation")){write-error "Unable to find/create SCOM install media: $SCOMSetupLocalFolder";return}else{
		$scomSetupEXEFullname = priv_expandSCOMsetup
	}
}else{
    $scomSetupEXEFullname = "$SCOMSetupLocalFolder\setup.exe"
}


$opsDBObj = priv_getSQLConnStr -targetComputer $SqlServerInstance
$SqlServerInstanceStr = $opsDBObj.connStr

$opsDWHObj =priv_getSQLConnStr -targetComputer $DWSqlServerInstance
$DWSqlServerInstanceStr = $opsDWHObj.connStr

#endregion


#region: main

if($Operation -contains 'EnableScomLinuxMonitoring'){

    write-host "Starting EnableScomLinuxMonitoring task."
    Import-Module operationsManager -UseWindowsPowerShell

    $MSNames = Get-SCOMManagementServer |?{!$_.isgateway} | select -expand Name

    $wsmanNotworking = $false
    foreach($MSName in $MSNames){
     
        if(! (Test-WSMan -ComputerName $MSName)){
            write-host "wsman not available on: $Msname!";
            $wsmanNotworking = $true
        }
    }
    if($wsmanNotworking -eq $true){write-error "WSMAN remoting not working on all management servers.";break}

    write-host "Exporting/Importing required SCX certs"
    # get all MSs and invoke-command
    Invoke-Command -computer $MSNames -ScriptBlock {
    
        $SCOMNasBackup = $Using:SCOMNasBackup
        # Define the registry path for SCOM installation
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
        if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCOM installed?";break;return;}else{
            # Get the installation path value
            $ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory
        }

        $dir = New-Item -Path $SCOMNasBackup -ItemType Directory -Force 
        if(!$dir){Write-error "Couldn't create backup folder at: $SCOMNasBackup";break;return}
    
        try{
            $exportFullname = "$SCOMNasBackup\Linux_$env:COMPUTERNAME.cer"
            Start-Process -PSPath "$ScomInstallPath\scxcertconfig.exe" -ArgumentList "-export $exportFullname" -NoNewWindow -Wait
            if($?){"[$env:COMPUTERNAME] Exported cert to: $exportFullname"}
        }catch{write-error $_}
    }

    # Import all but our own CERT.
    Invoke-Command -computer $MSNames -ScriptBlock {
        
        $SCOMNasBackup = $Using:SCOMNasBackup
        
        # Define the registry path for SCOM installation
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
        if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCoM installed?";break;return;}else{
            # Get the installation path value
            $ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory
        }

        $exportFullname = "$SCOMNasBackup\Linux_$env:COMPUTERNAME.cer"
        [array]$AllCerts = dir "$SCOMNasBackup\*.cer" 
        [array]$importCerts = $AllCerts| ?{$_.name -ne "Linux_$env:COMPUTERNAME.cer"}
        try{
            write-host "[$env:COMPUTERNAME] Starting import of Certs."
            foreach($importCert in $importCerts){
                
                    $exportFullname = "$SCOMNasBackup\Linux_$env:COMPUTERNAME.cer"
                    Start-Process -PSPath "$ScomInstallPath\scxcertconfig.exe" -ArgumentList "–import $($importCert.fullname)" -NoNewWindow -Wait
                    if($?){"[$env:COMPUTERNAME] Exported cert to: $exportFullname"}
                
            }
        }catch{write-error $_}
        write-host "[$env:COMPUTERNAME] Finished importing '$($importCerts.count)' of expected total of '$($AllCerts.count - 1)' Linux certs. (Self-cert is always skipped)"
    }

    #-----------------------------------------

    $module = Import-Module OperationsManager  -PassThru -UseWindowsPowerShell
    if(!$module){write-error "Missing required module 'operationsManager', is SCOM console installed here?";break;return;}

    $sess = Get-PSSession | ?{$_.name -eq "WinPSCompatSession"} | select -first 1
    Invoke-Command -Session $sess -ScriptBlock {
         . $using:configFilePath
         
         New-SCOMManagementGroupConnection -ComputerName $RMSServer | Set-SCOMManagementGroupConnection
    }

    write-host "Creating Linux pool"
    Invoke-Command -Session $sess -ScriptBlock {
        $MSObjs = Get-SCOMManagementServer
        [array]$MSObjs2 = $MSObjs | ?{!$_IsGateway}
        $MSNames = $MSObjs2 | select -ExpandProperty Name

        if($MSObjs2.count -eq 1){
            $poolMembers = $MSObjs2 
        }else{
            $poolMembers = $MSObjs2 | ?{!$_.IsRootManagementServer}
        }
       
        #create initial linux resoource pool (exclude RMS if possible)
        $poolObj = get-SCOMResourcePool -DisplayName $DefaulLinuxPoolName 
        if(!$poolObj){$poolObj = New-SCOMResourcePool -DisplayName $DefaulLinuxPoolName -Member $poolMembers }
    }

    write-host "Creating Linux Runas Accounts"
    Invoke-Command -Session $sess -ScriptBlock {
      
        $secString1 = convertto-securestring $linuxPrivMaintPass -asplaintext -force
        $privCred = New-Object System.Management.Automation.PSCredential ($linuxPrivMaintUser,$secString1)

        $secString2 = convertto-securestring $linuxAAPass -asplaintext -force
        $monCred = New-Object System.Management.Automation.PSCredential ($linuxAAUser,$secString2)


        $account = Get-SCOMRunAsAccount -Name "$linuxPrivMaintUser (Linux Maintenance)"
        if(!$account){$account = Add-SCOMRunAsAccount -SCXMaintenance -Name "$linuxPrivMaintUser (Linux Maintenance)" -RunAsCredential $privCred -Sudo}
        $account | Set-SCOMRunAsDistribution -LessSecure

        $account = Get-SCOMRunAsAccount -Name "$linuxPrivMaintUser (Linux High Priv)"
        if(!$account){$account = Add-SCOMRunAsAccount -SCXMonitoring -Name "$linuxPrivMaintUser (Linux High Priv)" -RunAsCredential $privCred -Sudo}
        $account | Set-SCOMRunAsDistribution -LessSecure

        $account = Get-SCOMRunAsAccount -Name "$linuxAAUser (Linux Action Account)"
        if(!$account){$account = Add-SCOMRunAsAccount -SCXMonitoring -Name "$linuxAAUser (Linux Action Account)" -RunAsCredential $monCred }
        $account | Set-SCOMRunAsDistribution -LessSecure
    }

    write-host "associate Linux creds to profiles"
    Invoke-Command -Session $sess -ScriptBlock {
        

        $Account = Get-SCOMRunAsAccount -Name  "$linuxAAUser (Linux Action Account)"
        $profile = Get-SCOMRunAsProfile -Name "Microsoft.Unix.ActionAccount"
        Set-SCOMRunAsProfile -Action "Add" -Profile $profile -Account $Account

        $Account = Get-SCOMRunAsAccount -Name  "$linuxAAUser (Linux High Priv)"
        $profile = Get-SCOMRunAsProfile -Name "Microsoft.Unix.PrivilegedAccount"
        Set-SCOMRunAsProfile -Action "Add" -Profile $profile -Account $Account

        $Account = Get-SCOMRunAsAccount -Name  "$linuxPrivMaintUser (Linux Maintenance)"
        $profile = Get-SCOMRunAsProfile -Name "Microsoft.Unix.AgentMaintenanceAccount"
        Set-SCOMRunAsProfile -Action "Add" -Profile $profile -Account $Account

    }

    #----------------------------

    write-host "find/import the linux packs"
    if( !(test-path $scomSetupEXEFullname) ){write-error "Missing SCOM local folderpath";break;}
    $scomInstallMediaFolder2 = Split-Path -Path $scomSetupEXEFullname #just in case bits shift between install and best practices.
    $packsFolder = "$scomInstallMediaFolder2\ManagementPacks"
    if( !(test-path $packsFolder)){Write-Error "Something went wrong finding Linux Management Packs folder at: $packsFolder";break}

    #we dont include the ACS packs
    [array]$MPSToImport = dir -Path $packsFolder | ? {$_.Extension -in '.mpb','.mp' -and $_.name -match "^Microsoft.(Linux|Unix|Solaris|HPUX|AIX)."}

    write-host "Trying oneshot import of $($MPSToImport.count) packs"
    try{Import-SCOMManagementPack -Fullname $MPSToImport.fullname -ErrorAction 0 -PassThru}catch{continue}
    
    foreach($mp in $MPSToImport){
        write-host "Importing Pack: $($mp.name)"
        try{Import-SCOMManagementPack -Fullname $mp.fullname -ErrorAction 0 -PassThru}catch{continue}
    }
    
    write-host "Finished linux monitoring setup"

}


if($Operation -contains 'AutoApproveNewWinAgents'){


    Set-SCOMAgentApprovalSetting -AutoApprove # -Pending is the default switch
}


if($Operation -contains 'InitTLSSupport'){

    write-host "[InitTLSSupport] Allowing dotnet to use TLS."
    # (fixes broken scom catalog) : enable The SchUseStrongCrypto setting allows .NET to use TLS 1.1 and TLS 1.2. The SystemDefaultTlsVersions setting allows .NET to use the OS configuration
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto  -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto  -Value 1

}


if($Operation -contains 'PreSizeSCOMOpsDB'){
    
    write-host "[PreSizeSCOMOpsDB] Starting to Presize the OpsDB"

    # Set your SQL Server and database details

    $DatabaseName = "OperationsManager"

    # Set the desired new size (in MB)
    $NewDataSizeMB = $initialSCOMDBSize
    [int]$NewLogSizeMB = $NewDataSizeMB / 2

    # Resize the database script
    $Query = @"
    USE [$DatabaseName]
    ALTER DATABASE [$DatabaseName] MODIFY FILE (NAME = N'MOM_DATA', SIZE = $($NewDataSizeMB)MB)
    ALTER DATABASE [$DatabaseName] MODIFY FILE (NAME = N'MOM_LOG', SIZE = $($NewLogSizeMB)MB)
"@

    try{
        # Connect to SQL Server
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = "Server=$SqlServerInstanceStr;Database=master;Integrated Security=True"
        $SqlConnection.Open()

        $SqlCommand = $SqlConnection.CreateCommand()
        $SqlCommand.CommandText = $Query
        $SqlCommand.CommandTimeout = 3600 #secss = 1hr
        $SqlCommand.ExecuteNonQuery()
    }catch{
        write-error $_
    }finally{
        # Close the connection
        $SqlConnection.Close()
    }

}

if($Operation -contains 'PreSizeSCOMOpsDWH'){
    
    write-host "[PreSizeSCOMOpsDWH] Starting to Presize the Ops Datawarehouse"

    # Set your SQL Server and database details

    $DatabaseName = "OperationsManagerDW"

    # Set the desired new size (in MB)
    $NewDataSizeMB = $initialSCOMDWHSize
    [int]$NewLogSizeMB = $NewDataSizeMB * .10

    # Resize the database script
    $Query = @"
    USE [$DatabaseName]
    ALTER DATABASE [$DatabaseName] MODIFY FILE (NAME = N'MOM_DATA', SIZE = $($NewDataSizeMB)MB)
    ALTER DATABASE [$DatabaseName] MODIFY FILE (NAME = N'MOM_LOG', SIZE = $($NewLogSizeMB)MB)
"@

    try{
        # Connect to SQL Server
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = "Server=$DWSqlServerInstanceStr;Database=master;Integrated Security=True"
        $SqlConnection.Open()

        $SqlCommand = $SqlConnection.CreateCommand()
        $SqlCommand.CommandText = $Query
        $SqlCommand.CommandTimeout = 3600 #secss = 1hr
        $SqlCommand.ExecuteNonQuery()
    }catch{
        write-error $_
    }finally{
        # Close the connection
        $SqlConnection.Close()
    }

}





if($Operation -contains 'EnableOpsDBAutoGrowth'){

    # Set your SQL Server and database details

    $DatabaseName = "OperationsManager"
    $LogFileGrowth = "10%" # 10% growth rate

    write-host "[EnableOpsDBAutoGrowth] Enable OpsDB Data and Log files growth at: $LogFileGrowth"

    # growth database script
    $Query = @"
    USE [$DatabaseName]
    ALTER DATABASE [$DatabaseName] MODIFY FILE (NAME = N'MOM_DATA', FILEGROWTH = $LogFileGrowth)
    ALTER DATABASE [$DatabaseName] MODIFY FILE (NAME = N'MOM_LOG', FILEGROWTH = $LogFileGrowth)
"@

    try{
        # Connect to SQL Server
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = "Server=$SqlServerInstanceStr;Database=master;Integrated Security=True"
        $SqlConnection.Open()

        $SqlCommand = $SqlConnection.CreateCommand()
        $SqlCommand.CommandText = $Query
        $SqlCommand.CommandTimeout = 3600 #secss = 1hr
        $SqlCommand.ExecuteNonQuery()

        Write-Host "[EnableOpsDBAutoGrowth] Autogrowth settings updated for database $DatabaseName"
    }catch{
        write-error $_
    }finally{
        # Close the connection
        $SqlConnection.Close()
    }

}


if($Operation -contains 'EnableAgentDefaultProxying'){

    write-host "[EnableAgentDefaultProxying] starting.. (OperationsManager Module has this unexposed, must use the old snapin; SCOM2016-2019 tested)"

    $module = Import-Module OperationsManager  -PassThru -UseWindowsPowerShell
    if(!$module){write-error "Missing required module 'operationsManager', is SCOM console installed here?";break;return;}
    $sess = Get-PSSession | ?{$_.name -eq "WinPSCompatSession"} | select -first 1

    Invoke-Command -Session $sess -ScriptBlock {
    
        #. $using:configFilePath
        # If you want to use this remotely – change “localhost” above to the FQDN of your SCOM server:
        add-pssnapin "Microsoft.EnterpriseManagement.OperationsManager.Client";
        new-managementGroupConnection -ConnectionString:$($using:RMSServer);

        # In order to inspect this setting, you can run:
        set-location "OperationsManagerMonitoring::";
        $defaults = Get-DefaultSetting #-Name HealthService\ProxyingEnabled
        $proxySetting = $defaults | ?{$_.name -eq 'HealthService\ProxyingEnabled'}

        if($proxySetting.Value -eq $true){return $proxySetting}else{

            Set-DefaultSetting -Name HealthService\ProxyingEnabled -Value True
        }

        set-location "$($using:currentDir)"
    }

}


if($Operation -contains 'ImportLogonasServicePack'){ 

    #https://kevinholman.com/2019/03/14/security-changes-in-scom-2019-log-on-as-a-service/

    write-host "[ImportLogonasServicePack] starting operation"

    $packPath = "$PSScriptRoot\extras\SCOM2019.RunAsHelper.xml"
    if( !(test-path $packPath) ){write-error "ManagementPack was not found at path: $packPath";break}
    
    $module = Import-Module OperationsManager  -PassThru -UseWindowsPowerShell
    if(!$module){write-error "Missing required module 'operationsManager', is SCOM console installed here?";break;}

    $sess = Get-PSSession | ?{$_.name -eq "WinPSCompatSession"} | select -first 1
    Invoke-Command -Session $sess -ScriptBlock {
        #. $using:configFilePath
         
        try{
        New-SCOMManagementGroupConnection -ComputerName $RMSServer | Set-SCOMManagementGroupConnection

        Import-SCOMManagementPack $using:packPath -Verbose

        write-host "Imported pack: $($using:packPath)"
        }catch{write-error $_}
    }

}


if($Operation -contains 'ImportSelfMaintenanceMP'){ 

    #https://kevinholman.com/2019/03/14/security-changes-in-scom-2019-log-on-as-a-service/

    write-host "[ImportSelfMaintenanceMP] starting operation"

    $packPath = "$PSScriptRoot\extras\SCOM.Management.xml"
    if( !(test-path $packPath) ){write-error "ManagementPack was not found at path: $packPath";break}
    
    $module = Import-Module OperationsManager  -PassThru -UseWindowsPowerShell
    if(!$module){write-error "Missing required module 'operationsManager', is SCOM console installed here?";break;}

    $sess = Get-PSSession | ?{$_.name -eq "WinPSCompatSession"} | select -first 1
    Invoke-Command -Session $sess -ScriptBlock {
        #. $using:configFilePath
         
        try{
        New-SCOMManagementGroupConnection -ComputerName $RMSServer | Set-SCOMManagementGroupConnection

        Import-SCOMManagementPack $using:packPath -Verbose

        write-host "Imported pack: $($using:packPath)"
        }catch{write-error $_}
    }

}





if($Operation -contains 'SetSqlHighPerfPowerPlan'){

    write-host "[SetSqlHighPerfPowerPlan] starting operation"


    $allsqlServerNames0 = @($DWSqlServerInstance,$SqlServerInstance,$SqlServerReportInstance)
    $allsqlServerNames1 = $allsqlServerNames0 | %{$_ -split "\." | select -first 1}
    $allsqlServerNames = $allsqlServerNames1 | sort -uniq

    if(!$allsqlServerNames){Write-Error "No sqlserver name(s) found/defined in config.";return}
    
    foreach($allsqlServerName in $allsqlServerNames){

        write-host "setting power plan for: $allsqlServerName"

        Invoke-Command -ComputerName $allsqlServerName -ScriptBlock {

            try{
            #$powerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'High Performance'" 
            #$powerPlan | Invoke-CimMethod -MethodName 'Activate' #doesn't work.

            $powerPlan = Get-CimInstance -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'High Performance'" 
            $instanceid = $powerPlan.InstanceID -split '\\' | select -Last 1 | %{$_.trim('{').trim('}')}
            Start-Process -wait "powercfg.exe" -ArgumentList "-SETACTIVE $instanceid" -NoNewWindow #check the server to confirm in control panel.
            write-host "Finished activating powerplan"
            }catch{write-error $_}
        }
    }

}


if($Operation -contains 'SetHealthServiceRegTweaks'){

    write-host "[SetHealthServiceRegTweaks] starting operation"

    #from remote session: pwsh -file .\3_BestPractices.ps1 -configFilePath ".\_config2019Prod.ps1" -Operation "SetHealthServiceRegTweaks"
    #https://kevinholman.com/2017/03/08/recommended-registry-tweaks-for-scom-2016-management-servers/

    $service = Get-Service -name healthservice -ea 0
    if(!$service){write-host "No SCOM install detected. IS this a SCOM Gateway or ManagementServer?";break}

    try{
    Invoke-Command -ScriptBlock { 
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\HealthService\Parameters" /v "State Queue Items" /t REG_DWORD /d 20480 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\HealthService\Parameters" /v "Persistence Checkpoint Depth Maximum" /t REG_DWORD /d 104857600 /f
        reg add "HKLM\SOFTWARE\Microsoft\System Center\2010\Common\DAL" /v "DALInitiateClearPool" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\System Center\2010\Common\DAL" /v "DALInitiateClearPoolSeconds" /t REG_DWORD /d 60 /f
        reg add "HKLM\SOFTWARE\Microsoft\System Center\2010\Common" /v "GroupCalcPollingIntervalMilliseconds" /t REG_DWORD /d 1800000 /f
        reg add "HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Data Warehouse" /v "Command Timeout Seconds" /t REG_DWORD /d 1800 /f
        reg add "HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Data Warehouse" /v "Deployment Command Timeout Seconds" /t REG_DWORD /d 86400 /f
        
    }
    write-host "Finished adding reg tweaks"
    }catch{write-host $_;break}
}


if($Operation -contains 'setTimeZone'){

    # why utc? things break after dst. https://kevinholman.com/2020/03/09/fix-maintenance-mode-schedules-after-a-dst-time-change/

    write-host "[setTimeZone] starting operation"    

    #Get-TimeZone -ListAvailable
    Set-TimeZone -Name $timezone1 -PassThru
}


if($Operation -contains 'setSystemLocaleENUS'){
    
    write-host "[setSystemLocaleENUS] starting operation"    

    #set locale.  https://technet.microsoft.com/en-us/library/hh852115.aspx  (Get-WinHomeLocation, get-culture,get-WinSystemLocale)
    Set-WinSystemLocale -SystemLocale en-US

    get-WinSystemLocale 
    write-host "you must reboot for a new local to take effect"
}


if($Operation -contains 'addScomSDKSPNs'){

    #https://kevinholman.com/2011/08/08/opsmgr-2012-what-should-the-spns-look-like/ # yes even on later scom version 2019 etc
    write-host "[addScomSDKSPNs] starting operation"


    $module = Import-Module OperationsManager  -PassThru -UseWindowsPowerShell
    if(!$module){write-error "Missing required module 'operationsManager', is SCOM console installed here?";break;return;}
    $sess = Get-PSSession | ?{$_.name -eq "WinPSCompatSession"} | select -first 1
    
    $ms = Get-SCOMManagementServer
    $ms2 = $ms | ?{$_.IsGateway -eq $false} | select -expand Name

    if(!$ms2){write-error "Couldn't find SCOM Management Servers";break}

    foreach($ms in $ms2){
        
        try{
            write-host "Setting spn with command: setspn.exe -A MSOMSdkSvc/$ms $SCOMDataAccessAccount"
            start-process "setspn.exe" -ArgumentList "-A MSOMSdkSvc/$ms $SCOMDataAccessAccount" -Wait -NoNewWindow
        }catch{write-error $_}
    }
    write-host "Finished setting SPNs"
    

}


if($Operation -contains 'OpsDBEnableBroker'){

    $sqltoolsModule = get-Module SQLServer -ListAvailable
    if(!$sqltoolsModule ){ $sqltoolsModule = Install-Module SQLServer -Force -PassThru}
    if(!$sqltoolsModule){Write-Error "Unable to install needed module: SQLServer";pause;return}
    try{Import-Module SQLServer -ea 0}catch{continue} #supress scary dll conflicts

    write-host "[OpsDBEnableBroker] starting operation"

    $testBrokerQuery = "SELECT is_broker_enabled FROM sys.databases WHERE name='OperationsManager'"
    $enableBrokerQuery = "
    ALTER DATABASE OperationsManager SET SINGLE_USER WITH ROLLBACK IMMEDIATE
	ALTER DATABASE OperationsManager SET ENABLE_BROKER
	ALTER DATABASE OperationsManager SET MULTI_USER
    "

    try{
        
    $res1 = invoke-SqlCmd -ServerInstance $SqlServerInstanceStr -Query $testBrokerQuery -trustServerCertificate
    if($res1 -and $res1.is_broker_enabled -eq $false){

        write-host "Broker was found disabled, enabling with query: `n$enableBrokerQuery"
        invoke-SqlCmd -ServerInstance $SqlServerInstanceStr -Query $enableBrokerQuery -trustServerCertificate
        invoke-SqlCmd -ServerInstance $SqlServerInstanceStr -Query $testBrokerQuery -trustServerCertificate
    }else{
        $res1
    }
    }catch{write-error $_}
}


if($Operation -contains 'OpsDBEnableCLR'){

    $sqltoolsModule = get-Module SQLServer -ListAvailable
    if(!$sqltoolsModule ){ $sqltoolsModule = Install-Module SQLServer -Force -PassThru}
    if(!$sqltoolsModule){Write-Error "Unable to install needed module: SQLServer";pause;return}
    try{Import-Module SQLServer -ea 0}catch{continue} #supress scary dll conflicts

    write-host "[OpsDBEnableCLR] starting operation"

    $testCLRQuery = "
    SELECT name,value
    FROM sys.configurations 
    WHERE name = 'clr enabled'
    "

    $enableCLRQuery = "
    EXEC sp_configure 'clr enabled', 1;  
    RECONFIGURE;  
    GO  
    "

    try{
    $res1 = invoke-SqlCmd -ServerInstance $SqlServerInstanceStr -Query $testCLRQuery -trustServerCertificate
    if($res1 -and $res1.value -eq 0){

        write-host "CLR was found disabled, enabling with query: `n$enableCLRQuery"
        invoke-SqlCmd -ServerInstance $SqlServerInstanceStr -Query $enableCLRQuery -trustServerCertificate
        invoke-SqlCmd -ServerInstance $SqlServerInstanceStr -Query $testCLRQuery -trustServerCertificate
    }else{
        $res1
    }
    }catch{write-error $_}
}


if($Operation -contains 'GetDbsDOPRecommend'){

    
    $sqltoolsModule = get-Module SQLServer -ListAvailable
    if(!$sqltoolsModule ){ $sqltoolsModule = Install-Module SQLServer -Force -PassThru}
    if(!$sqltoolsModule){Write-Error "Unable to install needed module: SQLServer";pause;return}
    try{Import-Module SQLServer -ea 0}catch{continue} #supress scary dll conflicts

    write-host "[GetDbsDOPRecommend] starting operation"

    $DOPscriptSql = @'

    /*
    ==================================================================================================
    Script Title: Configuration Script for MaxDOP and Cost Threshold for Parallelism
    Author: Blake Drumm
    Date: 2023-10-31
    Description: 
        This script is designed to review and recommend settings for MaxDOP and Cost Threshold for
        Parallelism for SQL Server in a System Center Operations Manager (SCOM) environment.
        It checks the current configuration, calculates recommended values based on the system's 
        hardware and existing settings, and generates a script for applying the recommended settings.

    Usage:
        1. Run the script in a SQL Server Management Studio (SSMS) query window connected to the target
        SQL Server instance.
        2. Review the results and execute the generated script if the recommended settings are acceptable.

    Revision History:
        2023-11-13: Added ability to check TempDB file count - Blake Drumm (blakedrumm@microsoft.com)
        2023-10-31: Fixed the MaxDOP Calculation - Blake Drumm (blakedrumm@microsoft.com)
        2023-10-30: Script created by Blake Drumm (blakedrumm@microsoft.com)

    Note:
        My personal blog: https://blakedrumm.com/
    ==================================================================================================
    */

    SET NOCOUNT ON;
    USE MASTER;

    -- Declare variables
    DECLARE @NumaNodes INT,
            @NumCPUs INT,
            @MaxDop INT,
            @RecommendedMaxDop INT,
            @CostThreshold INT,
            @TempDBFileCount INT,
            @RecommendedTempDBFileCount INT,
            @ChangeScript NVARCHAR(MAX) = '',
            @ShowAdvancedOptions INT;

    -- Initialize variables
    SELECT @NumaNodes = COUNT(DISTINCT parent_node_id) FROM sys.dm_os_schedulers WHERE status = 'VISIBLE ONLINE';
    SELECT @NumCPUs = cpu_count FROM sys.dm_os_sys_info;
    SELECT @MaxDop = CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'max degree of parallelism';
    SELECT @CostThreshold = CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'cost threshold for parallelism';
    SELECT @ShowAdvancedOptions = CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'show advanced options';
    SELECT @TempDBFileCount = COUNT(*) FROM sys.master_files WHERE database_id = 2 AND type_desc = 'ROWS';

    -- Recommended TempDB File Count Calculation
    SET @RecommendedTempDBFileCount = IIF(@NumCPUs <= 8, @NumCPUs, 8);

    -- MAXDOP Calculation
    IF @NumaNodes = 1
    BEGIN
        IF @NumCPUs < 8
            SET @RecommendedMaxDop = @NumCPUs;
        ELSE
            SET @RecommendedMaxDop = 8;
    END
    ELSE
    BEGIN
        DECLARE @LogicalCPUsPerNumaNode INT = @NumCPUs / @NumaNodes;
        
        IF @LogicalCPUsPerNumaNode <= 16
            SET @RecommendedMaxDop = @LogicalCPUsPerNumaNode;
        ELSE
            SET @RecommendedMaxDop = 16;
    END

    -- Define a table variable to store the results
    DECLARE @Results TABLE (Description NVARCHAR(MAX), Value NVARCHAR(MAX));

    -- Insert existing settings and recommendations into @Results
    INSERT INTO @Results (Description, Value)
    VALUES ('MAXDOP Configured Value', CAST(@MaxDop AS VARCHAR)),
        ('MAXDOP Recommended Value', CAST(@RecommendedMaxDop AS VARCHAR)),
        ('Cost Threshold Configured Value', CAST(@CostThreshold AS VARCHAR)),
        ('Generally Recommended Cost Threshold', '40-50'),
        ('TempDB File Count', CAST(@TempDBFileCount AS VARCHAR)),
        ('TempDB Recommended File Count', CAST(@RecommendedTempDBFileCount AS VARCHAR));

    -- Check and build ChangeScript for other settings
    IF @MaxDop <> @RecommendedMaxDop
        SET @ChangeScript += 'EXEC sp_configure ''max degree of parallelism'', ' + CAST(@RecommendedMaxDop AS VARCHAR) + '; RECONFIGURE WITH OVERRIDE; ';

    IF @CostThreshold < 40 OR @CostThreshold > 50
        SET @ChangeScript += 'EXEC sp_configure ''cost threshold for parallelism'', 45; RECONFIGURE WITH OVERRIDE; ';

    IF LEN(@ChangeScript) > 0 AND @ShowAdvancedOptions <> 1
        SET @ChangeScript = 'EXEC sp_configure ''show advanced options'', 1; RECONFIGURE WITH OVERRIDE; ' + @ChangeScript;

    -- Insert the "Change Script" row only if there are changes to be made
    IF LEN(@ChangeScript) > 0
        INSERT INTO @Results (Description, Value)
        VALUES ('Change Script', @ChangeScript);

    -- Display the results
    SELECT * FROM @Results;

'@

    [string[]]$Sqlservers = $SqlServerInstanceStr,$DWSqlServerInstanceStr | sort -uniq

    foreach($SqlserverInst in $Sqlservers){
        try{
            write-host "`n`nDOP/Tempdb Settings for: $SqlserverInst"
            invoke-SqlCmd -ServerInstance $SqlserverInst -Query $DOPscriptSql -trustServerCertificate | out-string
            
        }catch{write-error $_}
    }

}


if($Operation -contains 'SetDbsSqlMaintPlan'){

    #https://ola.hallengren.com/frequently-asked-questions.html
    
    $sqltoolsModule = get-Module SQLServer -ListAvailable
    if(!$sqltoolsModule ){ $sqltoolsModule = Install-Module SQLServer -Force -PassThru}
    if(!$sqltoolsModule){Write-Error "Unable to install needed module: SQLServer";pause;return}
    try{Import-Module SQLServer -ea 0}catch{continue} #supress scary dll conflicts

    write-host "[SetDbsSqlMaintPlan] starting operation"

    $TestMaintSql = @'
    DECLARE @VersionKeyword nvarchar(max)

    SET @VersionKeyword = '--// Version: '
    
    SELECT sys.schemas.[name] AS SchemaName,
           sys.objects.[name] AS ObjectName,
           CASE WHEN CHARINDEX(@VersionKeyword,OBJECT_DEFINITION(sys.objects.[object_id])) > 0 THEN SUBSTRING(OBJECT_DEFINITION(sys.objects.[object_id]),CHARINDEX(@VersionKeyword,OBJECT_DEFINITION(sys.objects.[object_id])) + LEN(@VersionKeyword) + 1, 19) END AS [Version],
           CAST(CHECKSUM(CAST(OBJECT_DEFINITION(sys.objects.[object_id]) AS nvarchar(max)) COLLATE SQL_Latin1_General_CP1_CI_AS) AS bigint) AS [Checksum]
    FROM sys.objects
    INNER JOIN sys.schemas ON sys.objects.[schema_id] = sys.schemas.[schema_id]
    WHERE sys.schemas.[name] = 'dbo'
    AND sys.objects.[name] IN('CommandExecute','DatabaseBackup','DatabaseIntegrityCheck','IndexOptimize')
    ORDER BY sys.schemas.[name] ASC, sys.objects.[name] ASC
'@

    $InstallmaintSqlFullname = "$currentDir\Extras\MaintenanceSolution.sql"
    if( !($InstallmaintSqlFullname) ){write-error "Couldn't find the MaintenanceSolution.sql at: $InstallmaintSqlFullname";break}
    $InstallmaintSql0 = gc -LiteralPath $InstallmaintSqlFullname 
    $InstallmaintSql = $InstallmaintSql0 -join "`n"

    [string[]]$Sqlservers = $SqlServerInstanceStr,$DWSqlServerInstanceStr | sort -uniq
    foreach($SqlserverInst in $Sqlservers){

        $isinstalled = invoke-SqlCmd -ServerInstance $SqlserverInst -Query $TestMaintSql -TrustServerCertificate
        if($isinstalled){write-host "SQL Maintenance Plan jobs are currently installed for: $SqlserverInst"}else{
            try{
                write-host "`n`nSetting up sqlmaintenance jobs for: $SqlserverInst"
                invoke-SqlCmd -ServerInstance $SqlserverInst -Query $InstallmaintSql -trustServerCertificate | out-string
            }catch{write-error $_}
        }
    }

    write-host "`n`nRemember: After initial Maintenance Plan installation, one must still go and schedule/configure the sqlagent jobs as needed.
    -By default, backups are removed every 96 hours (4 days), but change to suit your needs.
    
    Guidance per Kevin Holman: https://kevinholman.com/2017/08/03/what-sql-maintenance-should-i-perform-on-my-scom-2016-databases/
    '''
    Schedule the sqlagent jobs that don't conflict with the below times:

    Daily jobs that run for the OpsDB:
    12:00 AM - Partitioning and Grooming
    2:00 AM - Discovery Data Grooming
    2:30 AM - Optimize Indexes
    4:00 AM - Alert auto-resolution

    1.  Set up a nightly Re-Index job on your SCOM OperationsManager Database for best performance and to reduce significant wasted space on disk.
    2.  You can do the same for the DW, but be prepared to put in the work to analyze the benefits if you do.  Running a regular (multiple times a day) Update Statistics has also proven helpful to some customers.
    3.  Keep your DB recovery model in SIMPLE mode, unless you are using SQL AlwaysOn replication.
    4.  Ensure you pre-size your databases and logs so they are not always auto-growing, have plenty of free space as required to be supported.
    '''
    "
}


if($Operation -contains 'EnforceTls12'){

    # https://kevinholman.com/2018/05/06/implementing-tls-1-2-enforcement-with-scom/
    

    write-host "[EnforceTls12] starting operation"
    $tlsScript = "$currentDir\Extras\Invoke-EnforceSCOMTLS1.2.ps1"

    if( !($tlsScript) ){write-error "Couldn't find the tls12 script at: $tlsScript";break}

    $PrereqDir = New-Item -Path "$SCOMNasBackup\tls12PreReqs" -ItemType Directory -Force 
    if( !(test-path $PrereqDir) ){write-error "Couldn't find prereq dir at: $PrereqDir"; break } #technically we could change this to run, but why no NAS?

    write-host "tls12 script logs at: $env:PROGRAMDATA\SCOM_Enforce_TLS_1.2*.log"

    $scriptArgs = @{
        'AssumeYes' = $true;                     # The script will not ask any questions. Good for unattended runs
        'DirectoryForPrerequisites' =$PrereqDir.fullname; # The directory to save / load the prerequisites from. Default is the current directory
        'ForceDownloadPrerequisites' = $false;   # Force download the prerequisites to the directory specified in DirectoryForPrerequisites    
        'SkipDotNetCheck' = $false;              # Skip the .NET Check step.   
        'SkipDownloadPrerequisites' = $false;    # Skip downloading the prerequisite files to current directory.    
        'SkipModifyRegistry' = $false            # Skip any registry modifications (the actuall enforcement of tls12 only)
        'SkipRoleCheck' = $false;                # Skip the SCOM Role Check step (are we gateway, webconsole etc)    
        'SkipSQLQueries' = $false;               # Skip any check for SQL version compatibility    
        'SkipSQLSoftwarePrerequisites' = $false; # Skip the ODBC, MSOLEDBSQL, and/or Microsoft SQL Server 2012 Native Client.
        'SkipVersionCheck' = $false;             # Skip SCOM Version Check step.
        'SkipAutoReboot' = $true;             # Skip SCOM Version Check step.
    }
    & $tlsScript @scriptArgs

    #dir "$env:PROGRAMDATA\SCOM_Enforce_TLS_1.2*.log" | sort LastWriteTime | select -Last 1 | %{cat $_ -Last 100}
    #write-host "Dumped last 100 lines of log --^"
}


if($Operation -contains 'IncreaseConfigServiceTimeout'){

    write-error "not implemented";break

	#configservice timeout change
	#https://blogs.technet.microsoft.com/momteam/2013/01/29/support-tip-config-service-deltasynchronization-process-fails-with-timeout-exception/
	$sb = {
		#configservice timeout change
		#https://blogs.technet.microsoft.com/momteam/2013/01/29/support-tip-config-service-deltasynchronization-process-fails-with-timeout-exception/
		#http://vetasen.no/2015/12/22/scom-deltasynchronization-error/
		$force = $true
		$filepath = "C:\Program Files\Microsoft System Center 2016\Operations Manager\Server\ConfigService.config"
		if( (!(test-path "$($filepath).orig") -or $force) -and (test-path $filepath) ){

			cp $filepath "$($filepath).orig"
			[xml]$config = gc $filepath
			if(!$config){

				write-error "Unable to obtain xml file at $filepath"
			}else{
				$rootTimeout=$config.SelectNodes("//Config/Component/Instance/Category[@Name='Cmdb']/Setting/OperationTimeout")
				$rootTimeout[0].DefaultTimeoutSeconds="300"
				$rootTimeout2=$rootTimeout[0].SelectNodes("./Operation[@Name='GetEntityChangeDeltaList']")
				$rootTimeout2[0].TimeoutSeconds="300"
				
				$rootTimeout3 = $config.SelectNodes("//Config/Component/Instance/Category[@Name='ConfigStore']/Setting[@Name='OperationTimeout']/OperationTimeout")
				$rootTimeout3[0].DefaultTimeoutSeconds="300"
				
				$config.CreateNavigator().outerxml > $filepath
			}
		}else{

			write-error "Verify that $filepath exists, and that we don't have saved settings in the file $($filepath.orig)"
		}
	}
}


if($Operation -contains 'IncreaseHealthServiceRestartTimeouts'){

    write-error "not implemented";break

    <#
	#Verified settings at: https://blogs.technet.microsoft.com/kevinholman/2017/05/29/stop-healthservice-restarts-in-scom-2016/
    Private bytes monitors should be set to a default threshold of
    943718400 (triple the default of 300MB) -> Yes.  6294967296 6GB for MS Agent 

    Handle Count monitors should be set to 
    30000  (the default of 6000 is WAY low)  -> Yes. 60,000 for ms agent
    #>
}


if($Operation -contains 'SetWebBindingSSL'){
 

    write-host "[SetWebBindingSSL] starting operation"

    $module = Import-Module WebAdministration -UseWindowsPowerShell -PassThru
    if(!$module){write-error "Unable to import module: WebAdministration"; break}
    $sess = get-PSSession -Name WinPSCompatSession

    $websiteName = "Default Web Site"
    try{
        New-WebBinding -Name $websiteName -IP "*" -Port 443 -Protocol https

        #CD IIS:\SslBindings
        $binding = Get-WebBinding -Name $websiteName -Protocol "https"
        if(!$binding){write-error "Something went wrong creating 443/ssl binding on website: $websiteName"}

        write-host "Added ssl binding"
    }catch{write-error $_;break}

    try{
        write-host "Applying a cert for SSL binding..."
        $cert = dir Cert:\LocalMachine\My\ |?{$_.Subject -like "*CN=*$env:COMPUTERNAME*"} | select -first 1
        if(!$cert){
            
            write-warning "Unable to find self-signed cert for SSL Binding. Generating a self-signed cert instead. To manually update this, create/set a cert in inetmgr > Default WebSite > edit Bindings > 443 > certDropdown"
            $cert = New-SelfSignedCertificate -DnsName "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)" -CertStoreLocation cert:\LocalMachine\My
        }


        Invoke-Command -session $sess -ScriptBlock {
            
            try{
                $binding = Get-WebBinding -Name $using:websiteName -Protocol "https"
                $cert = dir Cert:\LocalMachine\My\ |?{$_.Subject -like "*CN=*$env:COMPUTERNAME*"} | select -first 1

                $binding.AddSslCertificate($cert.GetCertHashString(), "my")
            }catch{write-error $_}
        }
        
    }catch{write-error $_; break}

    write-host "[SetWebBindingSSL] Finished Operation"

}



#page file to be 1.5 times ram size on sql servers
#run webrecorder reg fixes via: https://social.technet.microsoft.com/Forums/office/en-US/9c07b863-4777-4911-bedd-0691a61b6258/web-recorder-grayed-out?forum=operationsmanagerauthoring


#endregion

Stop-Transcript