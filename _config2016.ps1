#config file global vars for subsequent scripts (tested with 2016/2019)
# These variable names should be considered 'reserved' names that subsequent scripts must not use.

##############################################
###### Active Directory / Accounts ###########
##############################################
$NetBiosDomainName = 'riddlelab' #NetBios Domain Name 
$FQDNDomainName = 'riddlelab.local' #FQDN Domain Name 
$domainUser = 'Administrator' # Domain Username that can join domain 
$domainPass = 'P4ssw0rd01'  # Domain Username's pass that can join domain
$OUName = 'SCOM Service Accounts 2016' #OU name for placing accounts and groups

#SCOM Accounts
$SCOMDataAccessAccount = 'OMDAS2016' # 
$SCOMDataAccessAccountPass = 'P@ssw0rd01!12016'
$SCOMDataWareHouseWriter = 'OMWrite2016' # 
$SCOMDataWareHouseWriterPass = 'P@ssw0rd01!22016' # 
$SCOMDataWareHouseReader = 'OMRead2016' # 
$SCOMDataWareHouseReaderPass = 'P@ssw0rd01!32016'
$SCOMServerAction = 'OMAA2016' # Action Account 
$SCOMServerActionPass = 'P@ssw0rd01!42016'

$SCOMAdmins = 'OMAdmins2016' # AD Group for SCOM Accounts 
$SCOMMgmtGroup = 'SCOM-2016-MG1' # SCOM management group name 

#SQL Accounts
$SQLUser = 'SQLUser2016' # User Name with admin rights on SQL Server (SQLUser,for example) 
$SQLUserPass = 'P@ssw0rd01!52016'

#UNIX Creds
$linuxPrivMaintUser = "scompriv" #maintenance / high priv user account
$linuxPrivMaintPass = "t0ps3cr3t"
$linuxAAUser = "scomuser"    # lowpriv monitoring Account
$linuxAAPass = "P4ssw0rd01"

$linuxDeployUser = 'tom'        #a pre-existing user that has root access
$linuxDeployPass = 'P4ssw0rd01'

$DefaulLinuxPoolName = "Linux Pool 01" #where linux agents are observed from
#############################################b


##############################################
######### ISO Names / Executables ############
##############################################
$SQLServerISO = '\\rectifier\datashare2\Apps\SQL Server\SQL2016\CustomSqlServer2016.iso' #Location of the SQL Server 2019 ISO (https://go.microsoft.com/fwlink/?linkid=866664) 
$SsrsExeLocation = '\\rectifier\datashare2\Apps\SQL Server\SQL2016\SQLServerReportingServices2016.exe'
$SCOMEXELocation = '' # Optional: Location of the SCOM monolithic Executable (https://www.microsoft.com/en-US/evalcenter/evaluate-system-center-2019) 
$SSMSexeDir = "\\rectifier\datashare2\Apps\SQL Server\SQL2016" #directory that contains SSMS-Setup-ENU.exe
$SCOMSetupLocalFolder = '\\rectifier\datashare2\Apps\SystemCenter\SC2016VHDSCOM\Runonce\SCOM' # Location containing expanded scom install files with setup.exe (extracted from $SCOMEXELocation) 

$SCOMNasBackup = '\\rectifier\datashare2\Apps\SystemCenter\_recovery' #location for cert/keys storage/retrieval
##############################################


##############################################
######### Additional Options #################
##############################################
$SCOM_InstallPath = "$env:ProgramFiles\Microsoft System Center\Operations Manager" # optional: Specifies a nondefault Destination Dir of SCOM install

$SQLInstanceName = 'MSSQLSERVER' # Name of the SQL instance installed 
$sqlserverport = '1433' #currently only opens a firewall port, no post-config (todo)
$SQL_INSTANCEDIR = "$Env:ProgramFiles\Microsoft SQL Server\130" #optional: Specifies a nondefault installation directory for instance-specific components like a copy of the sqlserver.exe engine. For all instances of SQL Server (both default and named), common files shared between all instances live here ending in version nnn. The usual Sql Server directory nnn values: 160,150,140,130,120,110

$SQL_INSTALLSQLDATADIR = "$Env:ProgramFiles\Microsoft SQL Server" #optional: "/INSTALLSQLDATADIR affects the default values of /SQLBACKUPDIR, /SQLTEMPDBDIR, /SQLTEMPDBLOGDIR, /SQLUSERDBDIR and /SQLUSERDBLOGDIR"
$SQL_SQLUSERDBDIR = "$SQL_INSTALLSQLDATADIR\$SQLInstanceName\MSSQL\Data"   #Optional: Specifies the directory for the data files for user databases. 
$SQL_SQLUSERDBLOGDIR = '' #It is a best practice to Place data and log files on separate drives. https://learn.microsoft.com/en-us/sql/relational-databases/policy-based-management/place-data-and-log-files-on-separate-drives?view=sql-server-ver16

$SQL_SQLTEMPDBDIR = '' # Best practices are to put the tempdb database on a fast I/O subsystem, on other disks than user dbs use. #https://learn.microsoft.com/en-us/sql/relational-databases/databases/tempdb-database?view=sql-server-ver16#optimizing-tempdb-performance-in-sql-server
$SQL_SQLTEMPDBLOGDIR = '' #It’s acceptable to keep tempdb log files on the same disk as user database logs.

$SQL_SQLBACKUPDIR = '' #  It's recommended that a backup disk be a different disk than the userDb and log disks. This is necessary to make sure that you can access the backups if the data or log disk fails. https://learn.microsoft.com/en-us/sql/relational-databases/backup-restore/backup-devices-sql-server?view=sql-server-ver16#DiskBackups


#$SSRS_InstallDir = "$env:ProgramFiles\Microsoft SQL Server Reporting Services" broken in 2016
##############################################



##############################################
############### Product Keys #################
##############################################
#Currently written to only license DataCenter Evaluation version: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019
#Optional : Without a valid license key you will get a 180-day trial period.
$WindowsProductKey = '' #xxxx-xxxx-xxxx-xxxx-xxxx
$SCOMProductKey = '' #xxxx-xxxx-xxxx-xxxx-xxxx
$SQLProductKey = '' #xxxx-xxxx-xxxx-xxxx-xxxx
$SSRSProductKey = '' #xxxx-xxxx-xxxx-xxxx-xxxx
##############################################


##############################################
############### Server Names #################
##############################################
$DWSqlServerInstance = "scom2016ms1"
$SqlServerInstance = 'scom2016ms1'
$SqlServerReportInstance = 'scom2016ms1'
$ScomReportingMS = 'scom2016ms1'
$RMSServer = 'scom2016ms1'

[string[]]$SCOMGatewayFQDNS = '' #servers that need the SCOM gateway setup/approved on. NOTE: you can put just the computer name without FQDN if in a workgroup.


$initialSCOMDBSize = 10240 #the default scom db size is 1GB which runs out quick.
$initialSCOMDWHSize = 40240 #In MB. the default scom OpsDWH size is 1GB which runs out quick.

##############################################




##############################################
###############  Agents ###############
##############################################
$OldSCOMMgmtGroup = 'SCOM-2016-MG1' # OLD SCOM management group name That we can remove/add via Agents.ps1
$OldMSServer = 'scom2016ms1' # OLD Management Server 
[string[]]$WindowsAgentNames = 'WinServer2016-1.riddlelab.local' #These servernames are targeted via PSRemoting to have agent operations performed
[string[]]$linuxAgentNames = 'ubuntu16' #These servernames are targeted via SSH/SCOM to have agent operations performed




##############################################
############### Linux Config #################
##############################################


# Optional: These contents help the SCOM linux agent escalate privs to install/monitor processes
$LinuxSudoersHighSec = @"
# Sudoers file taken from 2022 overall example
# General requirements
# More info:  https://learn.microsoft.com/en-us/archive/technet-wiki/7375.scom-configuring-sudo-elevation-for-unix-and-linux-monitoring
# https://kevinholman.com/2022/12/12/monitoring-unix-linux-with-scom-2022/
#====================================================================
Defaults:$linuxAAUser  !requiretty
Defaults:$linuxPrivMaintUser !requiretty

#Agent maintenance
##Certificate signing
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c cp /tmp/scx-$linuxPrivMaintUser/scx.pem /etc/opt/microsoft/scx/ssl/scx.pem; rm -rf /tmp/scx-$linuxPrivMaintUser; /opt/microsoft/scx/bin/tools/scxadmin -restart
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c cat /etc/opt/microsoft/scx/ssl/scx.pem
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c if test -f /opt/microsoft/omsagent/bin/service_control; then cp /tmp/scx-$linuxPrivMaintUser/omsadmin.conf /etc/opt/microsoft/omsagent/scom/conf/omsadmin.conf; /opt/microsoft/omsagent/bin/service_control restart scom; fi
##Install or upgrade
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c sh /tmp/scx-$linuxPrivMaintUser/scx-1.[5-9].[0-9][0-9]-[0-9].universal[[\:alpha\:]].[[\:digit\:]].x[6-8][4-6].sh --install --enable-opsmgr; EC=$?; cd /tmp; rm -rf /tmp/scx-$linuxPrivMaintUser; exit $EC
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c sh /tmp/scx-$linuxPrivMaintUser/scx-1.[5-9].[0-9]-[0-9].universal[[\:alpha\:]].[[\:digit\:]].x[6-8][4-6].sh --install --enable-opsmgr; EC=$?; cd /tmp; rm -rf /tmp/scx-$linuxPrivMaintUser; exit $EC
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c sh /tmp/scx-$linuxPrivMaintUser/scx-1.[5-9].[0-9][0-9]-[0-9].universal[[\:alpha\:]].[[\:digit\:]].x[6-8][4-6].sh --upgrade --enable-opsmgr; EC=$?; cd /tmp; rm -rf /tmp/scx-$linuxPrivMaintUser; exit $EC
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c sh /tmp/scx-$linuxPrivMaintUser/scx-1.[5-9].[0-9]-[0-9].universal[[\:alpha\:]].[[\:digit\:]].x[6-8][4-6].sh --upgrade --enable-opsmgr; EC=$?; cd /tmp; rm -rf /tmp/scx-$linuxPrivMaintUser; exit $EC
##Uninstall
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c /opt/microsoft/scx/bin/uninstall
$linuxPrivMaintUser ALL=(root) NOPASSWD: /bin/sh -c if test -f /opt/microsoft/omsagent/bin/omsadmin.sh; then if test "`$(/opt/microsoft/omsagent/bin/omsadmin.sh -l | grep scom | wc -l)" \= "1" && test "`$(/opt/microsoft/omsagent/bin/omsadmin.sh -l | wc -l)" \= "1" || test "`$(/opt/microsoft/omsagent/bin/omsadmin.sh -l)" \= "No Workspace"; then /opt/microsoft/omsagent/bin/uninstall; else /opt/microsoft/omsagent/bin/omsadmin.sh -x scom; fi; else /opt/microsoft/scx/bin/uninstall; fi

##Log file monitoring
$linuxAAUser ALL=(root) NOPASSWD: /opt/microsoft/scx/bin/scxlogfilereader -p

###Examples
#Custom shell command monitoring example - replace <shell command> with the correct command string
#$linuxAAUser ALL=(root) NOPASSWD: /bin/sh -c echo error

##For ubuntu18
$linuxAAUser ALL=(root) NOPASSWD: /bin/bash -c echo error

#Daemon diagnostic and restart recovery tasks example (using cron)
$linuxAAUser ALL=(root) NOPASSWD: /bin/sh -c ps -ef | grep cron | grep -v grep
$linuxAAUser ALL=(root) NOPASSWD: /usr/sbin/cron & 

#End user configuration for SCOM agent
#====================================================================

"@

#below is a "wide-open" sudoers file that will always "just work"
$linuxSudoersAll = @"

# Add the following lines to grant the necessary permissions to the SCOM accounts
$linuxAAUser ALL=(ALL) NOPASSWD: ALL
$linuxPrivMaintUser ALL=(ALL) NOPASSWD: ALL

# It's important to ensure that 'requiretty' is disabled for the SCOM accounts
Defaults:$linuxAAUser  !requiretty
Defaults:$linuxPrivMaintUser !requiretty

"@

$LinuxSudoers = $linuxSudoersAll #assigns the actual sudoers we want

$timezone1 = 'Coordinated Universal Time' #what timezone the MS servers run.


$CAConfigName = 'SCOMMS2.riddlelab.local\riddlelab-SCOMMS2-CA' # Optional unless using Gateway servers. Find by running 'certutil' and chosing a 'config' field. This is the config string to connect to a certificate authority. 


#---------------------------------
#Shared global functions etc.

Function priv_getSQLConnStr {
    #will determine whether we are on dwh or opsDb and give the proper string for SQL connections
    param(
        $targetComputer = $env:COMPUTERNAME
    )

    $DWHconfigShortName = $DWSqlServerInstance -split "\." | select -first 1
    $OpsDBconfigShortName = $SqlServerInstance -split "\." | select -first 1

    #determine if we are running on dwh or opsdb server, then use appropriate port
    if($targetComputer -like "$DWHconfigShortName*"){
            
        $portToUse = $sqlserverportDWH
        $instanceNametoUse = $SQLInstanceNameDWH
        $serverNameToUse = $DWSqlServerInstance

    }elseif($targetComputer -like "$OpsDBconfigShortName*"){
        $portToUse = $sqlserverport
        $instanceNametoUse = $SQLInstanceName
        $serverNameToUse = $SqlServerInstance
    }else{
        write-host "Target computer provided is not a sql server: $targetComputer"
        return $null
    }
    
    #finally, build up the string, stripping defaults if needed.
    $FinstanceNametoUse = if($instanceNametoUse -eq 'MSSQLSERVER'){''}else{"\$instanceNametoUse"}
    $fportToUse = if($portToUse -eq 1433){''}else{",$portToUse"}
    $connStr = "$($serverNameToUse)$($FinstanceNametoUse)$($fportToUse)"
    
    $connobj = [pscustomobject]@{
        'portToUse' = $portToUse;
        'instanceNametoUse' = $instanceNametoUse;
        'serverNameToUse' = $serverNameToUse;
        'connStr' = $connStr;
    }

    return $connobj
}