#Requires -Version 7 -RunAsAdministrator
<#
.SYNOPSIS
    # Installs a sql server for use by scom on a server.

.DESCRIPTION

    $Roles:
        OMServer - Install SCOM Management Server
        OMConsole - Install SCOM fat client console
        OMReporting - install the SCOM Report server role (Done BEFORE webconsole, and typically on SQL DWH)
        OMWebConsole - install a web console (sets up IIS if it is missing)

        InstallStandAloneCA - Sets up a standalone certificate authority (along with web enrollment) for use in SCOM gateways (Hint: Use the flags -skipTailFinalInstallLog and -skipScomFolderExtract for readability)
        1OMGatewayApprove - Run on a Management Server to allow Gateway server to install.
        2OMGateway - Installs Gateway binaries on this server. (Hint: Use the flags -skipTailFinalInstallLog and -skipScomFolderExtract for readability)
        3GetGatewayServerCerts - Run on a Certificate Authority server. This will generate certificates for Scom gateways servernames, and save them to the SCOM nas backup path. (Hint: Use the flags -skipTailFinalInstallLog and -skipScomFolderExtract for readability. pfxPassword=password)
        4ImportGatewayServerCerts - Run on Gateways, and their upstream Management servers. (Hint: Use the flags -skipTailFinalInstallLog and -skipScomFolderExtract for readability)

        OMGatewayRemove - Removes Gateways from approval set in the config file (Hint: Use the flags -skipTailFinalInstallLog and -skipScomFolderExtract for readability. pfxPassword=password)

        ApplyLicense - will attempt to license SCOM if possible
        AddCustomReportExtensions - Fixes a bug that prevents SCOM from adding all SSRS reports        
.NOTES

.LINK
    https://learn.microsoft.com/en-us/system-center/scom/install-using-cmdline

#>
param(
    # Service name. Mandatory, by default MSSQLSERVER
    [ValidateSet('OMServer','OMConsole','OMReporting','OMWebConsole','ApplyLicense','AddCustomReportExtensions','InstallStandAloneCA','1OMGatewayApprove','2OMGateway','OMGatewayRemove','3GetGatewayServerCerts','4ImportGatewayServerCerts')]
    [string[]]$Roles,

    [string]$configFilePath = "$PSScriptRoot\_config.ps1",

    [switch]$skipTailFinalInstallLog, #shows the last lines of the setup log post-operation(s)
    
    [switch]$skipScomFolderExtract # Skips extracting SCOM.exe for certain situations where shared NAS is unavailable (like remote gateway installations)
)


###########################
#region: Functions

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

Function priv_quickInstalledProductsDump {

    $Installer = New-Object -ComObject WindowsInstaller.Installer
    $InstallerProducts = $Installer.ProductsEx("", "", 7)
    $InstalledProducts = ForEach ($Product in $InstallerProducts) {
        [PSCustomObject]@{
            ProductCode = $Product.ProductCode()
            LocalPackage = $Product.InstallProperty("LocalPackage")
            VersionString = $Product.InstallProperty("VersionString")
            ProductPath = $Product.InstallProperty("ProductName")
        }
    }
    $InstalledProducts
    

}

#endregion: Functions
###########################


#region: INIT

    $nullme = new-item -Path "$PSScriptRoot\Logs" -ItemType Directory 
    Start-Transcript -Path ("$PSScriptRoot\Logs\$($script:MyInvocation.MyCommand.name).{0:MM-dd-yyyy_hh.mm.ss.mm}.log" -f (get-date))

    if($skipTailFinalInstallLog -ne $true){
        write-host 'INFO: SCOM setup Log can be found at: get-content -wait $env:LOCALAPPDATA\SCOM\LOGS\OpsMgrSetupWizard.log'
    }
    
    #$domainJoinCred = New-Object System.Management.Automation.PsCredential($domainUser,$secstring)
    if( !(Test-Path $configFilePath) ){write-error "Unable to find config file: $configFilePath"; return;}
    . $configFilePath
    
    if(!$skipScomFolderExtract){
        $scomSetupEXEFullname = priv_expandSCOMsetup
        if(!$scomSetupEXEFullname){return}
    }
#endregion


#Main
if($Roles -contains 'OMConsole'){

    #install old prereqs if SCOM version is less than SCOM2022
    $scomSetupExe = get-item "$SCOMSetupLocalFolder\setup.exe"
    if($scomSetupExe -and [version]$scomSetupExe.VersionInfo.FileVersion -lt "10.22.0.0"){ #scom 2022 does not seem to require these any longer

        $installedProducts = priv_quickInstalledProductsDump
        $clrIsInstalled = $installedprocuts.ProductPath -match "^Microsoft System CLR Types for SQL Server" 
        $reportViewInstalled = $installedprocuts.ProductPath -match "^Microsoft Report Viewer"

        if($clrIsInstalled -and $reportViewInstalled){
            write-host "Both Report viewer and Sql CLRtypes prereqs are installed already"
        }else{


            if(!$SCOMEXELocation){
                $scomExeSourceDir = "$env:tmp"
            }else{
                $scomExeSourceDir = split-path -parent $SCOMEXELocation
            }           

            if($SCOMEXELocation -and !(test-path "$scomExeSourceDir\prereq*")){
                
                write-host "Creating and downloading prereqs for SCOM console"
                
                $nullme = new-item "$scomExeSourceDir\prereq" -ItemType Directory -Force
                
                Invoke-WebRequest https://download.microsoft.com/download/6/7/8/67858AF1-B1B3-48B1-87C4-4483503E71DC/ENU/x64/SQLSysClrTypes.msi -OutFile "$scomExeSourceDir\prereq\001_SQLSysClrTypes.msi"            
                Invoke-WebRequest http://download.microsoft.com/download/A/1/2/A129F694-233C-4C7C-860F-F73139CF2E01/ENU/x86/ReportViewer.msi -OutFile "$scomExeSourceDir\prereq\002_ReportViewer.msi"            
            }  
            $filesToInstall = dir "$scomExeSourceDir\prereq*\*.msi"

            Write-Host "Installing Prerequsites"
            foreach($msifile in $filesToInstall){
                #Start-Process  "$scomExeSourceDir\prereq\SQLSysClrTypes.msi" /qn -Wait
                #Start-Process  "$scomExeSourceDir\prereq\ReportViewer.msi" /quiet -Wait

                Start-Process $msifile.FullName "/quiet /qn" -Wait
            }
        }
    }
    


	write-host "Setting up SCOM Fat Console + Powershell Cmdlets"
	
    $ArgumentList = @(
		"/silent /install /InstallPath:$SCOM_InstallPath /components:OMConsole /EnableErrorReporting:Always /SendCEIPReports:1 /UseMicrosoftUpdate:0 /AcceptEndUserLicenseAgreement:1"
	)
    $res1 = Start-Process -FilePath "$SCOMSetupLocalFolder\Setup.exe" -ArgumentList $ArgumentList -Wait
}


if($Roles -contains "OMWebConsole"){
    #region Install Web Console prerequisites
    try{
        write-host "Setting up SCOM webconsole prereqs"
        
        #todo: may need some massaging if 2016 vs 2019 etc
        $featurenames = 'Web-Server,NET-WCF-HTTP-Activation45,Web-Static-Content,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Http-Logging,Web-Request-Monitor,Web-Filtering,Web-Stat-Compression,Web-Mgmt-Console,Web-Metabase,Web-Asp,Web-Asp-Net45,Web-Asp-Net,Web-Windows-Auth' -split ','
        $res1 = Install-WindowsFeature -name $featurenames -IncludeManagementTools -Restart #-Source "C:\Sources\Sxs"

        if($res1.ExitCode -ne "NoChangeNeeded"){write-host "Server must be restarted after prereqs are installed. Press Ctrl+C to exit or wait 60secs for server to reboot";sleep -Seconds 60;Restart-Computer -Force;return;exit;}

        #Import-Module -Name WebAdministration

        #$nullme = New-NetFirewallRule -Name "IIS 80" -DisplayName "IIS 80" -Profile Domain -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow -ea 0
        #$nullme = New-NetFirewallRule -Name "IIS 443" -DisplayName "IIS 443" -Profile Domain -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow -ea 0

        Write-Host "The Web Console prerequisites have been installed. " 
    }catch{write-error $_}

    try{
        write-host "Setting up SCOM webconsole..."
        $res1 = Start-Process "$SCOMSetupLocalFolder\Setup.exe" '/silent /install /components:OMWebConsole /WebSiteName:"Default Web Site" /WebConsoleAuthorizationMode:Mixed /SendCEIPReports:1 /UseMicrosoftUpdate:0 /AcceptEndUserLicenseAgreement:1' -Wait
    }catch{write-error $_}
}


if($Roles -contains 'OMReporting'){


    write-host "Setting up SCOM Reporting"

	$ArgumentList = @(
    "/silent /install /InstallPath:$SCOM_InstallPath /components:OMReporting /ManagementServer:$ScomReportingMS /SRSInstance:$SqlServerReportInstance\SSRS",
    "/DataReaderUser:$NetBiosDomainName\$SCOMDataWareHouseReader /DataReaderPassword:$SCOMDataWareHouseReaderPass",
    "/SendODRReports:1 /UseMicrosoftUpdate:0 /AcceptEndUserLicenseAgreement:1"
    )
    
    Start-Process -FilePath "$SCOMSetupLocalFolder\Setup.exe" -ArgumentList $ArgumentList -Wait
}


if($Roles -contains 'OMServer'){

	write-host "Setting up SCOM Management Server"

    #this helps solve an issue where "local users".msc incorrectly displays an old DAS user name as valid.
    try{priv_RemoveDomainUsertoGroup -domain $NetBiosDomainName -username $SCOMDataAccessAccount -groupname "Administrators" -computer "localhost"}catch{} #swallow error
    try{priv_AddDomainUsertoGroup -domain $NetBiosDomainName -username $SCOMDataAccessAccount -groupname "Administrators" -computer "localhost"}catch{} #swallow error


    $opsDBObj = priv_getSQLConnStr -targetComputer $SqlServerInstance
    $SqlServerInstanceStr = $opsDBObj.connStr

    $opsDWHObj =priv_getSQLConnStr -targetComputer $DWSqlServerInstance
    $DWSqlServerInstanceStr = $opsDWHObj.connStr

    $ArgumentList = @(
		"/silent /install /InstallPath:$SCOM_InstallPath /components:OMServer /ManagementGroupName:$SCOMMgmtGroup /SqlServerInstance:$SqlServerInstanceStr",
		"/DatabaseName:OperationsManager /DWSqlServerInstance:$DWSqlServerInstanceStr /DWDatabaseName:OperationsManagerDW /ActionAccountUser:$NetBiosDomainName\$SCOMServerAction",
		"/ActionAccountPassword:$SCOMServerActionPass /DASAccountUser:$NetBiosDomainName\$SCOMDataAccessAccount /DASAccountPassword:$SCOMDataAccessAccountPass /DataReaderUser:$NetBiosDomainName\$SCOMDataWareHouseReader",
		"/DataReaderPassword:$SCOMDataWareHouseReaderPass /DataWriterUser:$NetBiosDomainName\$SCOMDataWareHouseWriter /DataWriterPassword:$SCOMDataWareHouseWriterPass",
		'/EnableErrorReporting:Always /SendCEIPReports:1 /UseMicrosoftUpdate:0 /AcceptEndUserLicenseAgreement:1'
	)

    $res1 = Start-Process -FilePath "$SCOMSetupLocalFolder\Setup.exe" -ArgumentList $ArgumentList -Wait
}


if ($Roles -contains 'ApplyLicense'){

    if($SCOMProductKey -notmatch "^\w{5}-\w{5}-\w{5}-\w{5}-\w{5}$"){write-warning "No valid license key provided with: $SCOMProductKey"}else{    
        if( !(test-path "${env:ProgramFiles}\Microsoft System Center\Operations Manager\Powershell\OperationsManager") ){write-error "Unable to find SCOM module. Skipping Licensing."}else{

            Write-Host "Attempting to license SCOM..."
            #Importing the OperationsManager module by specifying the full folder path
            Import-Module "${env:ProgramFiles}\Microsoft System Center\Operations Manager\Powershell\OperationsManager"
            #Checking the SkuForLicense = Retail 

            try{
                $Cred = New-Object System.Management.Automation.PSCredential ($SCOMDataAccessAccount, (convertto-securestring $SCOMDataAccessAccountPass -asplaintext -force))
                $mg = Get-SCOMManagementGroup -Credential:$Cred -ManagementServer $RMSServer

                if($mg.SKUForLicense -ne 'Retail'){
                   
                    #To properly license SCOM, install the product key using the following cmdlet: 
                    Set-SCOMLicense -ProductId $SCOMProductKey -ManagementServer $RMSServer -Credential:$Cred -Confirm:$false
                    #(Re)Starting the 'System Center Data Access Service'is mandatory to take effect
                    #Restart-Service healthservice, omsdk, cshost -ErrorAction SilentlyContinue #-Force
                    Write-Warning "To apply the license, you must restart the following services on all managagement servers: healthservice, omsdk, cshost"
                }else{
                    write-host "Scom already licensed"
                }
            }catch{write-error $_}
        }
    }
}


if($Roles -contains 'AddCustomReportExtensions'){
	#import-module Microsoft.PowerShell.Management -UseWindowsPowerShell
	$sb = {
		$SqlServerReportInstance = '%SqlServerReportInstance%'

		$ServiceAddress = "http://$SqlServerReportInstance"

		$ExtensionAdd = @(
			'*'
			'CustomConfiguration'
			'Report'
			'AvailabilityMonitor'
			'TopNApplications'
			'Settings'
			'License'
			'ServiceLevelTrackingSummary'
			'CustomPerformance'
			'MostCommonEvents'
			'PerformanceTop'
			'Detail'
			'DatabaseSettings'
			'ServiceLevelObjectiveDetail'
			'PerformanceDetail'
			'ConfigurationChange'
			'TopNErrorGroupsGrowth'
			'AvailabilityTime'
			'rpdl'
			'mp'
			'TopNErrorGroups'
			'Downtime'
			'TopNApplicationsGrowth'
			'DisplayStrings'
			'Space'
			'Override'
			'Performance'
			'AlertDetail'
			'ManagementPackODR'
			'AlertsPerDay'
			'EventTemplate'
			'ManagementGroup'
			'Alert'
			'EventAnalysis'
			'MostCommonAlerts'
			'Availability'
			'AlertLoggingLatency'
			'PerformanceTopInstance'
			'rdl'
			'PerformanceBySystem'
			'InstallUpdateScript'
			'PerformanceByUtilization'
			'DropScript'
		)

		Write-Output 'Setting Allowed Resource Extensions for Upload'
		$error.clear()
		try
		{
			$Uri = [System.Uri]"$ServiceAddress/ReportServer/ReportService2010.asmx"
			$Proxy = New-WebServiceProxy -Uri $Uri -UseDefaultCredential
			$Type = $Proxy.GetType().Namespace + '.Property'
			
			$Property = New-Object -TypeName $Type
			$Property.Name = 'AllowedResourceExtensionsForUpload'

		$ValueAdd = $ExtensionAdd | ForEach-Object -Process {
				"*.$psItem"
			}

		$Current = $Proxy.GetSystemProperties($Property)
			if ($Current)
			{
			$ValueCurrent = $Current.Value -split ','
			$ValueSet = $ValueCurrent + $ValueAdd | Sort-Object -Unique
			}
			else
			{
				$ValueSet = $ValueAdd | Sort-Object -Unique
			}

		$Property.Value = $ValueSet -join ','
			
			$Proxy.SetSystemProperties($Property)
			Write-Output '  Successfully set property to: *.*'
		}
		catch
		{
			Write-Warning "Failure occurred: $error"
		}
		Write-Output 'Script completed!'

		Invoke-Command -ComputerName $SqlServerReportInstance -ScriptBlock {Restart-Service SQLServerReportingServices }
	} -replace '%SqlServerReportInstance%',$SqlServerReportInstance
	
	powershell.exe -command $sb
}


if($Roles -contains 'InstallStandAloneCA'){

    write-host "[InstallStandAloneCA] starting operation"

    #https://learn.microsoft.com/en-us/system-center/scom/obtain-certificate-windows-server-and-operations-manager?view=sc-om-2019&tabs=Standal%2CEnter

    # Install the AD CS role (if not already installed)
    Add-WindowsFeature @('Adcs-Cert-Authority','Adcs-Enroll-Web-Svc','ADCS-Web-Enrollment') -IncludeManagementTools -Verbose
    
    # Install and configure the standalone root CA
    Install-AdcsCertificationAuthority -CAType StandaloneRootCa -force -Verbose

    Install-AdcsWebEnrollment -force -verbose

    #Install-AdcsEnrollmentWebService -force -verbose

}

if($Roles -contains '1OMGatewayApprove'){
    
    write-host "[1OMGatewayApprove] Starting operation.."

    if(!$SCOMupstreamGatewayMsFQDNs){write-error "At least one upstream Management Server must be specified at config var: `$SCOMupstreamGatewayMsFQDNs";break}
    if(!$SCOMGatewayFQDNs){write-error "At least one Gatewayserver must be specified at config var: `$SCOMGatewayFQDNs";break}

    if(!(Get-Service -name omsdk) ){Write-Error "Is this a SCOM Management Server? omSDK service not found.";break}
    

    $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
    if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCOM installed?";break;return;}else{
        # Get the installation path value
        $ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory
    }
    
    #ensure we have the GatewayApprovalTool.exe
    $gatewayApprovalToolFullname = "$ScomInstallPath\Microsoft.EnterpriseManagement.GatewayApprovalTool.exe"
    if( !( test-path $gatewayApprovalToolFullname) ){
        
        $gatewayApprovalToolSrc = "$SCOMSetupLocalFolder\SupportTools\AMD64\Microsoft.EnterpriseManagement.GatewayApprovalTool.exe"
        if( !(test-path $gatewayApprovalToolSrc) ){write-error "Could not find gatewayApprovalTool source at: $gatewayApprovalToolSrc";break}

        try{
            write-host "Copying GatewayApprovalTool.exe to install path ..."
            Copy-Item -LiteralPath $gatewayApprovalToolSrc -Destination $ScomInstallPath -force -Verbose
            Copy-Item -LiteralPath "$($gatewayApprovalToolSrc).config" -Destination $ScomInstallPath -force -Verbose

        }catch{
            write-error $_
            break
        }        
    }

    
    
    <#
      
    certutil -importpfx certificate.pfx
    Microsoft.EnterpriseManagement.GatewayApprovalTool  /ManagementServerInitiatesConnection=True /managementServerName=MS-FQN /GatewayName=GW-FQN /Action=Create
    msiexec.exe /i MOMGateway.msi
    momcertimport64.exe
    #>

    $i = 0
    $MScount = $SCOMupstreamGatewayMsFQDNs.count - 1
    foreach($SCOMGatewayFQDN in $SCOMGatewayFQDNS){

        if($MScount -gt $i){
            write-warning "Couldn't match an upstream Management Server based on count. For GW '$SCOMGatewayFQDN', we are defaulting to first stream MS: $($SCOMupstreamGatewayMsFQDNs[0])"
            $upstreamMS = $SCOMupstreamGatewayMsFQDNs[0]
        }else{
            $upstreamMS = $SCOMupstreamGatewayMsFQDNs[$i]
        }

        
        try{
            
            $argumentlist = "/ManagementServerName=$upstreamMS /GatewayName=$SCOMGatewayFQDN /ManagementServerInitiatesConnection=$ManagementServerInitiatesConnection /Action=Create"

            write-host "Running GatewayApprovalTool.exe with args: $argumentlist"
            Start-Process -FilePath $gatewayApprovalToolFullname -ArgumentList $ArgumentList -Wait -NoNewWindow

        }catch{
            write-error $_
            continue
        }
        $i++
    }

}

if($Roles -contains 'OMGatewayRemove'){
    
    write-host "[OMGatewayRemove] Starting operation.."

    if(!$SCOMupstreamGatewayMsFQDNs){write-error "At least one upstream Management Server must be specified at config var: `$SCOMupstreamGatewayMsFQDNs";break}
    if(!$SCOMGatewayFQDNs){write-error "At least one Gatewayserver must be specified at config var: `$SCOMGatewayFQDNs";break}

    if(!(Get-Service -name omsdk) ){Write-Error "Is this a SCOM Management Server? omSDK service not found.";break}
    

    $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
    if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCOM installed?";break;return;}else{
        # Get the installation path value
        $ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory
    }
    
    #ensure we have the GatewayApprovalTool.exe
    $gatewayApprovalToolFullname = "$ScomInstallPath\Microsoft.EnterpriseManagement.GatewayApprovalTool.exe"
    if( !( test-path $gatewayApprovalToolFullname) ){
        
        $gatewayApprovalToolSrc = "$SCOMSetupLocalFolder\SupportTools\AMD64\Microsoft.EnterpriseManagement.GatewayApprovalTool.exe"
        if( !(test-path $gatewayApprovalToolSrc) ){write-error "Could not find gatewayApprovalTool source at: $gatewayApprovalToolSrc";break}

        try{
            write-host "Copying GatewayApprovalTool.exe to install path ..."
            Copy-Item -LiteralPath $gatewayApprovalToolSrc -Destination $ScomInstallPath -force -Verbose
            Copy-Item -LiteralPath "$($gatewayApprovalToolSrc).config" -Destination $ScomInstallPath -force -Verbose

        }catch{
            write-error $_
            break
        }        
    }

    
    
    <#
      
    certutil -importpfx certificate.pfx
    Microsoft.EnterpriseManagement.GatewayApprovalTool  /ManagementServerInitiatesConnection=True /managementServerName=MS-FQN /GatewayName=GW-FQN /Action=Create
    msiexec.exe /i MOMGateway.msi
    momcertimport64.exe
    #>

    $i = 0
    $MScount = $SCOMupstreamGatewayMsFQDNs.count - 1
    foreach($SCOMGatewayFQDN in $SCOMGatewayFQDNS){

        if($MScount -gt $i){
            write-warning "Couldn't match an upstream Management Server based on count. For GW '$SCOMGatewayFQDN', we are defaulting to first stream MS: $($SCOMupstreamGatewayMsFQDNs[0])"
            $upstreamMS = $SCOMupstreamGatewayMsFQDNs[0]
        }else{
            $upstreamMS = $SCOMupstreamGatewayMsFQDNs[$i]
        }

        
        try{
            
            $argumentlist = "/ManagementServerName=$upstreamMS /GatewayName=$SCOMGatewayFQDN /ManagementServerInitiatesConnection=$ManagementServerInitiatesConnection /Action=Delete"

            write-host "Running GatewayApprovalTool.exe with args: $argumentlist"
            Start-Process -FilePath $gatewayApprovalToolFullname -ArgumentList $ArgumentList -Wait -NoNewWindow

        }catch{
            write-error $_
            continue
        }
        $i++
    }

}

if($Roles -contains '2OMGateway'){

    write-host "[2OMGateway] starting operation"

    if( Get-Service -name omsdk -ea 0 ){Write-Error "Is this a SCOM Management Server? Gateway can't be installed here.";break}

    $GatewayMsiFullname = "$SCOMSetupLocalFolder\gateway\AMD64\MOMGateway.msi"
    if( !(test-path $GatewayMsiFullname) ){write-error "Could not find Gateway.msi at: $GatewayMsiFullname";break}

    write-host "[2OMGateway]Setting up SCOM Gateway"

    $i_GW = 0
    foreach($SCOMGatewayFQDN in $SCOMGatewayFQDNs){
        
        # this is a bit hacky, but should work in most cases to determine correct "Connection-specific DNS Suffix" for the host.
        if($SCOMupstreamGatewayMsFQDN -eq "$env:COMPUTERNAME.$env:USERDNSDOMAIN" -or $SCOMGatewayFQDN -like "$env:COMPUTERNAME.*" -or $SCOMGatewayFQDN -eq $env:COMPUTERNAME){ 
            $GatewayFQDNPos = $SCOMGatewayFQDN
        }

        $i_GW++
    }

    if(!$GatewayFQDNPos){Write-Host "Couldn't find a Gateway server defined at `$SCOMGatewayFQDNs that matched this computer's name: $env:COMPUTERNAME.$env:USERDNSDOMAIN";break}

    $i = 0
    $MScount = $SCOMupstreamGatewayMsFQDNs.count - 1
    if($MScount -gt $i_GW){

        write-warning "Couldn't match an upstream Management Server based on count. For GW '$GatewayFQDNPos', we are defaulting to first stream MS: $($SCOMupstreamGatewayMsFQDNs[0])"
        $upstreamMS = $SCOMupstreamGatewayMsFQDNs[0]
    }else{
        $upstreamMS = $SCOMupstreamGatewayMsFQDNs[$i]
    }

    # I never could get full unattend to work with /qn.
    $ArgumentList = @"
    /i $GatewayMsiFullname
    /l*v $env:LocalAppData\SCOM\Logs\GatewayInstall.log
    ADDLOCAL=MOMGateway
    MANAGEMENT_GROUP="$SCOMMgmtGroup"
    IS_ROOT_HEALTH_SERVER=0
    MANAGEMENT_SERVER_AD="$upstreamMS"
    MANAGEMENT_SERVER_DNS="$upstreamMS"
    ACTIONS_USE_COMPUTER_ACCOUNT=1
    MANAGEMENT_SERVER_PORT=5723
    INSTALLDIR="C:\Program Files\System Center Operations Manager"
    AcceptEndUserLicenseAgreement=1
    
"@ -split "`n" | %{$_.trim()} | ?{$_}
    
    #NOTE: other docs seem to incorrectly show ROOT_MANAGEMENT_SERVER_DNS, ROOT_MANAGEMENT_SERVER_AD, ROOT_MANAGEMENT_SERVER_PORT as the named options and don't include the AcceptEndUserLicenseAgreement flag.
    #consider: INSTALLDIR="C:\Program Files\System Center Operations Manager", NOAPM=1


    write-host "Installing gateway.msi with cmdline: msiexec.exe $($ArgumentList -join ' ')"
    write-host "*Click through all prompts."
    
    Start-Process "msiexec.exe" -ArgumentList $ArgumentList -Wait -NoNewWindow # -verb RunAs #

    cat "$env:LocalAppData\SCOM\Logs\GatewayInstall.log" -last 100
    write-host "Dumped gateway setup log above --^"
  
}

if($Roles -contains '3GetGatewayServerCerts'){

    write-host "[3GetGatewayServerCerts] starting operation"

    #-------------------------

    if($CAConfigName){write-host "Using defined CA config string: $CAConfigName";$chosenCAStr = $CAConfigName}else{

        $CAinfoDump = iex "certutil.exe -dump"
        [string[]]$caConfigStrings0 = $CAinfoDump | ?{$_ -like "*Config: *"}
        [string[]]$caConfigStrings = $caConfigStrings0 | %{$_ -split '"' | select -Index 1}

        if($caConfigStrings.count -eq 0){write-error "Could not find CA info published in Active Directory. Is a windows CA installed on this domain? 3rd party CA?";break}
        if($caConfigStrings.count -eq 1){write-host "Defaulting to the only CA found: $caConfigStrings"; $chosenCAStr = $caConfigStrings[0]}else{
            
            $mainChoice = $null
            Do{
                
                $i=0
                foreach($caConfigString in $caConfigStrings){
                    write-host "Found more than one CA:"
                    write-host "[$i] - $caConfigString"
                    $i++
                }
                $loopChoice = Read-Host -Prompt "Enter a number to select which Certificate Authority we are requesting against"
                $loopAsInt =  $loopChoice -as [int]
                
                if( $loopAsInt -isnot [int] -or $loopChoice -gt $caConfigStrings.count ){$loopChoice = $null}else{
                    $mainChoice =  $loopChoice
                }

            }While(!$mainChoice)

            $chosenCAStr = $caConfigStrings[$mainChoice]
            write-host "Selecting config: $chosenCAStr"
        }
    }
    #---------------------

    $baseCertReqStr = @'
[NewRequest]
Subject="CN={0}"
Exportable = TRUE  ; Private key is exportable
HashAlgorithm = SHA256
KeyLength = 2048  ; (2048 or 4096 as per Organization security requirement.)
KeySpec = 1  ; Key Exchange – Required for encryption
KeyUsage = 0xf0  ; Digital Signature, Key Encipherment
MachineKeySet = TRUE
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0" ; Microsoft RSA SChannel Cryptographic Provider and Microsoft Enhanced Cryptographic Provider v1.0
ProviderType = 12
KeyAlgorithm = RSA

; Optionally include the Certificate Template for Enterprise CAs, remove the ; to uncomment
; [RequestAttributes]
; CertificateTemplate="SystemCenterOperationsManager"

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1  ; Server Authentication
OID = 1.3.6.1.5.5.7.3.2  ; Client Authentication
'@

    try{
        write-host "Exporting the CA Cert with command: certutil.exe -f -config $chosenCAStr -ca.cert $env:tmp\Root_CA.cer"
        start-process certutil.exe -ArgumentList "-f -config $chosenCAStr -ca.cert $env:tmp\Root_CA.cer" -NoNewWindow -Wait
        Copy-Item -LiteralPath "$env:tmp\Root_CA.cer" -Destination $SCOMNasBackup -force -Verbose

    }catch{write-error $_;break}
    
    

    #---------------------

    #https://vetasen.no/2015/10/06/request-template-certificates-using-certreq-and-powershell/
    #https://techcommunity.microsoft.com/t5/system-center-blog/obtaining-certificates-for-ops-mgr-via-command-line-or-script/ba-p/340422
    #https://blakedrumm.com/blog/request-offline-certificate-for-off-domain-server/
    #https://learn.microsoft.com/en-us/system-center/scom/obtain-certificate-windows-server-and-operations-manager?view=sc-om-2019&tabs=Enterp%2CEnter

    [string[]]$AllManagementServers = $null
    $SCOMGatewayFQDNs | %{$AllManagementServers += $_}
    $SCOMupstreamGatewayMsFQDNs | %{$AllManagementServers += $_}
    foreach($SCOMGatewayFQDN in $AllManagementServers){
        
        write-host "Requesting Cert for: $SCOMGatewayFQDN"
        
        $infReqPath = "$($env:tmp)\$($SCOMGatewayFQDN).certreq.inf"
        $CSRPath = "$($env:tmp)\$($SCOMGatewayFQDN).certreq.csr"

        $infReq = $baseCertReqStr -f $SCOMGatewayFQDN
        $infReq | out-file -LiteralPath $infReqPath -Verbose

        write-host "Creating Cert request with command: certreq -new -f -config $chosenCAStr $infReqPath $CSRPath"
        $ouput = start-process certreq.exe -ArgumentList "-new -f -config $chosenCAStr $infReqPath $CSRPath" -NoNewWindow -Wait

        $cmdstr = "certreq.exe -submit -f -config $chosenCAStr $CSRPath"
        write-host "Submitting the request to: $cmdstr"
        #start-process certreq.exe -ArgumentList "-submit -f -config $chosenCAStr $CSRPath" -NoNewWindow -Wait
        $requestRes = iex $cmdstr
        $requestID = ($requestRes | ?{$_ -like "RequestId: `"*"} | select -First 1) -split '"' | select -Index 1
        if(!$requestID){write-error "something went wrong determining request id for cert.";break}
        
        #$viewStr = "certutil -view -out `"Request ID, Request Submission Date, Request Common Name, Requester Name, Request Email Address, Request Distinguished Name, CertificateTemplate, Request Disposition`" -Restrict `"Request Disposition=9`" -config $chosenCAStr"

        $approveStr = "certutil.exe -config $chosenCAStr -resubmit $requestID"
        write-host "Attempting to approve request with command: $approveStr"
        $approvres = iex $approveStr
        $isIssued = $approvres -like "*Certificate issued*"
        if(!$isIssued){write-error "Certificate was not approved: $($approvres|out-string)";break}
                

        $cmdstr2 = "certreq -retrieve -f -config $chosenCAStr $requestID $($env:tmp)\$SCOMGatewayFQDN.cer"
        write-host "Attempting to download cert with command: $cmdstr2"
        $requestRes2 = iex $cmdstr2
        $isRetrieved = $requestRes2 -like "*Certificate retrieved(Issued)*"
        if(!$isRetrieved){write-error "Certificate was not retrieved: $($requestRes2|out-string)";break}

        $cmdstr3 = "certreq -accept $($env:tmp)\$SCOMGatewayFQDN.cer"
        write-host "Temporarily adding cert to local machine's certificate store with cmd: $cmdstr3"
        $addRes = iex $cmdstr3
        $isAdded = $addRes -like "*Installed Certificate:*"
        if(!$isAdded){write-error "Certificate could not be added cert to local machine's certificate store: $($addRes|out-string)";break}

        #Exporting certificate with Private Key
        $convertCmdstr = "certutil -exportpfx -p `"password`" my `"$SCOMGatewayFQDN`" `"$($env:temp)\$SCOMGatewayFQDN.pfx`" `"nochain`""
        write-host "exporting cert to pfx with private key: $convertCmdstr"
        $convertRes = iex $convertCmdstr

        Copy-Item -LiteralPath "$($env:temp)\$SCOMGatewayFQDN.pfx" -Destination $SCOMNasBackup -force -Verbose

        #-------------------------------

        write-host "Cleaning up temp files..."
        $importedThumbprint = ($addRes | ?{$_ -like "*Thumbprint: *"}) -split ":" | select -Last 1 | %{$_.trim()}
        $tempCertObj = dir Cert:\LocalMachine\ -Recurse | ?{$_.Thumbprint -eq $importedThumbprint}
        
        
        $tempCertObj | Remove-Item -Force -Verbose        
        if(test-path "$env:tmp\Root_CA.cer"){get-item "$env:tmp\Root_CA.cer" | Remove-Item -Force -Verbose}
        get-item "$($env:temp)\$SCOMGatewayFQDN.pfx" | Remove-Item -Force -Verbose
        get-item "$($env:tmp)\$SCOMGatewayFQDN.cer" | Remove-Item -Force -Verbose
        get-item "$($env:tmp)\$SCOMGatewayFQDN.rsp" | Remove-Item -Force -Verbose
        get-item $infReqPath | Remove-Item -Force -Verbose
        get-item $CSRPath | Remove-Item -Force -Verbose

        write-host "[3GetGatewayServerCerts] Operation finished. Files saved to: $SCOMNasBackup"
    }

}


if($Roles -contains '4ImportGatewayServerCerts'){


    #https://learn.microsoft.com/en-us/system-center/scom/deploy-install-gateway-server?view=sc-om-2019&tabs=install-using-the-gui#import-certificates-with-the-momcertimportexe-tool


    write-host "[4ImportGatewayServerCerts] starting operation"

    #Find out if this is a SCOM Management server or GW
    $SCOMRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
    $SCOMSvrRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Server Management Groups"
    $SCOMServer = Test-Path $SCOMSvrRegPath
    IF ($SCOMServer)
    {
        [string]$Product = (Get-ItemProperty $SCOMRegPath).Product
        IF ($Product -match "Gateway")
        {
            $Gateway = $true
            Write-host "Gateway Role Role has been detected"
        }
        ELSE
        {
            $ManagementServer = $true
            Write-host "Management Server Role has been detected"
        }
    }
    if(!$Gateway -and !$ManagementServer){write-error "This does not appear to be a SCOM MS or Gateway server, is SCOM installed?";break}


    $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
    if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCOM installed?";break;return;}else{
        # Get the installation path value
        $ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory | %{$_.trimend('\')}
    }
   
    #---------------------------------------

    $caCertPath = "$SCOMNasBackup\Root_CA.cer"
    $canGetCACert = test-path $caCertPath

    if(!$canGetCACert){
        
        $caCertPath2 = "c:\temp\Root_CA.cer"
        $canGetCACert2 = test-path $caCertPath2

        if(test-path $caCertPath2){write-host "Found copied Root CA cert at: $caCertPath";$useFallback = $true}
    }

    if($ManagementServer -and !$canGetCACert -and !$canGetCACert2){write-error "Did not find the expected CA cert. Has it been generated via operation '3GetGatewayServerCerts'? Expected Path at: $caCertPath";break}
    
    if($useFallback){
        $caCertPath = $caCertPath2        
        $canGetCACert = $true
    }

    if($gateway -and !$canGetCACert){

        write-host "Did not find the expected CA cert at: $caCertPath"
        write-host "As this is a Gateway and may be outside SCOM network, please first copy Root_CA.cer and relevant SCOM Gateway cert to 'c:\temp', and rerun this script."
        write-host "Alternatively, simply run this command manually after copying to c:\temp: Import-Certificate -FilePath c:\temp\Root_CA.cer -CertStoreLocation `"Cert:\LocalMachine\Root`" -Verbose"
        break
    }

    if($canGetCACert){
        
        $certObj = Get-PfxCertificate -FilePath $caCertPath
        $isalreadyImported = dir "Cert:\LocalMachine\Root" | ?{$_.Thumbprint -eq $certObj.Thumbprint}
        if($isalreadyImported){write-host "Cert was already found imported at Cert:\LocalMachine\Root with thumbprint: `n$($certObj | out-string)"}else{

            try{
            write-host "Trusting Root CA certificate..."
            Import-Certificate -FilePath $caCertPath -CertStoreLocation "Cert:\LocalMachine\Root" -Verbose
            }catch{write-error $_}
        }
        
    }else{write-error "Somthing has gone wrong with the script, please investigate";break}
    
    #-----------------------------------

    #ensure we have the momcertimport.exe tool
    $momcerttool = "$ScomInstallPath\MOMCertImport.exe"
    if( !( test-path $momcerttool) ){
        
        $certTool = "$SCOMSetupLocalFolder\SupportTools\AMD64\MOMCertImport.exe"
        if( !(test-path $certTool) ){write-error "Could not find MOMCertImport.exe at: $certTool";break}

        try{
            write-host "Copying MOMCertImport.exe to install path ..."
            Copy-Item -LiteralPath $certTool -Destination $ScomInstallPath -force -Verbose

        }catch{
            write-error $_
            break
        }
    }
    if( !( test-path $momcerttool) ){write-error "Could not find MOMCertImport.exe at: $momcerttool";break}

   #---------------------------------------------

    [string[]]$AllManagementServers = $null
    $SCOMGatewayFQDNs | %{$AllManagementServers += $_}
    $SCOMupstreamGatewayMsFQDNs | %{$AllManagementServers += $_}

    #determine the actual name of the certFile.pfx for this server.
    [string]$TargetedMSName = $null
    foreach($MSName in $AllManagementServers){
        
        # this is a bit hacky, but should work in most cases to determine correct "Connection-specific DNS Suffix" for the host.
        if($MSName -like "$env:COMPUTERNAME.*" -or $MSName -eq "$env:COMPUTERNAME"){ 
            $TargetedMSName = $MSName
        }
    }    
    if(!$TargetedMSName){Write-Host "Does this server need a certificate? Couldn't find a Gateway server defined at `$SCOMGatewayFQDNs or `$SCOMupstreamGatewayMsFQDNs that matched this computer's name: $env:COMPUTERNAME.$env:USERDNSDOMAIN";break}
    
    $GatewayFQDNPos = $TargetedMSName


    write-host "Working to find/import cert for Gateway/MS: $GatewayFQDNPos"
    $GWCertPath = "$SCOMNasBackup\$GatewayFQDNPos.pfx"
    $canGetGWCert = test-path $GWCertPath

    if(!$canGetGWCert){
        
        $GWCertPath2 = "c:\temp\$GatewayFQDNPos.pfx"
        $canGetGWCert2 = test-path $caCertPath2

        if($canGetGWCert2){write-host "Found copied Gateway cert at: $GWCertPath2";$useFallbackGW = $true}
    }

    if($useFallbackGW){
        $GWCertPath = $GWCertPath2        
        $canGetGWCert = $true
    }

    
    if($gateway -and !$canGetGWCert){
        
        $certimportCmdStr2 = "`"$momcerttool`" `"c:\temp\$GatewayFQDNPos.pfx`" /Password `"password`""
        write-host "Did not find the expected Gateway cert at: $GWCertPath"
        write-host "As this is a Gateway and may be outside SCOM network, please first copy Root_CA.cer and relevant SCOM Gateway cert '$GatewayFQDNPos.pfx' to 'c:\temp', and rerun this script."
        write-host "Alternatively, simply run this command manually after copying to c:\temp: $certimportCmdStr2"
        break
    
    }
    
    
    #$tmpCert = Copy-Item -LiteralPath $GWCertPath -Destination $env:tmp -Force -Verbose
    $certimportCmdStr = "`"$momcerttool`" `"$GWCertPath`" /Password `"password`""
    write-host "importing Scom cert with cmd: $certimportCmdStr"
                
    #$certImportRes = iex $certimportCmdStr
    $certImportRes = Start-Process -FilePath $momcerttool -ArgumentList "`"$GWCertPath`" /Password `"password`"" -NoNewWindow -Wait -PassThru
    if($certImportRes.ExitCode -ne 0){write-error "Last Exit code indicated an error importing cert, please review logs and retry";break}else{
        write-host "restarting healthservice to apply change.."
        Restart-Service -Name HealthService -force -Verbose
    }

    write-host "[4ImportGatewayServerCerts] operation finished."
}


#endregion MAIN 


#region: end

if($skipTailFinalInstallLog -ne $true){
    cat "$env:LOCALAPPDATA\SCOM\LOGS\OpsMgrSetupWizard.log" -Last 100
    write-host "`n`n==========`n`nScript Finished. Last 100 lines of the log above --^"
}

Stop-Transcript
#endregion
