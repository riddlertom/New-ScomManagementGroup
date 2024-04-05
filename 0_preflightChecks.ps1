#Requires -Version 7 -RunAsAdministrator
<#
.SYNOPSIS
    #Contains some basic checks and prerequsite operations before install sql/scom on a server.

.DESCRIPTION

    OPERATIONS:
        JoinDomain - joins this computer to the specified domain and reboots if needed
        AddScomAdObjs - adds SQL and SCOM service accounts, added to a new domainGroup, organized in AD under a new OU
        GetLatestDotnetFramework - download and installs the latest offline installer of dotnetframework.
        UnblockFileWarnings - Adds the NAS server locations to the machine's trusted sites so that installs will start without confirmation
        InstallWebConsolePreReqs - Enables roles needed for the SCOM webconsole
.NOTES
    Author: Tom Riddle
.LINK
    https://github.com/riddlertom/New-ScomManagementGroup
#>
param(
    # Service name. Mandatory, by default MSSQLSERVER
    [ValidateSet('JoinDomain','AddScomAdObjs','GetLatestDotnetFramework','UnblockFileWarnings','InstallWebConsolePreReqs')]
    [string[]]$Operations,

    [string]$configFilePath = "$PSScriptRoot\_config.ps1",

    [bool]
    $force #tries the operation regardless of state
)


###########################
#region: Functions

function get-DotnetFrameworkUrls {
	
	$baseUri = "https://dotnet.microsoft.com"
	$basepage = iwr "$baseUri/en-us/download/dotnet-framework" -verbose
	
	
	$relativeLinks = $basepage.Links.href |?{$_ -like "*/net*"} 
	$relativeLinks | %{"$baseUri/$_"}	
}
#$alldotnetlinks = get-DotnetFrameworkUrls 
#$latestDotnet = $alldotnetlinks | select -first 1

Function download-DotnetUrlOfflineSetup {
	param(
		[uri]$uri,
		$outputdir = $env:tmp
	)
	
	$baseUri = "https://dotnet.microsoft.com"
	$basePage = iwr $uri -verbose
	
	$relativeLinks = $basePage.Links | ?{$_.href -like "*-offline-installer*" -and $_.href -notlike "*developer*"} 
	if(!$relativeLinks){write-error "No downloadable file was found!";return}else{
		
		$downloadLink1 = $relativeLinks.href | select -First 1 | %{"$($baseUri)$_"}
		
		$downloadName = split-path $downloadlink1 -Leaf
		$filefullname = "$outputdir\$downloadName.exe"
		$fileExists = test-path $filefullname
		
		if($fileExists -and !$force){write-host "File previously downloaded: $filefullname";return $filefullname}
		
		$downloadPage2 = iwr $downloadLink1 -Verbose
	}
	
	if(!$downloadPage2){write-error "Secondary download page couldn't be found!";return}else{
		
		$relativeLinks2 = $downloadPage2.Links | ?{$_.outerHTML -like "*click here to download manually*" -and $_.href -like "*linkid=*"} 
		$downloadLink2 = $relativeLinks2 | select -first 1 | %{$_.href} #not a relative link here
	
		try{
			write-host "Trying to download from found link: $downloadLink2"
			iwr $downloadLink2 -outfile $filefullname -Verbose
			write-host "saved file at: $filefullname"
			return $filefullname
		}catch{write-error $_}
	}
}

#endregion Functions
###########################

#region: INIT
    $nullme = new-item -Path "$PSScriptRoot\Logs" -ItemType Directory 
    Start-Transcript -Path ("$PSScriptRoot\Logs\$($script:MyInvocation.MyCommand.name).{0:MM-dd-yyyy_hh.mm.ss.mm}.log" -f (get-date))

    if( !(Test-Path $configFilePath) ){write-error "Unable to find config file: $configFilePath"; pause;return;}else{
        . $configFilePath
    }
    
    <#
    #not needed 
    if( !(Get-Module -ListAvailable -Name WindowsCompatibility) ){
        write-host "Installing WindowsCompatibility module for windowsPowershell cmdlets"
        Install-Module WindowsCompatibility -force
    }else{import-module WindowsCompatibility}
    #>

#endregion

<#todo:     sizing calc https://learn.microsoft.com/en-us/system-center/scom/system-requirements?view=sc-om-2016

    https://learn.microsoft.com/en-us/system-center/scom/plan-sqlserver-design?view=sc-om-2019#sql-server-requirements
    Operations Manager 2019 supports SQL 2019 with CU8 or later; however, it doesn't support SQL 2019 RTM.
#>

if($Operations -contains "UnblockFileWarnings"){

    #stop untrusted file warnings from our rectifier nas site.
    $servername = ([uri]$sqlserverISO).dnssafehost

    if(!$servername){write-host "[UnblockFileWarnings] It appears we do not have remote install media. Skipping IE Lan zone trusted host update"}else{

        write-host "[UnblockFileWarnings] Adding IE Lan zone trusted host: $servername"
        try{
            #for all users
            new-item -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\$servername" -Force
            Set-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\$servername" -Name 'File' -Value 1 #nonstring is important

            write-host "[UnblockFileWarnings] Server unblocked: $servername"
            #for this user
            #new-item -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\$servername" -Force
            #Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\$servername" -Name 'File' -Value 1 #nonstring is important
        }catch{write-error $_}


        write-host "[UnblockFileWarnings] Unblocking SSMS directory executables"
        Get-ChildItem -ea 0 "$SSMSexeDir\*" -Include ("*.exe", "*.msi")| Unblock-File -verbose



        $SQLServerISODir = split-path -ea 0 $SQLServerISO -Parent
        write-host "[UnblockFileWarnings] Unblocking SQLServerISO directory executables"
        Get-ChildItem -ea 0 "$SQLServerISODir\*" -Include ("*.exe", "*.msi")| Unblock-File -verbose
        


        write-host "[UnblockFileWarnings] Unblocking SSRS exe" 
        $SsrsExeLocationDir = split-path -ea 0 $SsrsExeLocation -Parent
        Get-ChildItem -ea 0 $SsrsExeLocationDir -Include ("*.exe", "*.msi")| Unblock-File -verbose

        if($SCOMEXELocation){
            $SCOMEXELocationDir = split-path -ea 0 $SCOMEXELocation -Parent
            write-host "[UnblockFileWarnings] Unblocking SCOM exe"
            Get-ChildItem -ea 0 "SCOMEXELocationDir\*"  -Include ("*.exe", "*.msi") | Unblock-File -verbose
        }

        write-host "[UnblockFileWarnings] Unblocking any SCOMEXELocation prereq directory executables"
        Get-ChildItem -ea 0 "$SCOMEXELocationDir\prereq\*" -Include ("*.exe", "*.msi") | Unblock-File -verbose
        

        $SCOMSetupLocalFolderDir = split-path -ea 0 $SCOMSetupLocalFolder -Parent
        write-host "[UnblockFileWarnings] Unblocking SCOMSetupLocalFolder directory executables"
        Get-ChildItem -ea 0 "$SCOMSetupLocalFolderDir\*" -Include ("*.exe", "*.msi") | Unblock-File -verbose

        write-host "[UnblockFileWarnings] Unblocking any SCOMSetupLocalFolder prereq directory executables"
        Get-ChildItem -ea 0 "$SCOMSetupLocalFolderDir\prereq\*" -Include ("*.exe", "*.msi") | Unblock-File -verbose


    }
}

if($Operations -contains "JoinDomain"){

    #install-module ComputerManagementDsc
    Import-Module Microsoft.PowerShell.Management -UseWindowsPowerShell
    
    

    $cimCS = Get-CimInstance -ClassName Win32_ComputerSystem
    write-host "[JoinDomain]This computer is currently joined to domain: $($cimCS.Domain)"
    if ($cimCS.partofdomain -ne $true -or $force) {
        
        $secstring = convertto-securestring $domainPass -asplaintext -force #-Key $key
        $domainJoinCred = New-Object System.Management.Automation.PsCredential("$NetBiosDomainName\$domainUser",$secstring)

        try{
            $res1 = Add-Computer -DomainName $FQDNDomainName -Force -PassThru -Credential $domainJoinCred #-Restart
            if(!$res1.hassucceeded){write-error "Domain join failed: $($res1|out-string)"}else{
                write-warning "[JoinDomain] Domain Join completed. Be sure to restart the computer after domain joining"
            }
        }catch{write-error $_}
        
    }
    
}

if($Operations -contains "AddScomAdObjs"){

    write-host "[AddScomAdObjs] Checking/installing management modules before creating SCOM user(s)/group(s)/OU(s)..."
    #prereq for ad modules
    
    
    #server-specific command for ad module
    $rsatFeatureState = Get-WindowsFeature -Name "RSAT-AD-PowerShell"
    #$rsatFeatureState = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools"
    #if($rsatFeatureState.State -eq 'NotPresent'){Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools" -Online}
    if($rsatFeatureState.InstallState -ne 'Installed'){Install-WindowsFeature -Name "RSAT-AD-PowerShell" –IncludeAllSubFeature}
    
    $ADModule = import-Module -Name ActiveDirectory -UseWindowsPowerShell -PassThru
    if(!$ADModule){write-error "Unable to load ActiveDirectory module.";pause;break}
    #---------------------------------

    $ADDistinguishedOjb = Get-ADDomain -Identity $FQDNDomainName
    $ADDistinguishedName = $ADDistinguishedOjb.DistinguishedName
	
	#Creating AD OU
    $ADOrganizationalUnit = get-ADOrganizationalUnit -Identity "OU=$OUName,$ADDistinguishedName" -ErrorAction SilentlyContinue
    if(!$ADOrganizationalUnit){$ADOrganizationalUnit = New-ADOrganizationalUnit -Name $OUName -Path $ADDistinguishedName -Passthru -ErrorAction SilentlyContinue}
	
	
	#Creating AD Users
    try{
    

    if( !(Get-ADUser -Identity "CN=$SQLUser,$($ADOrganizationalUnit.DistinguishedName)" -ErrorAction 0)){
        $secstring = convertto-securestring $SQLUserPass -asplaintext -force #-Key $key
        New-ADUser -Name $SQLUser -SamAccountName $SQLUser -AccountPassword $secstring -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    }

    if( !(Get-ADUser -Identity "CN=$SCOMDataAccessAccount,$($ADOrganizationalUnit.DistinguishedName)" -ErrorAction 0)){
        $secstring = convertto-securestring $SCOMDataAccessAccountPass -asplaintext -force #-Key $key
        New-ADUser -Name $SCOMDataAccessAccount -SamAccountName $SCOMDataAccessAccount -AccountPassword $secstring -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    }

    if( !(Get-ADUser -Identity "CN=$SCOMDataWareHouseReader,$($ADOrganizationalUnit.DistinguishedName)" -ErrorAction 0)){
        $secstring = convertto-securestring $SCOMDataWareHouseReaderPass -asplaintext -force #-Key $key
        New-ADUser -Name $SCOMDataWareHouseReader -SamAccountName $SCOMDataWareHouseReader -AccountPassword $secstring -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    }

    if( !(Get-ADUser -Identity "CN=$SCOMDataWareHouseWriter,$($ADOrganizationalUnit.DistinguishedName)" -ErrorAction 0)){
        $secstring = convertto-securestring $SCOMDataWareHouseWriterPass -asplaintext -force #-Key $key
        New-ADUser -Name $SCOMDataWareHouseWriter -SamAccountName $SCOMDataWareHouseWriter -AccountPassword $secstring -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    }

    if( !(Get-ADUser -Identity "CN=$SCOMServerAction,$($ADOrganizationalUnit.DistinguishedName)" -ErrorAction 0)){
        $secstring = convertto-securestring $SCOMServerActionPass -asplaintext -force #-Key $key
        New-ADUser -Name $SCOMServerAction -SamAccountName $SCOMServerAction -AccountPassword $secstring -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    }

    if( !(Get-ADGroup -Identity "CN=$SCOMAdmins,$($ADOrganizationalUnit.DistinguishedName)" -ErrorAction 0)){

        New-ADGroup -Name $SCOMAdmins -GroupScope Global -GroupCategory Security -Path $ADOrganizationalUnit.DistinguishedName
    }

	Add-ADGroupMember -Members @($SCOMDataAccessAccount, $SCOMServerAction, $env:USERNAME) -Identity "CN=$SCOMAdmins,$($ADOrganizationalUnit.DistinguishedName)"

	#SQL Server service accounts (SQLSSRS is a service reporting services account)
	#New-ADUser -Name $SQLSVC -SamAccountName $SQLSVC -AccountPassword $secstring -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
	#New-ADUser -Name $SQLSSRS -SamAccountName $SQLSSRS -AccountPassword $secstring -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
	write-host "The service Accounts and 'SCOM-Admins' group have been added to: OU=$OUName,$DistinguishedName"

    }catch{
        write-error $_
    }
}

if($Operations -contains "GetLatestDotnetFramework"){

    write-host "[ManagementTools] Checking/downloading for latest dotnet install..."
    $alldotnetlinks = get-DotnetFrameworkUrls 
    $latestDotnet = $alldotnetlinks | ?{$_ -notmatch 'net..1$'} | select -first 1 #exclude versions like 4.8.1 which aren't supported by 2016. 


    

    $LatestMSIFullname = download-DotnetUrlOfflineSetup -uri $latestDotnet -outputdir $SSMSexeDir
    
    if($LatestMSIFullname){
        
        Start-Process -Wait -FilePath $LatestMSIFullname -ArgumentList "/passive /AcceptEULA /norestart" #   "/quiet /norestart"
        write-warning "Be sure to restart the computer after install of new dotnet"
    }

    $dotnet35 = get-WindowsFeature NET-Framework-Core
    if($dotnet35 -and $dotnet35.InstallState -ne "Installed" ){
        write-host "Installing dotnet 3.5"
        Add-WindowsFeature NET-Framework-Core
    }

}

if($Operations -contains "InstallWebConsolePreReqs"){
        #todo: may need some massaging if 2016 vs 2019 etc
        $featurenames = 'Web-Server,NET-WCF-HTTP-Activation45,Web-Static-Content,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Http-Logging,Web-Request-Monitor,Web-Filtering,Web-Stat-Compression,Web-Mgmt-Console,Web-Metabase,Web-Asp,Web-Asp-Net45,Web-Asp-Net,Web-Windows-Auth' -split ','
        $res1 = Install-WindowsFeature -name $featurenames -IncludeManagementTools #-Source "C:\Sources\Sxs" -Restart
        write-warning "Be sure to restart the computer after install of webconsole prereqs"
}

Stop-Transcript