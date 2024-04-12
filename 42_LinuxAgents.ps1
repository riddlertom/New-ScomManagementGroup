#Requires -Version 5.1 -RunAsAdministrator
<#
.SYNOPSIS
    Operations for SCOM Linux Agents


.DESCRIPTION

    $Operation:

        LINUX
        ClearTrustedSSHHosts - For when you reinstall a linux agent between runs of this script.

        CreateLinuxSCOMUsers - creates the high and low priv linux users.
        SetSudoers - Enables Linux SCOM users to run monitoring commands/maintenance operations.
        DetectOSInfo - Runs SCOM's OS Detection script.

        InstallLinuxBinary - Detects OS arch, processor, and installs the appropriate agent. This should install the package and enable port 1270.
        UnInstallLinuxBinary - Detects the appropriate agent, and runs it with the --uninstall flag. This should uninstall the package.
        PurgeLinuxBinary - Detects the appropriate agent, and runs it with the --purge flag. This should uninstall the package and remove all related data.
        UngradeLinuxBinary - Detects the appropriate agent, and runs it with the --upgrade flag. This should upgrade the existing binary with a more current one.
        VersionCheckLinuxBinary - Detects the appropriate agent, and runs it with the --version-check flag. This checks existing installed versions to see if upgradable
        VersionOfLinuxBinary - Detects the appropriate agent, and runs it with the --version flag. This shows the Version of this shell bundle.

        SignCertForLinuxBinary - Signs the Certificate for an existing installation of a Linux Binary. This allows the ManagementServer to authenticate.

        AddAgentToMG - Tells SCOM to discover, and add the agent to the linux resource pool. Normal install process will occur if no cert/agent bins are installed.
        RemoveAgentFromOldMG - Tells SCOM to remove agent from monitoring in the old environment. This does NOT uninstall the binary from the server.

.NOTES
    Needs posh-SSH and operationsManager modules.
    Powershell 5.1 was used here due to the dotnetframework scx creds

.LINK
#>
param(
    [ValidateSet('ClearTrustedSSHHosts','CreateLinuxSCOMUsers','SetSudoers','InstallLinuxBinary','UnInstallLinuxBinary','PurgeLinuxBinary','UngradeLinuxBinary','VersionCheckLinuxBinary','VersionOfLinuxBinary','DetectOSInfo','SignCertForLinuxBinary','AddAgentToMG','RemoveAgentFromOldMG')]
    [string[]]$Operation,

    [string]$configFilePath = "$PSScriptRoot\_config.ps1"
)

#region: INIT

$nullme = new-item -Path "$PSScriptRoot\Logs" -ItemType Directory -Force
Start-Transcript -Path ("$PSScriptRoot\Logs\$($script:MyInvocation.MyCommand.name).{0:MM-dd-yyyy_hh.mm.ss.mm}.log" -f (get-date))

if($PSVersionTable.PSVersion.Major -ne 5){write-error "This script must be ran on WINDOWSPowershell 5.1 for old dotnetframework objs to work";return}

#$domainJoinCred = New-Object System.Management.Automation.PsCredential($domainUser,$secstring)
if( !(Test-Path $configFilePath) ){write-error "Unable to find config file: $configFilePath"; return;}
. $configFilePath


#endregion


#region: INIT


$moduleName = "Posh-SSH"
$Module = get-Module $moduleName -ListAvailable
if(!$Module ){ $nullme = Install-Module $moduleName -Force -verbose; $Module = get-Module $moduleName -ListAvailable}
if(!$Module){Write-Error "Unable to install needed module: $moduleName";return}
try{Import-Module $moduleName -ea 0}catch{continue} #suppress scary dll conflicts


$OpsModule = Import-Module OperationsManager  -PassThru #-UseWindowsPowerShell
if(!$OpsModule){Write-Error "Unable to load SCOM module: OperationsManager";return}

#endregion /INIT


###########################
#region: Functions / SBs


#Scripts for Creating LinuxUsers. The naming scheme here is tied to SCOM's GetOSVersion.sh > OSName field (vs just uname -a)
$OsAliasToAddUserScripts = @{}
$OsAliasToAddUserScripts."AIX" = @"
    sudo mkuser -c "$linuxPrivMaintUser" -h /home/$linuxPrivMaintUser -g staff -p "$linuxPrivMaintPass" "$linuxPrivMaintUser"
    sudo mkuser -c "$linuxAAUser" -h /home/$linuxAAUser -g staff -p "$linuxAAPass" "$linuxAAUser"
"@
$OsAliasToAddUserScripts."SunOS" = @"
    
    sudo useradd -m -d /export/home/$linuxPrivMaintUser -s /bin/bash "$linuxPrivMaintUser"
    echo "$($linuxPrivMaintUser):$linuxPrivMaintPass" | sudo passwd -e "$linuxPrivMaintUser"

    sudo useradd -m -d /export/home/$linuxAAUser -s /bin/bash "$linuxAAUser"
    echo "$($linuxAAUser):$linuxAAPass" | sudo passwd -e "$linuxAAUser"
"@
#HPUX seems the same as Solaris commands.
$OsAliasToAddUserScripts."HPUX" = $OsAliasToAddUserScripts."Solaris"

# For Red Hat, Ubuntu, SUSE-specific, etc commands are default and most common. Update as required
$OsAliasToAddUserScripts."Linux" = @"
    #linux
    sudo useradd -m -s /bin/bash "$linuxPrivMaintUser"
    echo "$($linuxPrivMaintUser):$linuxPrivMaintPass" | sudo chpasswd 

    sudo useradd -m -s /bin/bash "$linuxAAUser"
    echo "$($linuxAAUser):$linuxAAPass" | sudo chpasswd 
"@
$OsAliasToAddUserScripts."CentOS" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."Fedora" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."Ubuntu" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."Debian" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."openSUSE" = $OsAliasToAddUserScripts."Linux"
$OsAliasToAddUserScripts."SUSE Linux Enterprise Server" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."Red Hat Enterprise Linux" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."ALT Linux" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."Enterprise Linux Server" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."NeoKylin Linux Server" = $OsAliasToAddUserScripts."Linux" 
$OsAliasToAddUserScripts."Default" = $OsAliasToAddUserScripts."Linux"


function Get-SCXSSHCredentialFromScript{
    [CmdletBinding()]
    param
    (
      [Parameter(Mandatory=$True)]
      [string]$UserName,
      
      [string]$Passphrase,
      
      [string]$SSHKeyFile,          
      
      [string]$SuPassword, #for escalating privs from base $UserName
      
      [ValidateSet('su','sudo')]
      [string]$ElevationType
    )
  
    process {
      $SSHcredential=""
      $scred=""
      $SSHcredential = New-Object Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.Core.CredentialSet
      $scred = New-Object Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.Core.PosixHostCredential
      $scred.Usage = 2
  
      $scred.PrincipalName = $username
  
      if ($Passphrase.Length -gt 0){
          $sPassphrase=ConvertTo-SecureString "$Passphrase" -AsPlainText -Force    
          $scred.Passphrase = $sPassphrase
      }
  
      if ($SSHKeyFile.Length -gt 0)
      {
          $scred.KeyFile = $SSHKeyFile
          #Write-Host "Validating SSH Key"   
          $scred.ReadAndValidateSshKey()
      }
      
      #add posixhost credential to credential set
      $SSHcredential.Add($scred)
  
      if ($elevationType.Equals("su"))
      {
        $sSUPassword=ConvertTo-SecureString "$SUPassword" -AsPlainText -Force  
        $sucred = New-Object Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.Core.PosixHostCredential
        $sucred.Usage = 32 #su elevation
        $sucred.PrincipalName = "root"
        $sucred.Passphrase = $SUPassword
        $SSHcredential.Add($sucred)
      }
  
  
      if ($elevationType.Equals("sudo"))
      {
        $sudocred = New-Object Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.Core.PosixHostCredential
        $sudocred.Usage = 16 #sudo elevation
        $SSHcredential.Add($sudocred)
      }
      Return $SSHCredential
    }
}


Function Set-LinuxBinary {
    # Copies the specified linux kit and performs the given operation
    param(
        [string[]]$computernames,
                
        [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.Core.CredentialSet]
        $SCXSSHCred,

        [System.IO.FileInfo]
        $BinPath, #path to scom package (found via getosversion)
        
        <# Complete options are:
        --extract              Extract contents and exit.
        --install              Install the package from the system.
        --purge                Uninstall the package and remove all related data.
        --remove               Uninstall the package from the system.
        --restart-deps         Reconfigure and restart dependent service
        --source-references    Show source code reference hashes.
        --upgrade              Upgrade the package in the system.
        --version              Version of this shell bundle.
        --version-check        Check versions already installed to see if upgradable
        #>
        [ValidateSet('install','purge','remove','upgrade','version-check','version')]
        [string]$SCXOperation,

        #--enable-opsmgr        Enable port 1270 for usage with opsmgr.
        [switch]$enableopsmgrPort,

        # --force                Force upgrade (override version checks).
        [switch]$force
    )

    #region: INIT

    Import-Module "Posh-SSH"


    # Build SSH creds from the SCX cred obj
    # credentials for SSH
    $sshPassSecObj = $SCXSSHCred.GetXmlPassword('SshDiscovery') # contains XML in the pass field
    $tmpCred = New-Object System.Management.Automation.PsCredential($SCXSSHCred.SshUserName, $sshPassSecObj)

    [xml]$sshPassSecXML = $tmpCred.GetNetworkCredential().Password
    $sshPassSec = ConvertTo-SecureString $sshPassSecXML.SCXSecret.Password -AsPlainText -Force 
    $sshCred = New-Object System.Management.Automation.PsCredential($SCXSSHCred.SshUserName, $sshPassSec)   


    # Define the registry path for SCOM installation
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
    if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCOM installed?";break;return;}else{
        # Get the installation path value
        $ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory
    }


    #endregion /INIT


    #region MAIN
    foreach($computername in $computernames){

        try {Write-Host "Setting up SSH session to: $computername"
            $sshSession = New-SSHSession -ComputerName $computername -Credential $sshCred -AcceptKey -ErrorAction stop
        
        } catch {write-error $_
            continue
        }

        #'Install','Upgrade','Uninstall')]
        
       
        try{

            write-host "copying kit to /tmp from: $($BinPath.Fullname)"
            Set-SCPItem -ComputerName $computername -Path $BinPath.Fullname -Destination /tmp -Credential $sshCred -AcceptKey -ConnectionTimeout 300 -ErrorAction stop -verbose
    
            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "chmod 777 /tmp/$($BinPath.Name)"
            if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}

            #build what we're running
            $operationStr = "--$($SCXOperation)"            
            if($enableopsmgrPort){$operationStr = "$operationStr --enable-opsmgr"} #--enable-opsmgr        Enable port 1270 for usage with opsmgr.
            if($force){$operationStr = "$operationStr --force"} # --force                Force upgrade (override version checks).

            $fullOpsStr = "sudo /tmp/$($BinPath.Name) $operationStr".tolower()

            #------------------------------
            
            write-host "Executing command: $fullOpsStr"
            $scriptRes1 = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command $fullOpsStr
            if ($scriptRes1.ExitStatus -ne 0) {write-error "Last Exit '$($scriptRes1.ExitStatus)': $($scriptRes1.Error)" -ea Stop}

            $scriptRes1

            write-host "Finished operation on: /tmp/$($BinPath.Name)"
        }catch{
            write-error $_
        
        }finally{
            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "rm -f /tmp/$($BinPath.Name)"
            if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}
        }

    }

    #endregion /MAIN

}

Function Get-LinuxOSVersion {
    #returns linux OS info, and a path to the proper linux package to install
    param(
        [string[]]$computernames,
        
        [pscredential]
        $SSHCreds
    )

    # Define the registry path for SCOM installation
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
    if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCOM installed?";break;return;}else{
        # Get the installation path value
        $ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory
    }

    # get sources folder
    $AgentsDir = "$($ScomInstallPath)AgentManagement\UnixAgents"
    if( !(test-path $AgentsDir)){write-error "Path Not Found: $ScomInstallPath\AgentManagement\UnixAgents";return}
    $DownloadedKits = "$ScomInstallPath\AgentManagement\UnixAgents\DownloadedKits"
    if( !(test-path $AgentsDir)){write-error "Path Not Found: $ScomInstallPath\AgentManagement\UnixAgents\DownloadedKits"return}
    $getOsVersionSH = "$AgentsDir\GetOSVersion.sh"
    if( !(test-path $AgentsDir)){write-error "Path Not Found: $AgentsDir\GetOSVersion.sh"return}


    foreach($computername in $computernames){
        
        try{
            write-host "[Get-LinuxOSVersion] Connecing to: $computername"
            $sshSession = New-SSHSession -ComputerName $computername -Credential $SSHCreds -AcceptKey -ErrorAction stop
        }catch{
            write-error $_
            continue
        }
        
        try{

            write-host "copying GetOSVersion.sh script to /tmp..."
            Set-SCPItem -ComputerName $computername -Path $getOsVersionSH -Destination /tmp -Credential $sshCred -AcceptKey -ConnectionTimeout 300 -ErrorAction stop -verbose
    
            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "chmod 777 /tmp/GetOSVersion.sh"
            if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}

            write-host "Executing GetOSVersion.sh..."
            $scriptRes1 = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "/tmp/GetOSVersion.sh"
            if ($scriptRes1.ExitStatus -ne 0) {write-error "Last Exit '$($scriptRes1.ExitStatus)': $($scriptRes1.Error)" -ea Stop}

            write-host "finished GetOSVersion.sh"
        }catch{
            write-error $_
        }

        #emit script resultobj
        if($scriptRes1.Output){
            write-host $scriptRes1.Output
            $scriptRes1.Output
        }
        
        #finally cleanup if possible
        $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "rm -f /tmp/GetOSVersion.sh"
        if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}
    }

}

Function priv_FindLinuxKit {
    #helper function to return the direct path for the linux kit install
    param(
        [xml]$osinfo #output from 
    )

    # Define the registry path for SCOM installation
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
    if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCOM installed?";break;return;}else{
        # Get the installation path value
        $ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory
    }

    # get sources folder
    $AgentsDir = "$($ScomInstallPath)AgentManagement\UnixAgents"
    if( !(test-path $AgentsDir)){write-error "Path Not Found: $ScomInstallPath\AgentManagement\UnixAgents";return}
    $DownloadedKits = "$($ScomInstallPath)AgentManagement\UnixAgents\DownloadedKits"
    if( !(test-path $AgentsDir)){write-error "Path Not Found: $($ScomInstallPath)AgentManagement\UnixAgents\DownloadedKits"return}
    $getOsVersionSH = "$AgentsDir\GetOSVersion.sh"
    if( !(test-path $AgentsDir)){write-error "Path Not Found: $AgentsDir\GetOSVersion.sh"return}


    # get Linux architecture (sample: "i386" or "x86_64" or "ppc")
    if ($osinfo.DiscoveredOS.Arch -eq "i386") {
        $Arch = "x86"
    } elseif  ($osinfo.DiscoveredOS.Arch -eq "x86_64") {
        $Arch = "x64"
    } else {
        $Arch = "ppc"
    }

    if($osinfo.DiscoveredOS.OSAlias -like "Universal*"){
        $osVersionStr = '1.*' # scx-1.8.1-0.universalr.1.s.x64 or scx-1.8.1-0.universald.1.x86.sh are two big patterns I See.
    }else{
        $osVersionStr = $osinfo.DiscoveredOS.Version -split "\." | select -first 1
    }

    $filePattern = "$($osinfo.DiscoveredOS.OSAlias).$osVersionStr.$($Arch)"
    $agentFile = dir $DownloadedKits | ? {$_.BaseName -match $filePattern} | sort CreationTime | select -last 1
    
    $agentFile
}

Function signLinuxAgentCert{
    #copies a linux cert to localhost, signs it, and copies back. (Restarts the agent to apply change)
    param(
        [string[]]$computernames,
        
        [pscredential]
        $SSHCreds
    )
    
    if(!$global:ScomInstallPath){
        
        # Define the registry path for SCOM installation
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
        if ( !(Test-Path -Path $registryPath)){write-host "SCOM install path not found, is SCOM installed?";break;return;}else{
            # Get the installation path value
            $global:ScomInstallPath = Get-ItemProperty -Path $registryPath -Name "InstallDirectory" | Select-Object -ExpandProperty InstallDirectory
        }
    }

    $scxEXE = "$($global:ScomInstallPath)scxcertconfig.exe"
    if( !(test-path $scxEXE) ){write-error "Couldn't find scxcertconfig.exe at:  $scxEXE";return}
    
    $path1 = "$SCOMNasBackup\SCXCertsBackup"
    $CertbackupDir = new-item -Path $path1 -ItemType Directory -Force #store certs here

    foreach($computername in $computernames){

        try {Write-Host "Setting up SSH session to: $computername"
            $sshSession = New-SSHSession -ComputerName $computername -Credential $sshCred -AcceptKey -ErrorAction stop
    
        } catch {write-error $_
            continue
        }

        try {
            Write-Host "Finding+copying .pem cert to copy locally"

            # SCOM new path:
            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "ls /etc/opt/omi/ssl/*-host-*.pem"
            if(!$output.Output){ #old SCOM 2012 path
                write-host "falling back to SCOM 2012 path..."
                $output = Invoke-SSHCommand -SessionId $sshSession.SessionId -Command "ls /etc/opt/microsoft/scx/ssl/*-host-*.pem" -TimeOut 60
            }
            if(!$output.output){write-error -ea stop "Couldn't find the SCOM LINUX agent's cert. Verify agent is installed"}
            
            $filestamp = '{0:MM-dd-yyyy_hh.mm.ss.mm}' -f (get-date)

            $remoteFile = $output.Output | select -first 1
            $remoteFileName = split-path $remoteFile -leaf
            $origCertPath = "$env:temp\$($remoteFileName).$filestamp.orig"
            
            Get-SCPItem -ComputerName $computername -Credential $sshCred -Path $remoteFile -PathType File -Destination $env:temp -NewName "$($remoteFileName).$filestamp.orig" -AcceptKey -ConnectionTimeout 300 -verbose -ErrorAction stop
            
        } catch {
            write-error $_
            continue
        }

        try {
            Write-Host "signing cert..."

            $newCertName = $remoteFileName # $origCertPath -replace '\.orig$',''
            Start-Process $scxEXE -verb runas -ArgumentList " -sign `"$origCertPath`" `"$env:temp\$newCertName`"" -wait -WindowStyle Hidden -ea stop
            write-host "Cert signed!"
        } catch {
            write-error $_
            continue
        }finally{
            rename-item -LiteralPath "$env:temp\$newCertName" -NewName "$env:temp\$newCertName.$filestamp.pem"
        }

        try {
            Write-Host "copying signed .pem to host, and updating current cert"

            Set-SCPItem -ComputerName $computername -Path "$env:temp\$newCertName.$filestamp.pem" -Destination /tmp -Credential $sshCred -AcceptKey -ConnectionTimeout 300 -ErrorAction stop -verbose

            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "sudo cp --force /tmp/$newCertName $remoteFile"
            if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}

            write-host "New Cert uploaded!"
        } catch {
            write-error $_
            continue
        }

        try {
            Write-Host "Restarting SCXagent to apply changes"
            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "sudo scxadmin -restart" 
            if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}
        } catch {
            write-error $_
            continue
        }
        
        try{

            write-host "Backing up certs to: $($CertbackupDir.FullName)"
            $nullme = Move-Item -Path "$env:tmp\*.pem" -Destination $CertbackupDir.FullName -force -Verbose
            $nullme = Move-Item -Path "$env:tmp\*.orig" -Destination $CertbackupDir.FullName -force -Verbose

            write-host "Finished SCX Certificate signing for server."
        }catch{
            write-error $_
        }
    }
}

Function invoke-SCOMDiscovery {
    #will attempt to install a SCOM linux agent if needed, else simply adds to SCOM MG
    param(
        [string[]]$computernames,
        
        [string]$LinuxPoolName,

        [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.Core.CredentialSet]
        $SCXSSHCred
    )

    # Build SSH creds from the SCX cred obj
    # credentials for SSH
    $sshPassSecObj = $SCXSSHCred.GetXmlPassword('SshDiscovery') # contains XML in the pass field
    $tmpCred = New-Object System.Management.Automation.PsCredential($SCXSSHCred.SshUserName, $sshPassSecObj)

    [xml]$sshPassSecXML = $tmpCred.GetNetworkCredential().Password
    $sshPassSec = ConvertTo-SecureString $sshPassSecXML.SCXSecret.Password -AsPlainText -Force 
    $sshCred = New-Object System.Management.Automation.PsCredential($SCXSSHCred.SshUserName, $sshPassSec)   

    $LinuxPool = Get-SCOMResourcePool -DisplayName $LinuxPoolName

    
    foreach($computername in $computernames){
        
        write-host "[AddAgentToMG] Attempting to discover computer: $computername"
        $SCXDiscovery = Invoke-SCXDiscovery -WsManCredential $sshCred -SshCredential $SCXSSHCred -Name $computerName -ResourcePool $LinuxPool
        
        if ( $SCXDiscovery.Succeeded -ne $True) #[string]::IsNullOrWhiteSpace($SCXDiscovery) )
        {
            #Discovery Failed
            Write-Output $($SCXDiscovery.ErrorData)
            return 1 
        }
        else
        {
            Write-host "Agent discovered successfully"

            if($true){

                write-host "Attempting to push agent from SCOM management server"
                $AgentInst = $SCXDiscovery | Install-SCXAgent
                if ([string]::IsNullOrWhiteSpace($AgentInst))
                {
                    #Agent Install Failed
                    write-host "Agent Install Attempt Failed for: $computername"
                    return 2
                }
                else
                {
                    return 0
                }
            }else{
                return 0
            }
        }
    }
}
###########################
#endregion

#Global operations
if($operation -contains 'ClearTrustedSSHHosts'){

    write-host "Clearing SSH fingerprints from prior runs"
    Get-SSHTrustedHost | Remove-SSHTrustedHost

    if(!$linuxAgentNames){return}
}


# Server / instance operations
if(!$linuxAgentNames){write-error "No Linux agent names provided!";return}


if($operation -contains 'DetectOSInfo'){

    #note: You may want to switch this at times to the linuxadmin or linuxuser instead in the config file.
    $secstring = ConvertTo-SecureString $linuxDeployPass -AsPlainText -Force
    $sshCred = New-Object System.Management.Automation.PsCredential($linuxDeployUser, $secstring)
    
    Get-LinuxOSVersion -computernames $linuxAgentNames -SSHCreds $sshCred
}


if($operation -contains 'CreateLinuxSCOMUsers'){

    write-host "[CreateLinuxSCOMUsers] Starting.."
    foreach($linuxAgentName in $linuxAgentNames){


        #note: You may want to switch this at times to the linuxadmin or linuxuser instead. 
        try{
            $secstring = ConvertTo-SecureString $linuxDeployPass -AsPlainText -Force
            $sshCred = New-Object System.Management.Automation.PsCredential($linuxDeployUser, $secstring)
            [xml]$osinfo = Get-LinuxOSVersion -computernames $linuxAgentNames -SSHCreds $sshCred
        }catch{
            write-error $_
            continue
        }

        try {Write-Host "Setting up SSH session to: $linuxAgentName"

            $secstring = ConvertTo-SecureString $linuxDeployPass -AsPlainText -Force
            $sshCred = New-Object System.Management.Automation.PsCredential($linuxDeployUser, $secstring)
            $sshSession = New-SSHSession -ComputerName $linuxAgentName -Credential $sshCred -AcceptKey -ErrorAction stop
        
        } catch {write-error $_ -ea Stop
            continue
        }

        #determine useradd Script
        $osname = $osinfo.DiscoveredOS.OSName
        if($OsAliasToAddUserScripts.$osname){
            $addScriptBlock = $OsAliasToAddUserScripts.$osname
        }else{
            $addScriptBlock = $OsAliasToAddUserScripts.Default
        }


        try{
            write-host "Attempting to create SCOM users..."


            write-host "Executing useradd..."
            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command ($addScriptBlock -replace "`r`n","`n")
            if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}

            write-host "finished SCOM user creation"
        }catch{
            write-error $_
            $docontinue = $true
        }

        
        $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "sudo rm -f /tmp/createScomUsers.sh"
        if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}
  
    }
}


if($operation -contains 'SetSudoers'){

    if(!$LinuxSudoers){write-error "No data stored in `$LinuxSudoers varible.";break}
        
    foreach($linuxAgentName in $linuxAgentNames){
        try {Write-Host "[SetSudoers] Setting up SSH session to: $linuxAgentName"

            $secstring = ConvertTo-SecureString $linuxDeployPass -AsPlainText -Force
            $sshCred = New-Object System.Management.Automation.PsCredential($linuxDeployUser, $secstring)        
            $sshSession = New-SSHSession -ComputerName $linuxAgentName -Credential $sshCred -AcceptKey -ErrorAction stop

        } catch {write-error $_ -ea Stop
            continue
        }

        #setup sudoers file:
        try {

            $fLinuxSudoers = $LinuxSudoers -replace "`r`n","`n" 
            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command "sudo echo `"$fLinuxSudoers`" > /tmp/scommonitoring"
            if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}

            $cmdStr = "
            sudo chmod 0440 /tmp/scommonitoring
            sudo chown root:root /tmp/scommonitoring
            sudo mv /tmp/scommonitoring /etc/sudoers.d/scommonitoring
            " -replace "`r`n","`n"

            $output = Invoke-SSHCommand -TimeOut 300 -SessionId $sshSession.SessionId -Command $cmdStr
            if ($output.ExitStatus -ne 0) {write-error "Last Exit '$($output.ExitStatus)': $($output.Error)" -ea Stop}

            write-host "[SetSudoers] Finished operation on: $linuxAgentName"
        }catch{write-error $_;continue}
    }

}


if($operation -contains 'InstallLinuxBinary'){

    #note: here we use the linuxPro
    write-host "[$operation] User set for connections: $linuxPrivMaintUser"
    $secstring = ConvertTo-SecureString $linuxPrivMaintPass -AsPlainText -Force
    $sshCred = New-Object System.Management.Automation.PsCredential($linuxPrivMaintUser, $secstring)
    

    foreach($linuxAgentName in $linuxAgentNames){

        write-host "[$operation] Starting operation for: $linuxAgentName"
       
        $osinfo = Get-LinuxOSVersion -computernames $linuxAgentName -SSHCreds $sshCred
        $binpath = priv_FindLinuxKit -osinfo $osinfo
        if(!$binpath){write-error "Unable to Find kit install path for: $linuxAgentName";continue}

        $SCXSSHCred = Get-SCXSSHCredentialFromScript -UserName $linuxPrivMaintUser -Passphrase $linuxPrivMaintPass -SSHKeyFile $null -SuPassword $null -ElevationType sudo 
        $res1 = Set-LinuxBinary -computernames $linuxAgentName -SCXSSHCred $SCXSSHCred -BinPath $binpath -SCXOperation "Install" -enableopsmgrPort
        $res1 | select * | out-string
    }

}

if($operation -contains 'UnInstallLinuxBinary'){

    #note: here we use the linuxPro
    write-host "[$operation] User set for connections: $linuxPrivMaintUser"
    $secstring = ConvertTo-SecureString $linuxPrivMaintPass -AsPlainText -Force
    $sshCred = New-Object System.Management.Automation.PsCredential($linuxPrivMaintUser, $secstring)
    
    
    foreach($linuxAgentName in $linuxAgentNames){

        write-host "[$operation] Starting operation for: $linuxAgentName"
       
        $osinfo = Get-LinuxOSVersion -computernames $linuxAgentName -SSHCreds $sshCred
        $binpath = priv_FindLinuxKit -osinfo $osinfo
        if(!$binpath){write-error "Unable to Find kit install path for: $linuxAgentName";continue}

        $SCXSSHCred = Get-SCXSSHCredentialFromScript -UserName $linuxPrivMaintUser -Passphrase $linuxPrivMaintPass -SSHKeyFile $null -SuPassword $null -ElevationType sudo 
        $res1 = Set-LinuxBinary -computernames $linuxAgentName -SCXSSHCred $SCXSSHCred -BinPath $binpath -SCXOperation "remove"
        $res1 | select * | out-string
    }
}

if($operation -contains 'PurgeLinuxBinary'){

        #note: here we use the linuxPro
        write-host "[$operation] User set for connections: $linuxPrivMaintUser"
        $secstring = ConvertTo-SecureString $linuxPrivMaintPass -AsPlainText -Force
        $sshCred = New-Object System.Management.Automation.PsCredential($linuxPrivMaintUser, $secstring)
        
        
        foreach($linuxAgentName in $linuxAgentNames){
    
            write-host "[$operation] Starting operation for: $linuxAgentName"
           
            $osinfo = Get-LinuxOSVersion -computernames $linuxAgentName -SSHCreds $sshCred
            $binpath = priv_FindLinuxKit -osinfo $osinfo
            if(!$binpath){write-error "Unable to Find kit install path for: $linuxAgentName";continue}
    
            $SCXSSHCred = Get-SCXSSHCredentialFromScript -UserName $linuxPrivMaintUser -Passphrase $linuxPrivMaintPass -SSHKeyFile $null -SuPassword $null -ElevationType sudo 
            $res1 = Set-LinuxBinary -computernames $linuxAgentName -SCXSSHCred $SCXSSHCred -BinPath $binpath -SCXOperation "purge"
            $res1 | select * | out-string
        }
}

if($operation -contains 'UngradeLinuxBinary'){

        #note: here we use the linuxPro
        write-host "[$operation] User set for connections: $linuxPrivMaintUser"
        $secstring = ConvertTo-SecureString $linuxPrivMaintPass -AsPlainText -Force
        $sshCred = New-Object System.Management.Automation.PsCredential($linuxPrivMaintUser, $secstring)
        
        
        foreach($linuxAgentName in $linuxAgentNames){
    
            write-host "[$operation] Starting operation for: $linuxAgentName"

            $osinfo = Get-LinuxOSVersion -computernames $linuxAgentName -SSHCreds $sshCred
            $binpath = priv_FindLinuxKit -osinfo $osinfo
            if(!$binpath){write-error "Unable to Find kit install path for: $linuxAgentName";continue}
    
            $SCXSSHCred = Get-SCXSSHCredentialFromScript -UserName $linuxPrivMaintUser -Passphrase $linuxPrivMaintPass -SSHKeyFile $null -SuPassword $null -ElevationType sudo 
            $res1 = Set-LinuxBinary -computernames $linuxAgentName -SCXSSHCred $SCXSSHCred -BinPath $binpath -SCXOperation "upgrade"
            $res1 | select * | out-string
        }
}

if($operation -contains 'VersionCheckLinuxBinary'){

        #note: here we use the linuxPro
        write-host "[$operation] User set for connections: $linuxPrivMaintUser"
        $secstring = ConvertTo-SecureString $linuxPrivMaintPass -AsPlainText -Force
        $sshCred = New-Object System.Management.Automation.PsCredential($linuxPrivMaintUser, $secstring)
        
        
        foreach($linuxAgentName in $linuxAgentNames){
    
            write-host "[VersionCheckLinuxBinary] Starting operation for: $linuxAgentName"

            $osinfo = Get-LinuxOSVersion -computernames $linuxAgentName -SSHCreds $sshCred
            $binpath = priv_FindLinuxKit -osinfo $osinfo
            if(!$binpath){write-error "Unable to Find kit install path for: $linuxAgentName";continue}
    
            $SCXSSHCred = Get-SCXSSHCredentialFromScript -UserName $linuxPrivMaintUser -Passphrase $linuxPrivMaintPass -SSHKeyFile $null -SuPassword $null -ElevationType sudo 
            $res1 = Set-LinuxBinary -computernames $linuxAgentName -SCXSSHCred $SCXSSHCred -BinPath $binpath -SCXOperation 'version-check'
            $res1 | select * | out-string
        }
}

if($operation -contains 'VersionOfLinuxBinary'){

    #note: here we use the linuxPro
    write-host "[$operation] User set for connections: $linuxPrivMaintUser"
    $secstring = ConvertTo-SecureString $linuxPrivMaintPass -AsPlainText -Force
    $sshCred = New-Object System.Management.Automation.PsCredential($linuxPrivMaintUser, $secstring)
    
    
    foreach($linuxAgentName in $linuxAgentNames){

        write-host "[$operation] Starting operation for: $linuxAgentName"
       
        $osinfo = Get-LinuxOSVersion -computernames $linuxAgentName -SSHCreds $sshCred
        $binpath = priv_FindLinuxKit -osinfo $osinfo
        if(!$binpath){write-error "Unable to Find kit install path for: $linuxAgentName";continue}

        $SCXSSHCred = Get-SCXSSHCredentialFromScript -UserName $linuxPrivMaintUser -Passphrase $linuxPrivMaintPass -SSHKeyFile $null -SuPassword $null -ElevationType sudo 
        $res1 = Set-LinuxBinary -computernames $linuxAgentName -SCXSSHCred $SCXSSHCred -BinPath $binpath -SCXOperation 'version'
        $res1 | select * | out-string
    }
}

if($operation -contains 'SignCertForLinuxBinary'){

    #note: here we use the linuxPro
    write-host "[$operation] User set for connections: $linuxPrivMaintUser"
    $secstring = ConvertTo-SecureString $linuxPrivMaintPass -AsPlainText -Force
    $sshCred = New-Object System.Management.Automation.PsCredential($linuxPrivMaintUser, $secstring)

    foreach($linuxAgentName in $linuxAgentNames){

        signLinuxAgentCert -computernames $linuxAgentName -SSHCreds $sshCred
    }

}


if($operation -contains 'AddAgentToMG'){


    $SCXSSHCred = Get-SCXSSHCredentialFromScript -UserName $linuxPrivMaintUser -Passphrase $linuxPrivMaintPass -SSHKeyFile $null -SuPassword $null -ElevationType sudo 
    $res1 = invoke-SCOMDiscovery -computernames $linuxAgentNames -SCXSSHCred $SCXSSHCred -LinuxPoolName $DefaulLinuxPoolName 
    $res1 
}

if($operation -contains 'RemoveAgentFromOldMG'){

    $module = Import-Module OperationsManager  -PassThru -UseWindowsPowerShell
    if(!$module){write-error "Missing required module 'operationsManager', is SCOM console installed here?";break;return;}
    $sess = Get-PSSession | ?{$_.name -eq "WinPSCompatSession"} | select -first 1

    Invoke-Command -Session $sess -ScriptBlock {

        #. $using:configFilePath
        # If you want to use this remotely – change “localhost” above to the FQDN of your SCOM server:
        
        try{
        new-SCOMManagementGroupConnection -ComputerName $using:OldMSServer |Set-SCOMManagementGroupConnection

        write-host "[$RemoveAgentFromMG] Starting operation "
        foreach($linuxAgentName in $using:linuxAgentNames){

            try{
                $linuxAgent = Get-SCXAgent -Name $linuxAgentName
                if(!$linuxAgent){write-error "No Linux agent found named: $linuxAgent" -ea stop}
                
                Remove-SCXAgent -Agent $linuxAgent
            }catch{
                write-error $_
                continue
            }

        }

        }catch{write-error $_}
    }
} 

Stop-Transcript