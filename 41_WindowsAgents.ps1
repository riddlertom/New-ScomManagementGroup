#Requires -Version 7 -RunAsAdministrator
<#
.SYNOPSIS
    Operations for SCOM Windows Agents


.DESCRIPTION

    $Operation:

        WINDOWS
        AddNewWinAgentMG - Adds the -NEW- SCOM MG and Server to the agents specified. This will dual home if -OLD- MG is present.
        RemoveNewWinAgentMG - Removes the -NEW- SCOM MG and Server to the agents specified.
        
        AddOldWinAgentMG - Adds the -OLD- SCOM MG and Server to the agents specified. This will dual home if -NEW- MG is present.
        RemoveOldWinAgentMG - Removes the -OLD- SCOM MG and Server to the agents specified.

        GetCurrentWinAgentMG - Dumps current MG info on Windows SCOM Agents
        

.NOTES
    Author: Tom Riddle
    Makes heavy use of windowsPowershell remoting, and SSH modules

.LINK
    https://github.com/riddlertom/New-ScomManagementGroup
#>
param(
    [ValidateSet('AddNewWinAgentMG','RemoveNewWinAgentMG','AddOldWinAgentMG','RemoveOldWinAgentMG','GetCurrentWinAgentMG')]
    [string[]]$Operation,

    [string]$configFilePath = "$PSScriptRoot\_config.ps1"
)




#region: Functions
###########################

Function Remove-SCOMManagementGroup {
    param(
     [parameter(mandatory=$true)]
     $ManagementGroup,
     $ComputerName = "Localhost"
    )
    $sb = {
     param($ManagementGroup, 
       $ComputerName = "Localhost")
     Try {
      $OMCfg = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
     } catch {
      throw "$ComputerName doesn't have the SCOM agent installed"
     }
     $mgs = $OMCfg.GetManagementGroups() | %{$_.managementGroupName}
     if ($mgs -contains $ManagementGroup) {
      $OMCfg.RemoveManagementGroup($ManagementGroup)
      $OMCfg.reloadconfiguration()
      return "$ManagementGroup removed from $ComputerName"
     } else {
      return "$ComputerName does not report to $ManagementGroup"
     }
    }
    Invoke-Command -ScriptBlock $sb -ComputerName $ComputerName -ArgumentList @($ManagementGroup,$ComputerName) 
}

Function Add-SCOMManagementGroup {
param(
    [parameter(mandatory=$true)]
    $ManagementGroup,
    $ComputerName = "Localhost",
    $ManagementServer,
    [int]$port=5723
)
$sb = {
    $ManagementGroup = $args[0]
    $ComputerName = $args[1]
    $ManagementServer = $args[2]
    $port = $args[3]
    
    
    Try {
    $OMCfg = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
    } catch {
    throw "$ComputerName doesn't have the SCOM agent installed"
    }
    $mgs = $OMCfg.GetManagementGroups() | %{$_.managementGroupName}
    if ($mgs -notcontains $ManagementGroup) {
    try{
    $OMCfg.AddManagementGroup($ManagementGroup,$ManagementServer,$port)
    $OMCfg.reloadconfiguration()
    return "$ManagementGroup added to $ComputerName"
    }catch{
    throw $_
    }
    
    } else {
    return "$ComputerName already reports to $ManagementGroup"
    }
}
Invoke-Command -ScriptBlock $sb -ComputerName $ComputerName -ArgumentList @($ManagementGroup,$ComputerName,$ManagementServer,$port)
}

Function Get-SCOMManagementGroup {
    param(
     [parameter(mandatory=$true)]
     $ComputerName = "Localhost"
    )
    $sb = {
     param($ManagementGroup, 
       $ComputerName = "Localhost")
     Try {
      $OMCfg = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
     } catch {
      throw "$ComputerName doesn't have the SCOM agent installed"
     }
     $mgs = $OMCfg.GetManagementGroups() | %{$_.managementGroupName}
     return "$ComputerName contains MGs: $($mgs -join ',')"
     
    }
    Invoke-Command -ScriptBlock $sb -ComputerName $ComputerName -ArgumentList @($ManagementGroup,$ComputerName) 
}


#Add-SCOMManagementGroup -ManagementGroup "NEWMGNAME" -ComputerName @('server1','server2') -ManagementServer "NewManagmementServer1.Contoso.Com" -port 5723
#Remove-SCOMManagementGroup -ManagementGroup "OLDMGNAME" -ComputerName @('server1','server2')
#Get-SCOMManagementGroup -ComputerName @('server1','server2')

###########################
#endregion Functions


#region: INIT

$nullme = new-item -Path "$PSScriptRoot\Logs" -ItemType Directory 
Start-Transcript -Path ("$PSScriptRoot\Logs\$($script:MyInvocation.MyCommand.name).{0:MM-dd-yyyy_hh.mm.ss.mm}.log" -f (get-date))

#$domainJoinCred = New-Object System.Management.Automation.PsCredential($domainUser,$secstring)
if( !(Test-Path $configFilePath) ){write-error "Unable to find config file: $configFilePath"; pause;return;}
. $configFilePath



if(!$WindowsAgentNames){write-error "No windows agent names provided!";return}



#endregion



if($Operation -eq 'AddNewWinAgentMG'){

    if(!$SCOMMgmtGroup){write-error "No NEW SCOM MG name given";break}else{$NewWinAgentMG = $SCOMMgmtGroup}
    if(!$RMSServer){write-error "No NEW SCOM ManagementServer name given";break}

    Add-SCOMManagementGroup -ManagementGroup $NewWinAgentMG -ComputerName $WindowsAgentNames -ManagementServer $RMSServer -port 5723
}

if($Operation -eq 'RemoveNewWinAgentMG'){

    if(!$SCOMMgmtGroup){write-error "No NEW SCOM MG name given";break}else{$NewWinAgentMG = $SCOMMgmtGroup}

    Remove-SCOMManagementGroup -ManagementGroup $NewWinAgentMG -ComputerName $WindowsAgentNames 
}

if($Operation -eq 'AddOldWinAgentMG'){

    if(!$OldSCOMMgmtGroup){write-error "No OLD SCOM MG name given";break}else{$OldWinAgentMG = $OldSCOMMgmtGroup}
    if(!$OldMSServer){write-error "No OLD SCOM ManagementServer name given";break}

    Add-SCOMManagementGroup -ManagementGroup $OldWinAgentMG -ComputerName $WindowsAgentNames -ManagementServer $OldMSServer -port 5723
}

if($Operation -eq 'RemoveOldWinAgentMG'){

    if(!$OldSCOMMgmtGroup){write-error "No OLD SCOM MG name given";break}else{$OldWinAgentMG = $OldSCOMMgmtGroup}

    Remove-SCOMManagementGroup -ManagementGroup $OldWinAgentMG -ComputerName $WindowsAgentNames 
}

if($Operation -eq 'GetCurrentWinAgentMG'){

    Get-SCOMManagementGroup -ComputerName $WindowsAgentNames 
}

Stop-Transcript