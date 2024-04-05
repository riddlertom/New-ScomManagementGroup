param(
		[Int64]$TotalFreeSpace = 400GB,
		$formatter = 1GB, #enter '1' to get raw bytes
		$opsDBDriveSize #Overrides $TotalFreeSpace
	)

Function computeSCOMDbSqlDriveSizes {
    #This function helps determine SQL drive sizes for placing databases in proper locations
	#Given a chunk of free space, maximally use the storage
	#doesn't include backup drive space.
	#https://learn.microsoft.com/en-us/archive/technet-wiki/53582.system-center-operations-manager-scom-management-group-performance-optimizations
	# The sizing tool can help with projecting expected db sizes based on agents.
	#https://techcommunity.microsoft.com/t5/system-center-blog/operations-manager-2012-sizing-helper-tool/ba-p/345075
	#Note: Datawarehouse is expected to be a seaparate server with its own drives.
	param(
		[Int64]$TotalFreeSpace = 400GB,
		$formatter = 1GB, #enter '1' to get raw bytes
		$opsDBDriveSize #Overrides $TotalFreeSpace
	)	
	
	$magicNumber = 0.588235293 #given 2 drives with known percentages of the first, what is the first?
	
	if($opsDBDriveSize){
		$opsDBDrive = $opsDBDriveSize
	}else{
		$opsDBDrive = $TotalFreeSpace * $magicNumber 
	}	
	
	$tempdbnLogDrive = $opsDBDrive * .2
	$opsDbUserLogDrive = $opsDBDrive * .5
	
	#expand to include leftover space
	if(!$opsDBDriveSize){
		$totalDriveSpaceSum = $opsDBDrive + $tempdbnLogDrive + $opsDbUserLogDrive;
		$addtoOps = $TotalFreeSpace - $totalDriveSpaceSum
		$opsDBDrive = $opsDBDrive + $addtoOps
	}
	
	$totalDriveSpaceSum2 = $opsDBDrive + $tempdbnLogDrive + $opsDbUserLogDrive;
	if($opsDBDriveSize){
		$LeftOverFreeSpace = 0
	}else{$LeftOverFreeSpace = $TotalFreeSpace - $totalDriveSpaceSum2}
	
	$opsdwhMagicNumber = 0.337 #from sizing calculator
	$OpsDWHUserDriveSpace = 4* $opsDBDrive / $opsdwhMagicNumber
	
	$OpsDWHUserDrive = $OpsDWHUserDriveSpace;
	$OpsDWHUserLogDrive = $OpsDWHUserDriveSpace * .10;
	$OpsDWHtempdbnLogDrive = $OpsDWHUserDriveSpace * .20;
	$totalDWHDriveSpaceSum = $OpsDWHUserDrive + $OpsDWHUserLogDrive + $OpsDWHtempdbnLogDrive
	
	$hash = [ordered]@{'opsDBDrive' = $opsDBDrive;
		'OpsDbtempdbnLogDrive' = $tempdbnLogDrive;
		'opsDbUserLogDrive' = $opsDbUserLogDrive;
		'totalOpsDbDriveSpaceSum' =  $totalDriveSpaceSum2;
		'OriginalFreeSpace' = $TotalFreeSpace;
		'LeftOverFreeSpace' = $LeftOverFreeSpace;
		'OpsMgrBackupDrive' = $null;
		'OpsDWHbackupDrive' = $null;
		'OpsDWHUserDrive' = $OpsDWHUserDrive;
		'OpsDWHUserLogDrive' = $OpsDWHUserLogDrive;
		'OpsDWHtempdbnLogDrive' = $OpsDWHtempdbnLogDrive;
		'totalDWHDriveSpaceSum' = $totalDWHDriveSpaceSum;
	}
	
	$keys = $hash.Keys | %{"$_"}
	foreach($key in $keys){$hash.$key = ($hash.$key / $formatter)}
	
	[pscustomobject]$hash
}
#computeSCOMDbSqlDriveSizes
#$a=get-disk | select -First 1
#computeSCOMDbSqlDriveSizes -TotalFreeSpace #$a.LargestFreeExtent
#computeSCOMDbSqlDriveSizes 
computeSCOMDbSqlDriveSizes -TotalFreeSpace $TotalFreeSpace  -formatter $formatter -opsDBDriveSize $opsDBDriveSize 

<#
computeSCOMDbSqlDriveSizes -opsDBDriveSize 32GB -TotalFreeSpace $null

    opsDBDrive              : 32
    OpsDbtempdbnLogDrive    : 6.4
    opsDbUserLogDrive       : 16
    totalOpsDbDriveSpaceSum : 54.4
    OriginalFreeSpace       : 0
    LeftOverFreeSpace       : 0
    OpsMgrBackupDrive       : 0
    OpsDWHbackupDrive       : 0
    OpsDWHUserDrive         : 379.821958456973
    OpsDWHUserLogDrive      : 37.9821958456973
    OpsDWHtempdbnLogDrive   : 75.9643916913947
    totalDWHDriveSpaceSum   : 493.768545994065

computeSCOMDbSqlDriveSizes -TotalFreeSpace 400GB

    opsDBDrive              : 235.29411796
    OpsDbtempdbnLogDrive    : 47.05882344
    opsDbUserLogDrive       : 117.6470586
    totalOpsDbDriveSpaceSum : 400
    OriginalFreeSpace       : 400
    LeftOverFreeSpace       : 0
    OpsMgrBackupDrive       : 0
    OpsDWHbackupDrive       : 0
    OpsDWHUserDrive         : 2792.80852178042
    OpsDWHUserLogDrive      : 279.280852178042
    OpsDWHtempdbnLogDrive   : 558.561704356083
    totalDWHDriveSpaceSum   : 3630.65107831454
#>