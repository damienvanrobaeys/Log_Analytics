#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = ""
$SharedKey = ''
$LogType = "TestReport"
$TimeStampField = ""
#***********************************************************************************************************

# Log analytics functions
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}


# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

$Current_User_Profile = Get-ChildItem Registry::\HKEY_USERS | Where-Object { Test-Path "$($_.pspath)\Volatile Environment" } | ForEach-Object { (Get-ItemProperty "$($_.pspath)\Volatile Environment").USERPROFILE }
$Username = $Current_User_Profile.split("\")[2]		
$WMI_computersystem = gwmi win32_computersystem
$Manufacturer = $WMI_computersystem.manufacturer
If($Manufacturer -eq "Lenovo")
	{
		$Get_Current_Model = $WMI_computersystem.SystemFamily.split(" ")[1]
	}
Else
	{
		$Get_Current_Model = $WMI_computersystem.Model
	}
	
$Get_Current_Model_MTM = ($WMI_computersystem.Model).Substring(0,4)
$Get_Current_Model_FamilyName = $WMI_computersystem.SystemFamily.split(" ")[1]		
$BIOS_Version = (gwmi win32_bios).SMBIOSBIOSVersion

# Get Hard disk size info
$Win32_LogicalDisk = Get-ciminstance Win32_LogicalDisk | where {$_.DeviceID -eq "C:"}
$Disk_Full_Size = $Win32_LogicalDisk.size
$Disk_Free_Space = $Win32_LogicalDisk.Freespace

# Hard disk size percent
[int]$Free_DiskPercent = '{0:N0}' -f (($Disk_Free_Space / $Disk_Full_Size * 100),1)                                                          

# Hard disk size Log Anaytics format
$Disk_Size = ([System.Math]::Round(($Disk_Full_Size) / 1MB, 2))
$Free_DiskSpace = ([System.Math]::Round(($Disk_Free_Space) / 1MB, 2))

# Bitlocker status
$Bitlocker_status = (Get-BitLockerVolume -MountPoint "c:").protectionstatus
If($Bitlocker_status -eq "On")
	{
		$Bitlocker_status = "Enabled"
	}
Else
	{
		$Bitlocker_status = "Disabled"	
	}
	
# Create the object
$Properties = [Ordered] @{
    "Computer"     = $env:computername
    "UserName"             = $Username
    "Vendor"     = $Manufacturer	
    "DeviceModel"            = $Get_Current_Model
	"BIOSVer"      = $BIOS_Version
	"DiskSize"     = $Disk_Size	
	"FreeDisk"    = $Free_DiskSpace	
	"FreeDiskPercentage"  = $Free_DiskPercent		
	"BitlockerStatus" = $Bitlocker_status			
}
$DeviceInfo = New-Object -TypeName "PSObject" -Property $Properties

$DeviceInfoJson = $DeviceInfo | ConvertTo-Json

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($DeviceInfoJson))
    LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params
	
