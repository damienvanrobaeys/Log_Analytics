$Custom_Logs = "MEMSummit1"
$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$TimeStampField = ""


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

$Test_LA_File = ".\BIOS_Lab.csv"
# $Test_LA_CSV = import-csv $Test_LA_File


$Get_CSV_FirstLine = Get-Content $Test_LA_File | Select -First 1
$Get_Delimiter = If($Get_CSV_FirstLine.Split(";").Length -gt 1){";"}Else{","};
$Test_LA_CSV = import-csv $Test_LA_File -Delimiter $Get_Delimiter	


$InfoToImport_Json = $Test_LA_CSV | ConvertTo-Json

$params = @{
	CustomerId = $customerId
	SharedKey  = $sharedKey
	Body       = ([System.Text.Encoding]::UTF8.GetBytes($InfoToImport_Json))
	LogType    = $Custom_Logs 
}
$LogResponse = Post-LogAnalyticsData @params	