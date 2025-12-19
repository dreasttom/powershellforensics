<#
.SYNOPSIS
  Creates a bit-by-bit (sector-level) image of a physical disk.

.WARNING
  RUN AS ADMINISTRATOR.
  VERIFY THE DISK NUMBER CAREFULLY.

NOTE: THIS IS DANGEROUS BE CAREFUL
You must run PowerShell as Administrator
Selecting the wrong disk can destroy data
This copies unused space, deleted data, slack space, and errors
The destination must have free space ≥ source disk size
This is forensic-style imaging, not backup software
Before running this:
Get-Disk | Format-Table Number, FriendlyName, SerialNumber, Size
#>

# ================== CONFIGURATION ==================
$DiskNumber = 1                      # CHANGE THIS (e.g. 0, 1, 2)
$OutputImage = "D:\DiskImages\disk1.img"
$BlockSize = 1MB                     # Read/write block size
# ===================================================

$devicePath = "\\.\PhysicalDrive$DiskNumber"

Write-Host "Source disk : $devicePath"
Write-Host "Output file : $OutputImage"
Write-Host "Block size  : $BlockSize"
Write-Host ""
Write-Host "!!! PRESS CTRL+C NOW IF THIS IS NOT CORRECT !!!" -ForegroundColor Red
Start-Sleep -Seconds 5

# Open source disk (read-only)
$sourceStream = New-Object System.IO.FileStream(
    $devicePath,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::ReadWrite
)

# Open destination image file
$destStream = New-Object System.IO.FileStream(
    $OutputImage,
    [System.IO.FileMode]::Create,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None
)

$diskSize = $sourceStream.Length
$buffer = New-Object byte[] $BlockSize
$totalRead = 0
$startTime = Get-Date

try {
    while ($true) {
        $bytesRead = $sourceStream.Read($buffer, 0, $buffer.Length)
        if ($bytesRead -le 0) { break }

        $destStream.Write($buffer, 0, $bytesRead)
        $totalRead += $bytesRead

        $percent = [math]::Round(($totalRead / $diskSize) * 100, 2)
        Write-Progress `
            -Activity "Imaging disk $DiskNumber" `
            -Status "$percent% complete" `
            -PercentComplete $percent
    }
}
finally {
    $sourceStream.Close()
    $destStream.Close()
}

$elapsed = (Get-Date) - $startTime

Write-Host ""
Write-Host "Imaging complete." -ForegroundColor Green
Write-Host ("Bytes copied : {0:N0}" -f $totalRead)
Write-Host ("Disk size   : {0:N0}" -f $diskSize)
Write-Host ("Time taken  : {0}" -f $elapsed)
