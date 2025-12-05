<#
.SYNOPSIS
    Lists USB devices found in the Windows registry.

.DESCRIPTION
    Enumerates:
      - HKLM:\SYSTEM\CurrentControlSet\Enum\USB
      - HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR

    For each device instance, it pulls common properties like:
      FriendlyName, DeviceDesc, Mfg, Service, Class, ClassGuid,
      HardwareID, CompatibleIDs, and a best-effort SerialNumber
      based on the leaf key name.
#>

$usbPaths = @(
    'HKLM:\SYSTEM\CurrentControlSet\Enum\USB',
    'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
)

$devices = foreach ($root in $usbPaths) {

    if (-not (Test-Path $root)) {
        Write-Verbose "Path not found: $root"
        continue
    }

    Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $key = $_

        # Try to read properties for this key
        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        if (-not $props) { return }

        # Best-effort serial number: last segment of the full key path
        $serial = ($key.Name -split '\\')[-1]

        # HardwareID and CompatibleIDs are usually string arrays
        $hwIds  = $props.HardwareID
        $compIds = $props.CompatibleIDs

        [PSCustomObject]@{
            RootPath      = $root
            RegistryKey   = ($key.Name -replace '^HKEY_LOCAL_MACHINE', 'HKLM')
            DeviceID      = $key.PSChildName
            FriendlyName  = $props.FriendlyName
            DeviceDesc    = $props.'DeviceDesc'
            Manufacturer  = $props.Mfg
            Service       = $props.Service
            Class         = $props.Class
            ClassGuid     = $props.ClassGuid
            HardwareID    = if ($hwIds) { $hwIds -join ', ' } else { $null }
            CompatibleIDs = if ($compIds) { $compIds -join ', ' } else { $null }
            SerialNumber  = $serial
            LastWriteTime = $key.LastWriteTime
        }
    }
}

# Show in a readable table
$devices |
    Sort-Object RootPath, DeviceDesc, FriendlyName |
    Format-Table RootPath, FriendlyName, DeviceDesc, Manufacturer, SerialNumber, LastWriteTime -AutoSize

# Optional: also export to CSV
# $devices | Export-Csv -Path '.\UsbDevicesFromRegistry.csv' -NoTypeInformation -Encoding UTF8
