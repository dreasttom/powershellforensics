<#
.SYNOPSIS
  Extracts network configuration from the Windows Registry and prints it in a human-friendly format.

.IMPROVEMENTS
  - Converts NetworkList profile DateCreated/DateLastConnected from FILETIME -> local human-readable timestamp.
  - Formats REG_MULTI_SZ, REG_BINARY, REG_DWORD/REG_QWORD cleanly.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-FileTimeBytesToLocalString {
    param([byte[]]$Bytes)
    try {
        if ($null -eq $Bytes -or $Bytes.Length -ne 8) { return $null }
        $ticks = [BitConverter]::ToInt64($Bytes, 0)
        if ($ticks -le 0) { return $null }
        # Convert from FILETIME (100-ns intervals since 1601-01-01 UTC)
        return ([DateTime]::FromFileTimeUtc($ticks)).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
    } catch { return $null }
}

function Convert-ValueToReadable {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    # REG_MULTI_SZ
    if ($Value -is [string[]]) {
        return ($Value -join ', ')
    }

    # REG_BINARY (byte[])
    if ($Value -is [byte[]]) {
        # If it looks like a FILETIME, show as a date too
        $ft = Convert-FileTimeBytesToLocalString -Bytes $Value
        if ($ft) { return $ft }

        # Otherwise show hex, trimmed if long
        $hex = ($Value | ForEach-Object { $_.ToString('X2') }) -join ' '
        if ($hex.Length -gt 120) { $hex = $hex.Substring(0, 120) + ' ...' }
        return $hex
    }

    # Numbers (DWORD/QWORD) -> show as decimal
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64]) {
        return [string]$Value
    }

    # Default: string / other types
    return [string]$Value
}

function Try-GetRegValueReadable {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )
    try {
        $v = (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name
        return (Convert-ValueToReadable $v)
    } catch {
        return $null
    }
}

function Convert-Category {
    param([int]$Category)
    switch ($Category) {
        0 { "Public" }
        1 { "Private" }
        2 { "DomainAuthenticated" }
        default { "Unknown($Category)" }
    }
}

Write-Host "=== Network Registry Summary (Human Readable) ===" -ForegroundColor Cyan
Write-Host ("Computer: {0}" -f $env:COMPUTERNAME)
Write-Host ("User:     {0}" -f $env:USERNAME)
Write-Host ""

# --- 1) Adapters (Class GUID for Network Adapters)
$adapterClass = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
Write-Host "=== Adapters (Registry Class) ===" -ForegroundColor Cyan

if (Test-Path $adapterClass) {
    $adapterKeys = Get-ChildItem -Path $adapterClass -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^\d{4}$' } |
        Sort-Object { [int]$_.PSChildName }

    foreach ($k in $adapterKeys) {
        $p = "Registry::$($k.Name)"
        $desc   = Try-GetRegValueReadable -Path $p -Name 'DriverDesc'
        $netCfg = Try-GetRegValueReadable -Path $p -Name 'NetCfgInstanceId'
        $svc    = Try-GetRegValueReadable -Path $p -Name 'Service'
        $mfg    = Try-GetRegValueReadable -Path $p -Name 'Manufacturer'

        if (-not $desc -and -not $netCfg -and -not $svc) { continue }

        Write-Host ""
        Write-Host "Adapter Key: $($k.PSChildName)" -ForegroundColor Yellow
        if ($desc)  { Write-Host "  Name:              $desc" }
        if ($mfg)   { Write-Host "  Manufacturer:      $mfg" }
        if ($svc)   { Write-Host "  Service:           $svc" }
        if ($netCfg){ Write-Host "  NetCfgInstanceId:  $netCfg" }
    }
} else {
    Write-Host "Adapter class key not found: $adapterClass"
}
Write-Host ""

# --- 2) TCP/IP Interfaces (IPv4)
$tcpipIfBase = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
Write-Host "=== TCP/IP Interfaces (IPv4) ===" -ForegroundColor Cyan

if (Test-Path $tcpipIfBase) {
    $ifKeys = Get-ChildItem -Path $tcpipIfBase -ErrorAction SilentlyContinue
    foreach ($k in $ifKeys) {
        $p = "Registry::$($k.Name)"
        $guid = $k.PSChildName

        $dhcpEnabled = Try-GetRegValueReadable -Path $p -Name 'EnableDHCP'
        $ipAddr      = Try-GetRegValueReadable -Path $p -Name 'IPAddress'
        $subnetMask  = Try-GetRegValueReadable -Path $p -Name 'SubnetMask'
        $gateway     = Try-GetRegValueReadable -Path $p -Name 'DefaultGateway'
        $dns         = Try-GetRegValueReadable -Path $p -Name 'NameServer'
        $dhcpIp      = Try-GetRegValueReadable -Path $p -Name 'DhcpIPAddress'
        $dhcpMask    = Try-GetRegValueReadable -Path $p -Name 'DhcpSubnetMask'
        $dhcpGw      = Try-GetRegValueReadable -Path $p -Name 'DhcpDefaultGateway'
        $dhcpDns     = Try-GetRegValueReadable -Path $p -Name 'DhcpNameServer'
        $domain      = Try-GetRegValueReadable -Path $p -Name 'Domain'
        $searchList  = Try-GetRegValueReadable -Path $p -Name 'SearchList'
        $mtu         = Try-GetRegValueReadable -Path $p -Name 'MTU'
        $hostname    = Try-GetRegValueReadable -Path $p -Name 'HostName'

        $hasSomething =
            $dhcpEnabled -ne $null -or $ipAddr -or $dhcpIp -or $gateway -or $dns -or $domain -or $searchList -or $mtu -or $hostname
        if (-not $hasSomething) { continue }

        Write-Host ""
        Write-Host "Interface GUID: $guid" -ForegroundColor Yellow

        if ($hostname)   { Write-Host "  HostName:          $hostname" }
        if ($domain)     { Write-Host "  Domain:            $domain" }
        if ($searchList) { Write-Host "  SearchList:        $searchList" }
        if ($mtu)        { Write-Host "  MTU:               $mtu" }

        if ($dhcpEnabled -ne $null) {
            $dhcpText = if ([int]$dhcpEnabled -eq 1) { "Enabled" } else { "Disabled" }
            Write-Host "  DHCP:              $dhcpText"
        }

        if ($ipAddr)     { Write-Host "  Static IP:         $ipAddr" }
        if ($subnetMask) { Write-Host "  Static Mask:       $subnetMask" }
        if ($gateway)    { Write-Host "  Static Gateway:    $gateway" }
        if ($dns)        { Write-Host "  Static DNS:        $dns" }

        if ($dhcpIp)     { Write-Host "  DHCP IP:           $dhcpIp" }
        if ($dhcpMask)   { Write-Host "  DHCP Mask:         $dhcpMask" }
        if ($dhcpGw)     { Write-Host "  DHCP Gateway:      $dhcpGw" }
        if ($dhcpDns)    { Write-Host "  DHCP DNS:          $dhcpDns" }
    }
} else {
    Write-Host "TCP/IP interface key not found: $tcpipIfBase"
}
Write-Host ""

# --- 3) TCP/IP Interfaces (IPv6)
$tcpip6IfBase = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces'
Write-Host "=== TCP/IP Interfaces (IPv6) ===" -ForegroundColor Cyan

if (Test-Path $tcpip6IfBase) {
    $ifKeys6 = Get-ChildItem -Path $tcpip6IfBase -ErrorAction SilentlyContinue
    foreach ($k in $ifKeys6) {
        $p = "Registry::$($k.Name)"
        $guid = $k.PSChildName

        $disabled = Try-GetRegValueReadable -Path $p -Name 'DisabledComponents'
        $addr     = Try-GetRegValueReadable -Path $p -Name 'IPAddress'
        $dns      = Try-GetRegValueReadable -Path $p -Name 'NameServer'

        if (-not ($disabled -or $addr -or $dns)) { continue }

        Write-Host ""
        Write-Host "Interface GUID: $guid" -ForegroundColor Yellow
        if ($disabled) { Write-Host "  DisabledComponents: $disabled" }
        if ($addr)     { Write-Host "  IPv6 Address(es):   $addr" }
        if ($dns)      { Write-Host "  IPv6 DNS:           $dns" }
    }
} else {
    Write-Host "TCP/IP6 interface key not found: $tcpip6IfBase"
}
Write-Host ""

# --- 4) Network Profiles (friendly names + human readable dates)
$profilesBase = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
Write-Host "=== Network Profiles (NetworkList) ===" -ForegroundColor Cyan

if (Test-Path $profilesBase) {
    $profiles = Get-ChildItem -Path $profilesBase -ErrorAction SilentlyContinue
    foreach ($k in $profiles) {
        $p = "Registry::$($k.Name)"
        $name = Try-GetRegValueReadable -Path $p -Name 'ProfileName'
        $desc = Try-GetRegValueReadable -Path $p -Name 'Description'
        $cat  = Try-GetRegValueReadable -Path $p -Name 'Category'
        $managed = Try-GetRegValueReadable -Path $p -Name 'Managed'

        # These are REG_BINARY FILETIMEs -> the helper will convert them automatically
        $created = Try-GetRegValueReadable -Path $p -Name 'DateCreated'
        $lastCon = Try-GetRegValueReadable -Path $p -Name 'DateLastConnected'

        if (-not $name -and -not $desc) { continue }

        Write-Host ""
        Write-Host "Profile: $($k.PSChildName)" -ForegroundColor Yellow
        if ($name) { Write-Host "  Name:           $name" }
        if ($desc) { Write-Host "  Description:    $desc" }
        if ($cat)  { Write-Host "  Category:       $(Convert-Category -Category ([int]$cat))" }
        if ($managed) { Write-Host "  Managed:        $managed" }
        if ($created) { Write-Host "  DateCreated:    $created" }
        if ($lastCon) { Write-Host "  LastConnected:  $lastCon" }
    }
} else {
    Write-Host "NetworkList profiles key not found: $profilesBase"
}
Write-Host ""

# --- 5) DNS Client NRPT (Policy) in readable form
$nrptBase = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig'
Write-Host "=== DNS Policy (NRPT) ===" -ForegroundColor Cyan

if (Test-Path $nrptBase) {
    $rules = Get-ChildItem -Path $nrptBase -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "NRPT key exists but no rules found."
    } else {
        foreach ($k in $rules) {
            $p = "Registry::$($k.Name)"
            Write-Host ""
            Write-Host "Rule: $($k.PSChildName)" -ForegroundColor Yellow

            $item = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            if ($null -eq $item) { continue }

            $props = $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(.*)$' }
            foreach ($prop in $props) {
                $readable = Convert-ValueToReadable $prop.Value
                if ($null -ne $readable -and $readable.Trim().Length -gt 0) {
                    Write-Host ("  {0,-22} {1}" -f ($prop.Name + ":"), $readable)
                }
            }
        }
    }
} else {
    Write-Host "NRPT policy key not found (this is normal on many systems)."
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
