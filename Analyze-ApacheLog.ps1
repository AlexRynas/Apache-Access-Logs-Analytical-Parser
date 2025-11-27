[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Determine script root and key paths
$ScriptRoot = Split-Path -Parent $PSCommandPath
$LogDir     = Join-Path $ScriptRoot "logs"
$ConfigPath = Join-Path $ScriptRoot "config.json"
$CachePath  = Join-Path $ScriptRoot "ip_cache.json"
$ReportPath = Join-Path $ScriptRoot "report.md"

# Helper: Write section header to console for user-friendly output
function Write-Info {
    param([string]$Message)
    Write-Host $Message
}

# 1) Ensure logs folder exists
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
    Write-Info "Created logs folder. Please put your Apache access logs into the logs folder and run the script again."
    exit 0
}

# 2) Collect log files
Write-Info "Reading logs from $LogDir..."
$logFiles = @()
try {
    $logFiles = @(Get-ChildItem -Path (Join-Path $LogDir '*.log'), (Join-Path $LogDir '*.txt') -File -ErrorAction SilentlyContinue)
} catch { $logFiles = @() }
if (-not $logFiles -or $logFiles.Count -eq 0) {
    Write-Info "No log files found in $LogDir. Place files (*.log, *.txt) and run again."
    exit 0
}

# 3) Config & Geoapify API key
function Get-GeoapifyApiKey {
    # Try config.json
    if (Test-Path -LiteralPath $ConfigPath) {
        try {
            $cfgRaw = Get-Content -LiteralPath $ConfigPath -Encoding UTF8 -ErrorAction Stop
            if ($cfgRaw) {
                $cfg = $cfgRaw | ConvertFrom-Json
                if ($cfg -and $cfg.GeoapifyApiKey -and $cfg.GeoapifyApiKey.Trim().Length -gt 0) {
                    return $cfg.GeoapifyApiKey.Trim()
                }
            }
        } catch { }
    }
    # Try environment variable
    $envKey = $env:GEOAPIFY_API_KEY
    if ($envKey -and $envKey.Trim().Length -gt 0) {
        return $envKey.Trim()
    }
    # Prompt user and save
    $apiKey = Read-Host "Enter your Geoapify API key (you can get it from geoapify.com)"
    if (-not $apiKey -or $apiKey.Trim().Length -eq 0) {
        throw "Geoapify API key is required to proceed."
    }
    $obj = [PSCustomObject]@{ GeoapifyApiKey = $apiKey.Trim() }
    try {
        $json = $obj | ConvertTo-Json -Depth 3
        Set-Content -LiteralPath $ConfigPath -Value $json -Encoding UTF8
    } catch { }
    return $apiKey.Trim()
}

# 4) Parsing Apache access logs (combined format)
function Parse-ApacheLogLine {
    param([string]$Line)
    if (-not $Line) { return $null }

    $pattern = '^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<time>[^\]]+)\]\s+"(?<method>\S+)\s+(?<url>\S+)\s+(?<protocol>[^"]+)"\s+(?<status>\d{3})\s+(?<bytes>\S+)\s+"(?<referrer>[^"]*)"\s+"(?<agent>[^"]*)"'
    $m = [System.Text.RegularExpressions.Regex]::Match($Line, $pattern)
    if (-not $m.Success) { return $null }

    $ip        = $m.Groups['ip'].Value
    $rawTime   = $m.Groups['time'].Value
    $method    = $m.Groups['method'].Value
    $rawUrl    = $m.Groups['url'].Value
    $protocol  = $m.Groups['protocol'].Value
    $statusStr = $m.Groups['status'].Value
    $bytesStr  = $m.Groups['bytes'].Value
    $referrer  = $m.Groups['referrer'].Value
    $agent     = $m.Groups['agent'].Value

    $statusCode = 0
    [void][int]::TryParse($statusStr, [ref]$statusCode)

    $bytesSent = 0
    if ($bytesStr -and $bytesStr -ne '-') { [void][int]::TryParse($bytesStr, [ref]$bytesSent) }

    # Timestamp parsing; leave null if fails
    $timestamp = $null
    try {
        $timestamp = [DateTime]::ParseExact($rawTime, "dd/MMM/yyyy:HH:mm:ss zzz", [System.Globalization.CultureInfo]::InvariantCulture)
    } catch {
        $timestamp = $null
    }

    # Extract path without query string
    $path = $rawUrl
    try {
        $uri = $null
        if ([Uri]::TryCreate($rawUrl, [UriKind]::Absolute, [ref]$uri)) {
            $path = $uri.AbsolutePath
        } else {
            [Uri]::TryCreate(("http://dummy" + $rawUrl), [UriKind]::Absolute, [ref]$uri) | Out-Null
            if ($uri) { $path = $uri.AbsolutePath }
        }
    } catch { }

    [PSCustomObject]@{
        IpAddress  = $ip
        Timestamp  = $timestamp
        Method     = $method
        Url        = $rawUrl
        Path       = $path
        Protocol   = $protocol
        StatusCode = $statusCode
        BytesSent  = $bytesSent
        Referrer   = $referrer
        UserAgent  = $agent
    }
}

# 5) IP cache load/save
function Load-IpCache {
    if (-not (Test-Path -LiteralPath $CachePath)) { return @{} }
    try {
        $raw = Get-Content -LiteralPath $CachePath -Encoding UTF8 -ErrorAction Stop
        if (-not $raw) { return @{} }
        $json = $raw | ConvertFrom-Json
        if (-not $json) { return @{} }
        $ht = @{}
        foreach ($p in $json.PSObject.Properties) {
            $v = $p.Value
            $countryName = if ($v -and $v.CountryName) { $v.CountryName } else { "Unknown" }
            $countryCode = if ($v -and $v.CountryCode) { $v.CountryCode } else { "" }
            $cityName    = if ($v -and $v.CityName)    { $v.CityName }    else { "Unknown" }
            $ht[$p.Name] = [PSCustomObject]@{ CountryName = $countryName; CountryCode = $countryCode; CityName = $cityName }
        }
        return $ht
    } catch {
        return @{}
    }
}

function Save-IpCache {
    param([hashtable]$IpCache)
    $obj = New-Object PSObject
    foreach ($key in $IpCache.Keys) {
        $v = $IpCache[$key]
        $obj | Add-Member -NotePropertyName $key -NotePropertyValue ([PSCustomObject]@{
            CountryName = if ($v.CountryName) { $v.CountryName } else { "Unknown" }
            CountryCode = if ($v.CountryCode) { $v.CountryCode } else { "" }
            CityName    = if ($v.CityName)    { $v.CityName }    else { "Unknown" }
        })
    }
    $json = $obj | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $CachePath -Value $json -Encoding UTF8
}

# 6) Geo lookup function (Geoapify IP Geolocation API)
function Get-GeoInfoForIP {
    param(
        [Parameter(Mandatory=$true)][string]$IpAddress,
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [Parameter(Mandatory=$true)][hashtable]$IpCache
    )
    if ($IpCache.ContainsKey($IpAddress)) { return $IpCache[$IpAddress] }

    $url = "https://api.geoapify.com/v1/ipinfo?ip=$IpAddress&apiKey=$ApiKey"
    $countryName = "Unknown"
    $countryCode = ""
    $cityName    = "Unknown"
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop -TimeoutSec 20
        if ($response) {
            if ($response.country -and $response.country.name) { $countryName = $response.country.name }
            if ($response.country -and $response.country.iso_code) { $countryCode = $response.country.iso_code }
            if ($response.city    -and $response.city.name)    { $cityName    = $response.city.name }
        }
    } catch {
        # Leave Unknowns; avoid repeated failing calls by caching Unknown
    }
    $info = [PSCustomObject]@{ CountryName = $countryName; CountryCode = $countryCode; CityName = $cityName }
    $IpCache[$IpAddress] = $info
    Start-Sleep -Milliseconds 150
    return $info
}

# 7) ASCII bar chart helper
function New-Bar {
    param(
        [int]$Value,
        [int]$Max,
        [int]$MaxWidth = 30
    )
    if ($Max -le 0 -or $Value -le 0) { return "" }
    $ratio = [double]$Value / [double]$Max
    $length = [Math]::Max(1, [Math]::Round($ratio * $MaxWidth))
    return ('#' * $length)
}

# 8) Read and parse logs
$entries = @()
$parsedLines = 0
$skippedLines = 0
foreach ($file in $logFiles) {
    foreach ($line in Get-Content -LiteralPath $file.FullName -Encoding UTF8) {
        $e = Parse-ApacheLogLine -Line $line
        if ($null -ne $e) { $entries += $e; $parsedLines++ } else { $skippedLines++ }
    }
}
Write-Info "Parsed $parsedLines entries from $($logFiles.Count) files, skipped $skippedLines lines."
if ($entries.Count -eq 0) {
    Write-Info "No valid entries parsed. Ensure logs are in Apache combined format."
    exit 0
}

# 9) Determine pages and page keys
foreach ($e in $entries) {
    $isPage = $false
    $pageKey = $null
    if ($e.Path) {
        $lower = $e.Path.ToLowerInvariant()
        if ($lower.EndsWith('/index.htm') -or $lower.EndsWith('/index.html')) {
            $isPage = $true
            $pageKey = $e.Path
        } elseif ($lower.EndsWith('.htm') -or $lower.EndsWith('.html')) {
            # Optional: count other .htm/.html as pages too
            $isPage = $true
            $pageKey = $e.Path
        }
    }
    $e | Add-Member -MemberType NoteProperty -Name IsPage -Value $isPage
    $e | Add-Member -MemberType NoteProperty -Name PageKey -Value $pageKey
}

# 10) Geoapify API key and IP geo resolution
$apiKey = Get-GeoapifyApiKey
$ipCache = Load-IpCache
$uniqueIps = $entries | Select-Object -ExpandProperty IpAddress | Sort-Object -Unique
Write-Info "Resolving geo information for $($uniqueIps.Count) unique IPs (using Geoapify)..."
foreach ($ip in $uniqueIps) { [void](Get-GeoInfoForIP -IpAddress $ip -ApiKey $apiKey -IpCache $ipCache) }
Save-IpCache -IpCache $ipCache

# Attach geo info to each entry
foreach ($e in $entries) {
    $ip = $e.IpAddress
    $info = $null
    if ($ipCache.ContainsKey($ip)) { $info = $ipCache[$ip] }
    if ($null -eq $info) { $info = [PSCustomObject]@{ CountryName = "Unknown"; CountryCode = ""; CityName = "Unknown" } }
    $e | Add-Member -MemberType NoteProperty -Name CountryName -Value ($info.CountryName)
    $e | Add-Member -MemberType NoteProperty -Name CountryCode -Value ($info.CountryCode)
    $e | Add-Member -MemberType NoteProperty -Name CityName    -Value ($info.CityName)
}

# 11) Aggregations
# Overview
$totalRequests   = $entries.Count
$uniqueIpsCount  = $uniqueIps.Count
$timestamps      = $entries | Select-Object -ExpandProperty Timestamp | Where-Object { $_ -ne $null } | Sort-Object
$startTime       = if ($timestamps.Count -gt 0) { $timestamps[0] } else { $null }
$endTime         = if ($timestamps.Count -gt 0) { $timestamps[$timestamps.Count-1] } else { $null }

# Countries
$countryStats = @()
foreach ($g in ($entries | Group-Object -Property CountryName)) {
    $country = if ($g.Name) { $g.Name } else { "Unknown" }
    $code    = ($g.Group | Where-Object { $_.CountryCode } | Select-Object -ExpandProperty CountryCode -First 1)
    $req     = $g.Count
    $uniqIps = ($g.Group | Select-Object -ExpandProperty IpAddress | Sort-Object -Unique).Count
    $countryStats += [PSCustomObject]@{ CountryName = $country; CountryCode = $code; Requests = $req; UniqueIps = $uniqIps }
}
$countryStats = $countryStats | Sort-Object -Property Requests -Descending
$maxCountryRequests = if ($countryStats.Count -gt 0) { ($countryStats | Select-Object -ExpandProperty Requests | Measure-Object -Maximum).Maximum } else { 0 }
$topCountry = if ($countryStats.Count -gt 0) { $countryStats[0] } else { $null }

# Cities
foreach ($e in $entries) {
    if (-not $e.CountryName) { $e.CountryName = "Unknown" }
    if (-not $e.CityName)    { $e.CityName    = "Unknown" }
    $e | Add-Member -MemberType NoteProperty -Name CountryCityKey -Value ($e.CountryName + "|" + $e.CityName)
}
$cityStats = @()
foreach ($g in ($entries | Group-Object -Property CountryCityKey)) {
    $parts = $g.Name.Split('|')
    $country = if ($parts.Length -ge 1) { $parts[0] } else { "Unknown" }
    $city    = if ($parts.Length -ge 2) { $parts[1] } else { "Unknown" }
    $req     = $g.Count
    $uniqIps = ($g.Group | Select-Object -ExpandProperty IpAddress | Sort-Object -Unique).Count
    $cityStats += [PSCustomObject]@{ CountryName = $country; CityName = $city; Requests = $req; UniqueIps = $uniqIps }
}
$cityStats = $cityStats | Sort-Object -Property Requests -Descending
$cityStatsTop = if ($cityStats.Count -gt 20) { $cityStats[0..19] } else { $cityStats }

# Pages (index.htm / index.html)
$pageEntries = $entries | Where-Object { $_.IsPage -eq $true -and $_.PageKey }
$pageStats = @()
foreach ($g in ($pageEntries | Group-Object -Property PageKey)) {
    $req     = $g.Count
    $uniqIps = ($g.Group | Select-Object -ExpandProperty IpAddress | Sort-Object -Unique).Count
    $pageStats += [PSCustomObject]@{ PageKey = $g.Name; Requests = $req; UniqueIps = $uniqIps }
}
$pageStats = $pageStats | Sort-Object -Property Requests -Descending
$maxPageRequests = if ($pageStats.Count -gt 0) { ($pageStats | Select-Object -ExpandProperty Requests | Measure-Object -Maximum).Maximum } else { 0 }
$pageStatsTop = if ($pageStats.Count -gt 20) { $pageStats[0..19] } else { $pageStats }
$topPage = if ($pageStats.Count -gt 0) { $pageStats[0] } else { $null }

# 12) Markdown report generation
Write-Info "Writing report to $ReportPath..."
$sb = New-Object System.Text.StringBuilder
$nowStr = (Get-Date).ToString('yyyy-MM-dd HH:mm')
$logCount = $logFiles.Count

[void]$sb.AppendLine('# Apache Access Log Analytics')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("Generated at: $nowStr  ")
[void]$sb.AppendLine("Log folder: ./logs  ")
[void]$sb.AppendLine("Log files processed: $logCount")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## 1. Overview')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("- Total requests: $totalRequests")
[void]$sb.AppendLine("- Unique IPs: $uniqueIpsCount")
if ($startTime -and $endTime) {
    [void]$sb.AppendLine("- Time range: " + $startTime.ToString('yyyy-MM-dd HH:mm:ss') + " → " + $endTime.ToString('yyyy-MM-dd HH:mm:ss'))
} else {
    [void]$sb.AppendLine("- Time range: Unknown")
}
[void]$sb.AppendLine("- Parsed lines: $parsedLines")
[void]$sb.AppendLine("- Skipped lines: $skippedLines")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')

# Top Countries
[void]$sb.AppendLine('## 2. Top Countries')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| Rank | Country | ISO | Unique IPs | Requests | Bar |')
[void]$sb.AppendLine('|------|---------|-----|------------|----------|-----|')
if ($countryStats.Count -gt 0) {
    $rank = 1
    foreach ($c in ($countryStats | Select-Object -First 10)) {
        $iso = if ($c.CountryCode) { $c.CountryCode } else { '' }
        $bar = New-Bar -Value $c.Requests -Max $maxCountryRequests -MaxWidth 30
        [void]$sb.AppendLine("| $rank    | $($c.CountryName) | $iso  | $($c.UniqueIps)        | $($c.Requests)     | $bar |")
        $rank++
    }
} else {
    [void]$sb.AppendLine('| (no data) | | | | | |')
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')

# Top Cities
[void]$sb.AppendLine('## 3. Top Cities')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| Rank | Country | City      | Unique IPs | Requests |')
[void]$sb.AppendLine('|------|---------|-----------|------------|----------|')
if ($cityStatsTop.Count -gt 0) {
    $rank = 1
    foreach ($ct in $cityStatsTop) {
        [void]$sb.AppendLine("| $rank    | $($ct.CountryName) | $($ct.CityName) | $($ct.UniqueIps)        | $($ct.Requests)     |")
        $rank++
    }
} else {
    [void]$sb.AppendLine('| (no data) | | | | |')
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')

# Top Pages
[void]$sb.AppendLine('## 4. Top Pages (index.htm / index.html)')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| Rank | Page (Path)                             | Unique IPs | Pageviews | Bar        |')
[void]$sb.AppendLine('|------|-----------------------------------------|------------|-----------|------------|')
if ($pageStatsTop.Count -gt 0) {
    $rank = 1
    foreach ($pg in $pageStatsTop) {
        $bar = New-Bar -Value $pg.Requests -Max $maxPageRequests -MaxWidth 30
        [void]$sb.AppendLine("| $rank    | $($pg.PageKey) | $($pg.UniqueIps)        |  $($pg.Requests)     | $bar |")
        $rank++
    }
} else {
    [void]$sb.AppendLine('| (no matching pages) | | | | |')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Note: No paths matched index.htm/index.html. If your site uses other page names, you can extend the script to include .htm/.html pages.')
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')

# Notes
[void]$sb.AppendLine('## 5. Notes')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('- Geo data powered by Geoapify IP Geolocation API.')
[void]$sb.AppendLine('- IP -> Geo results cached in ip_cache.json to reduce API usage.')

[System.IO.File]::WriteAllText($ReportPath, $sb.ToString(), [System.Text.Encoding]::UTF8)

Write-Info "Done. Open report.md in any text editor or on GitHub to view the analytics."