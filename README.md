# Apache Access Logs Analytical Parser

A small, self-contained Apache access log analyzer for Windows. It uses a PowerShell script and a simple batch launcher to produce a Markdown report with geo analytics (country/city via Geoapify) and page analytics.

## Features

- Geo analytics by country and city (Geoapify IP Geolocation API)
- Page analytics: most-viewed pages (index.htm / index.html; also counts .htm/.html)
- ASCII bar charts rendered in Markdown tables
- Caches IP → Geo results to reduce API usage

## Prerequisites

- Windows with PowerShell 5.1+ (default on Windows)
- Geoapify API key (free tier available): https://www.geoapify.com/

## Quick Start

1. Download the ZIP of this GitHub repo and unzip anywhere.
2. Place your Apache access log files (`*.log`, `*.txt`) into the `logs` folder.
   - If the folder doesn't exist yet, run the script once; it will create `logs/` and ask you to re-run after adding files.
3. Double-click `run_report.bat`.
4. **Optional**: When prompted, enter a partial URL to filter analytics for a specific page (e.g., "2025EarthPartnerPrize"), or press Enter to analyze all pages.
5. If prompted, paste your Geoapify API key. The script will save it to `config.json`.
6. When done, open the generated report file in the `reports` folder (e.g., `reports/report_2025-11-01_to_2025-11-07.md`).

### Alternative: Run from PowerShell

```powershell
cd "d:\Projects\Apache-Access-Logs-Analytical-Parser"
powershell -ExecutionPolicy Bypass -File ".\Analyze-ApacheLog.ps1"
```

The script will interactively prompt you for:
1. **Page filter** (optional) - Enter a partial URL to analyze only specific pages, or press Enter to skip
2. **Geoapify API key** (if not already saved in `config.json`)

### Optional: Provide API key via environment variable

```powershell
$env:GEOAPIFY_API_KEY = "YOUR_GEOAPIFY_KEY"
powershell -ExecutionPolicy Bypass -File ".\Analyze-ApacheLog.ps1"
```

## Output Files

- **Report files** – Saved in the `reports/` folder with dynamic names based on the time period and page filter (if used):
  - `reports/report_2025-11-01_to_2025-11-07.md` (for logs spanning multiple days)
  - `reports/report_2025-11-27.md` (for logs from a single day)
  - `reports/report_2025-11-01_to_2025-11-07_2025EarthPartnerPrize.md` (when using page filter)
- `config.json` – stores your Geoapify API key
- `ip_cache.json` – caches IP → Country/City to reduce API calls

## Example Report Snippet

```md
# Apache Access Log Analytics

Generated at: 2025-11-27 13:00  
Log folder: ./logs  
Log files processed: 2

---

## 1. Overview

- Total requests: 4321
- Unique IPs: 987
- Time range: 2025-11-01 00:00:09 → 2025-11-07 23:59:59
- Parsed lines: 4300
- Skipped lines: 21

---

## 2. Top Countries

| Rank | Country | ISO | Unique IPs | Requests | Bar |
|------|---------|-----|------------|----------|-----|
| 1    | Germany | DE  | 120        | 3210     | ########## |
| 2    | France  | FR  |  95        | 2845     | #######    |

---

## 3. Top Cities

| Rank | Country | City      | Unique IPs | Requests |
|------|---------|-----------|------------|----------|
| 1    | Germany | Nuremberg | 45         | 350      |
| 2    | France  | Paris     | 38         | 290      |

---

## 4. Top Pages (index.htm / index.html)

| Rank | Page (Path)                             | Unique IPs | Pageviews | Bar        |
|------|-----------------------------------------|------------|-----------|------------|
| 1    | /EarthPartner/BorgoLaudatoSi/index.htm  | 123        |  9876     | ########## |
| 2    | /SomeOtherSite/index.html               |  45        |  1234     | ####       |

---

## 5. Notes

- Geo data powered by Geoapify IP Geolocation API.
- IP -> Geo results cached in ip_cache.json to reduce API usage.
```

## Troubleshooting

- "No log files found": Ensure your `*.log` or `*.txt` files are in the `logs` folder next to the script.
- API key prompt keeps appearing: If `config.json` is not writable, you can set the `GEOAPIFY_API_KEY` environment variable instead.
- Network/Proxy issues: If Geo lookup fails, the script will mark unknown locations and continue. Cached "Unknown" entries avoid repeated failing calls.

## Notes

- Paths are relative to the script location, so launching via `run_report.bat` is recommended.
- Pages include `index.htm`, `index.html`, and other `.htm`/`.html` files.
