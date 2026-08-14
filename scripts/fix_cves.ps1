# Fix CVE descriptions - fetch real data from NVD API
$cves = @(
    "CVE-2025-22952","CVE-2025-34035","CVE-2025-48957","CVE-2025-49493",
    "CVE-2025-55449","CVE-2025-8266","CVE-2026-20841",
    "CVE-2025-2024","CVE-2025-20354","CVE-2025-22422","CVE-2025-24813",
    "CVE-2025-27817","CVE-2025-2825","CVE-2025-3134","CVE-2025-3863",
    "CVE-2025-4134","CVE-2025-4273","CVE-2025-4284","CVE-2025-4425",
    "CVE-2025-4426","CVE-2025-4505","CVE-2025-4567","CVE-2025-4677",
    "CVE-2025-4721","CVE-2025-4788","CVE-2025-4868","CVE-2025-49002",
    "CVE-2025-49003","CVE-2025-4912","CVE-2025-4965","CVE-2025-4978",
    "CVE-2025-5001","CVE-2025-5109","CVE-2025-5147","CVE-2025-5151",
    "CVE-2025-5163","CVE-2025-5195","CVE-2025-5301","CVE-2025-5345",
    "CVE-2025-5412","CVE-2025-5535","CVE-2025-5573","CVE-2025-5612",
    "CVE-2025-5766","CVE-2024-0012","CVE-2024-1709","CVE-2024-20353",
    "CVE-2024-20697","CVE-2024-20698","CVE-2024-21225","CVE-2024-21287",
    "CVE-2024-21413","CVE-2024-21762","CVE-2024-21763","CVE-2024-22252",
    "CVE-2024-22253","CVE-2024-2251","CVE-2024-24919","CVE-2024-27197",
    "CVE-2024-27198","CVE-2024-27199","CVE-2024-2812","CVE-2024-28839",
    "CVE-2024-28847","CVE-2024-2918","CVE-2024-29640","CVE-2024-29824",
    "CVE-2024-29825","CVE-2024-30039","CVE-2024-37080","CVE-2024-38021",
    "CVE-2024-38077","CVE-2024-38078","CVE-2024-38100","CVE-2024-38114",
    "CVE-2024-38477","CVE-2024-38819","CVE-2024-41929","CVE-2024-41931",
    "CVE-2024-42369","CVE-2024-43639","CVE-2024-44340","CVE-2024-45230",
    "CVE-2024-45590","CVE-2024-46956","CVE-2024-46982","CVE-2024-47575",
    "CVE-2024-48248","CVE-2024-49560","CVE-2024-49570","CVE-2024-50858",
    "CVE-2024-51378","CVE-2024-52027","CVE-2024-52726","CVE-2024-52727",
    "CVE-2024-56145","CVE-2024-56477","CVE-2024-9264"
)

$outFile = "E:\claw\workspace\vuln-pocs\scripts\nvd_results.json"
$results = @{}

foreach ($cve in $cves) {
    Write-Host "[$cve] Fetching..." -NoNewline
    try {
        $uri = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve&resultsPerPage=1"
        $req = [Net.HttpWebRequest]::Create($uri)
        $req.Timeout = 8000
        $req.UserAgent = "Mozilla/5.0"
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $json = $sr.ReadToEnd()
        $sr.Close()
        $resp.Close()

        $obj = $json | ConvertFrom-Json
        $vuln = $obj.vulnerabilities[0].cve

        $desc = ($vuln.descriptions | Where-Object { $_.lang -eq "en" })[0].value
        $cvss3 = $null
        $cvss2 = $null

        if ($vuln.metrics.cvssMetricV31) {
            $cvss3 = $vuln.metrics.cvssMetricV31[0].cvssData
        } elseif ($vuln.metrics.cvssMetricV30) {
            $cvss3 = $vuln.metrics.cvssMetricV30[0].cvssData
        } elseif ($vuln.metrics.cvssMetricV2) {
            $cvss2 = $vuln.metrics.cvssMetricV2[0].cvssData
        }

        $score = if ($cvss3) { $cvss3.baseScore } elseif ($cvss2) { $cvss2.baseScore } else { "N/A" }
        $severity = if ($cvss3) { $cvss3.baseSeverity } elseif ($cvss2) { $cvss2.baseSeverity } else { "N/A" }
        $vector = if ($cvss3) { $cvss3.vectorString } elseif ($cvss2) { $cvss2.vectorString } else { "" }
        $published = $vuln.published.Substring(0, 10)
        $lastMod = $vuln.lastModified.Substring(0, 10)

        $results[$cve] = @{
            description = $desc
            cvss = $score
            severity = $severity
            vector = $vector
            published = $published
            lastModified = $lastMod
        }

        Write-Host " OK (CVSS $score/$severity)" -ForegroundColor Green
        Start-Sleep -Milliseconds 300
    } catch {
        $results[$cve] = @{ error = $_.Exception.Message }
        Write-Host " FAIL: $($_.Exception.Message.Substring(0, [Math]::Min(60, $_.Exception.Message.Length)))" -ForegroundColor Red
    }
}

$results | ConvertTo-Json -Depth 5 | Out-File -FilePath $outFile -Encoding UTF8
Write-Host "`nDone. Saved to $outFile"
