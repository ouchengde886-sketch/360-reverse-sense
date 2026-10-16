param([string]$Spec)
# Spec format: owner/repo:file1~file2;owner2/repo2:file
# Use @ as repo separator to avoid shell metachars
$ErrorActionPreference = 'Continue'
$H = @{'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
$repos = $Spec -split '@' | Where-Object { $_ -ne '' }
foreach ($spec in $repos) {
    $idx = $spec.IndexOf(':')
    if ($idx -lt 0) { $rp = $spec; $names = @('README.md') }
    else { $rp = $spec.Substring(0, $idx); $names = $spec.Substring($idx + 1).Split('~') }
    $p = $rp.Split('/')
    $found = $false
    foreach ($b in @('main', 'master')) {
        foreach ($n in $names) {
            $u = "https://raw.githubusercontent.com/$($p[0])/$($p[1])/$b/$n"
            try {
                $c = (Invoke-WebRequest -Uri $u -UseBasicParsing -Headers $H -TimeoutSec 25).Content
                "`n########## $u (len=$($c.Length)) ##########"
                $c
                $found = $true
                break
            } catch { }
        }
        if ($found) { break }
    }
    if (-not $found) { "`n########## NOT FOUND: $spec ##########" }
}