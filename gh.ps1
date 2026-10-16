param([string]$Repos, [string]$Mode = 'repo')
$Repos = $Repos -split '\|' | Where-Object { $_ -ne '' }
$ErrorActionPreference = 'Continue'
$H = @{'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

function Get-Raw {
    param([string]$Owner, [string]$Repo, [string[]]$Names, [string[]]$Branches = @('main', 'master'))
    foreach ($b in $Branches) {
        foreach ($n in $Names) {
            $u = "https://raw.githubusercontent.com/$Owner/$Repo/$b/$n"
            try {
                $c = (Invoke-WebRequest -Uri $u -UseBasicParsing -Headers $H -TimeoutSec 25).Content
                return @{ url = $u; body = $c }
            } catch { }
        }
    }
    return $null
}

if ($Mode -eq 'repo') {
    foreach ($r in $Repos) {
        $p = $r.Split('/')
        try {
            $d = Invoke-RestMethod -Uri "https://api.github.com/repos/$r" -UseBasicParsing -Headers $H -TimeoutSec 25
            "{0} | stars={1} | pushed={2} | created={3} | lang={4} | archived={5}" -f $d.full_name, $d.stargazers_count, $d.pushed_at, $d.created_at, $d.language, $d.archived
            "   desc: $($d.description)"
            "   topics: $($d.topics -join ',')"
        } catch {
            # fallback to shields
            $s = '?'; $l = '?'
            try { $s = (Invoke-RestMethod -Uri "https://img.shields.io/github/stars/$r.json" -UseBasicParsing -TimeoutSec 20).value } catch { }
            try { $l = (Invoke-RestMethod -Uri "https://img.shields.io/github/last-commit/$r.json" -UseBasicParsing -TimeoutSec 20).value } catch { }
            "SHIELDS $r | stars=$s | lastcommit=$l  (api err: $($_.Exception.Message))"
        }
    }
}

if ($Mode -eq 'raw') {
    # Repos format: owner/repo:file1,file2
    foreach ($spec in $Repos) {
        $parts = $spec.Split(':')
        $rp = $parts[0].Split('/')
        $names = $parts[1].Split('~')
        $res = Get-Raw -Owner $rp[0] -Repo $rp[1] -Names $names
        if ($res) { "===== $($res.url) ====="; $res.body } else { "===== NOT FOUND: $spec =====" }
    }
}

if ($Mode -eq 'search') {
    foreach ($q in $Repos) {
        try {
            $d = Invoke-RestMethod -Uri "https://api.github.com/search/repositories?q=$q&sort=updated&order=desc&per_page=20" -UseBasicParsing -Headers $H -TimeoutSec 30
            "##### QUERY: $q (total=$($d.total_count))"
            foreach ($i in $d.items) {
                "{0} | stars={1} | pushed={2} | {3}" -f $i.full_name, $i.stargazers_count, $i.pushed_at, $i.description
            }
        } catch { "SEARCH FAIL $q : $($_.Exception.Message)" }
    }
}