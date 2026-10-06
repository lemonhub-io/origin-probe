# origin-probe bootstrapper for Windows.
#
#   powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/lemonhub-io/origin-probe/main/install.ps1 | iex"
#
# Optional environment overrides:
#   $env:ORIGIN_PROBE_VERSION = "v0.2.0"   pin a release tag (default: latest)
#   $env:ORIGIN_PROBE_DIR = "C:\path"      install directory (default: ~\AppData\Local\Programs\origin-probe)

$ErrorActionPreference = 'Stop'
$repo = 'lemonhub-io/origin-probe'

# --- detect architecture -------------------------------------------------------
$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch -Regex ($arch) {
    '^(AMD64|x86_64)$' { $target = 'x86_64-pc-windows-msvc' }
    '^(ARM64|aarch64)$' { throw "ARM64 Windows builds are not published yet" }
    default { throw "unsupported architecture: $arch" }
}

# --- resolve release -----------------------------------------------------------
# Asset filenames embed the tag, so "latest" must be resolved first via the API.
$version = $env:ORIGIN_PROBE_VERSION
if (-not $version) {
    $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
    Write-Host "Latest release: $version"
}
$base  = "https://github.com/$repo/releases/download/$version"
$asset = "origin-probe-$version-$target.zip"

# --- download + verify ---------------------------------------------------------
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("origin-probe-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp $asset
    Write-Host "Downloading $asset for $target ..."
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $zip

    try {
        $sumsPath = Join-Path $tmp 'SHA256SUMS.txt'
        Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $sumsPath
        $want = (Select-String -Path $sumsPath -Pattern " $([regex]::Escape($asset))$").Line.Split(' ')[0]
        if ($want) {
            $got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
            if ($got -ne $want) { throw "checksum mismatch for $asset" }
            Write-Host 'Checksum verified.'
        }
    } catch [System.Net.WebException] {
        Write-Warning 'SHA256SUMS.txt not found; skipping checksum verification'
    }

    # --- unpack + install -------------------------------------------------------
    $x = Join-Path $tmp 'x'
    Expand-Archive -Path $zip -DestinationPath $x
    $bin = Get-ChildItem -Recurse -Filter 'origin-probe.exe' $x | Select-Object -First 1
    if (-not $bin) { throw 'archive did not contain origin-probe.exe' }

    $dest = $env:ORIGIN_PROBE_DIR
    if (-not $dest) { $dest = Join-Path $env:LOCALAPPDATA 'Programs\origin-probe' }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item $bin.FullName (Join-Path $dest 'origin-probe.exe')
    Write-Host "Installed to $dest\origin-probe.exe"

    # add to user PATH if missing
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$dest*") {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$dest", 'User')
        Write-Host "Added $dest to your user PATH (restart the terminal to pick it up)."
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# --- usage ---------------------------------------------------------------------
Write-Host @'

origin-probe is ready. It inspects this device and estimates the
likelihood that its user is Chinese. You must explicitly consent
before any scanning happens.

  origin-probe            interactive scan (prompts for consent)
  origin-probe --offline  local checks only, no network requests
  origin-probe --json     machine-readable report on stdout

One-shot non-interactive use:

  echo yes | origin-probe --offline

Nothing is written to disk and nothing is sent anywhere except a
public-IP geolocation lookup (skipped by --offline).
'@
