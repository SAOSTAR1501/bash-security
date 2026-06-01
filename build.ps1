# ======================================================================
#          LINUX SERVER SECURITY TOOLKIT (POWERSHELL BUNDLER)
# ======================================================================
# Compiles modular source code files into a single production sec.sh.
# Forces Unix line endings (\n) and UTF-8 without BOM.
# ======================================================================

$ErrorActionPreference = "Stop"
$output = "sec.sh"

$files = @(
    "src/core/colors.sh",
    "src/core/logger.sh",
    "src/core/root.sh",
    "src/core/ui.sh",
    "src/modules/system/sys_info.sh",
    "src/modules/system/cpu_process.sh",
    "src/modules/network/connections.sh",
    "src/modules/network/firewall.sh",
    "src/modules/filesystem/writable_paths.sh",
    "src/modules/filesystem/integrity.sh",
    "src/modules/persistence/entries.sh",
    "src/modules/identity/users.sh",
    "src/modules/identity/ssh_keys.sh",
    "src/modules/updater/git_wget.sh",
    "src/main.sh"
)

Write-Host "[*] Compiling security components on Windows..." -ForegroundColor Cyan

$timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
$content = "#!/usr/bin/env bash`n"
$content += "# ======================================================================`n"
$content += "#          LINUX SERVER SECURITY TOOLKIT (Miner & Malware Scanner)`n"
$content += "#                 Compiled production build: $timestamp`n"
$content += "#                 Source Architecture: MVC Modular / Domain-Driven`n"
$content += "# ======================================================================`n"
$content += "set -o pipefail`n`n"

foreach ($file in $files) {
    if (Test-Path $file) {
        $resolved = (Resolve-Path $file).Path
        $fileContent = [IO.File]::ReadAllText($resolved)
        # Force Unix newlines
        $fileContent = $fileContent -replace "`r`n", "`n"
        
        $content += "# ======================================================================`n"
        $content += "# MODULE: $file`n"
        $content += "# ======================================================================`n"
        $content += $fileContent + "`n`n"
    } else {
        Write-Error "Source file not found: $file"
        Exit 1
    }
}

# Write file in UTF-8 without BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path (Get-Location) $output), $content, $utf8NoBom)

Write-Host "[+] Compilation complete! Production script compiled at: $output" -ForegroundColor Green
