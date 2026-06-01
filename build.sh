#!/usr/bin/env bash
# ======================================================================
#          LINUX SERVER SECURITY TOOLKIT (BASH BUNDLER / COMPILER)
# ======================================================================
# Compiles modular development files into the production sec.sh script.
# ======================================================================

set -e

OUTPUT="sec.sh"

echo -e "\e[1;36m[*] Commencing compilation of security components...\e[0m"

# Verify all source files exist
SRC_FILES=(
    "src/core/colors.sh"
    "src/core/logger.sh"
    "src/core/root.sh"
    "src/core/ui.sh"
    "src/modules/system/sys_info.sh"
    "src/modules/system/cpu_process.sh"
    "src/modules/network/connections.sh"
    "src/modules/network/firewall.sh"
    "src/modules/filesystem/writable_paths.sh"
    "src/modules/filesystem/integrity.sh"
    "src/modules/persistence/entries.sh"
    "src/modules/identity/users.sh"
    "src/modules/identity/ssh_keys.sh"
    "src/modules/updater/git_wget.sh"
    "src/main.sh"
)

for file in "${SRC_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo -e "\e[1;31m[!] Compilation Error: Source file not found: $file\e[0m"
        exit 1
    fi
done

# Assemble unified sec.sh
{
    echo "#!/usr/bin/env bash"
    echo "# ======================================================================"
    echo "#          LINUX SERVER SECURITY TOOLKIT (Miner & Malware Scanner)"
    echo "#                 Compiled production build: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "#                 Source Architecture: MVC Modular / Domain-Driven"
    echo "# ======================================================================"
    echo "set -o pipefail"
    echo ""

    echo "# ======================================================================"
    echo "# CORE STACK"
    echo "# ======================================================================"
    cat "src/core/colors.sh"
    cat "src/core/logger.sh"
    cat "src/core/root.sh"
    cat "src/core/ui.sh"
    echo ""

    echo "# ======================================================================"
    echo "# SECURITY MODULES"
    echo "# ======================================================================"
    cat "src/modules/system/sys_info.sh"
    cat "src/modules/system/cpu_process.sh"
    cat "src/modules/network/connections.sh"
    cat "src/modules/network/firewall.sh"
    cat "src/modules/filesystem/writable_paths.sh"
    cat "src/modules/filesystem/integrity.sh"
    cat "src/modules/persistence/entries.sh"
    cat "src/modules/identity/users.sh"
    cat "src/modules/identity/ssh_keys.sh"
    cat "src/modules/updater/git_wget.sh"
    echo ""

    echo "# ======================================================================"
    echo "# ENTRYPOINT & MENU"
    echo "# ======================================================================"
    cat "src/main.sh"

} > "$OUTPUT"

chmod +x "$OUTPUT"

echo -e "\e[1;32m[+] Compilation complete! Production-ready file generated at: $OUTPUT\e[0m"
echo -e "\e[1;32m[+] Ready to commit and deploy on Hetzner servers.\e[0m"
