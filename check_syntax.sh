#!/usr/bin/env bash
# ======================================================================
#          LINUX SERVER SECURITY TOOLKIT - SYNTAX CHECKER
# ======================================================================
# Performs non-execution syntax check (bash -n) on all shell scripts.
# Exit code 0 if all clean, 1 if any syntax errors detected.
# ======================================================================

C_RESET="\e[0m"
C_BOLD="\e[1m"
C_BRED="\e[1;31m"
C_BGREEN="\e[1;32m"
C_BYELLOW="\e[1;33m"
C_BCYAN="\e[1;36m"

echo -e "${C_BCYAN}======================================================================${C_RESET}"
echo -e " 🔍 ${C_BOLD}RUNNING BASH SYNTAX AUDIT (bash -n)${C_RESET}"
echo -e "${C_BCYAN}======================================================================${C_RESET}"

errors=0
checked=0

# Find all shell files in the workspace (excluding .git)
while read -r file; do
    if [[ -f "$file" ]]; then
        checked=$((checked + 1))
        # Perform syntax check
        if ! bash -n "$file" 2>&1; then
            echo -e " [${C_BRED}FAILED${C_RESET}] Syntax error in: ${C_BOLD}$file${C_RESET}"
            # Print exact syntax error details
            bash -n "$file" 2>&1 | sed 's/^/   | /'
            errors=$((errors + 1))
        else
            echo -e " [${C_BGREEN}OK${C_RESET}] ${file}"
        fi
    fi
done < <(find . -name "*.sh" -not -path "*/.git/*" -not -path "*/node_modules/*")

echo -e "${C_BCYAN}----------------------------------------------------------------------${C_RESET}"
if [[ "$errors" -gt 0 ]]; then
    echo -e " 🛑 ${C_BRED}AUDIT FAILED:${C_RESET} Detected ${C_BOLD}$errors${C_RESET} syntax error(s) across ${C_BOLD}$checked${C_RESET} script file(s)."
    echo -e "      Please resolve all syntax errors before committing/pushing."
    echo -e "${C_BCYAN}======================================================================${C_RESET}"
    exit 1
else
    echo -e " [${C_BGREEN}SUCCESS${C_RESET}] All ${C_BOLD}$checked${C_RESET} shell script(s) are syntactically sound and compile-ready!"
    echo -e "${C_BCYAN}======================================================================${C_RESET}"
    exit 0
fi
