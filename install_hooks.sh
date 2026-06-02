#!/usr/bin/env bash
# ======================================================================
#          STAR SECURITY - GIT HOOK INSTALLER
# ======================================================================
# Installs check_syntax.sh as Git pre-commit and pre-push hooks.
# ======================================================================

C_RESET="\e[0m"
C_BOLD="\e[1m"
C_BRED="\e[1;31m"
C_BGREEN="\e[1;32m"
C_BYELLOW="\e[1;33m"
C_BCYAN="\e[1;36m"

echo -e "${C_BCYAN}======================================================================${C_RESET}"
echo -e " ⚙️  ${C_BOLD}INSTALLING GIT PRE-COMMIT & PRE-PUSH HOOKS${C_RESET}"
echo -e "${C_BCYAN}======================================================================${C_RESET}"

# Check for .git directory
if [[ ! -d ".git" ]]; then
    echo -e " [${C_BRED}ERROR${C_RESET}] Not a git repository (missing .git folder)."
    echo -e "         Please run this script from the root of your git repository."
    echo -e "${C_BCYAN}======================================================================${C_RESET}"
    exit 1
fi

HOOKS_DIR=".git/hooks"
mkdir -p "$HOOKS_DIR"

# Write pre-commit hook
cat << 'EOF' > "$HOOKS_DIR/pre-commit"
#!/usr/bin/env bash
# Git pre-commit hook to audit shell script syntax
if [[ -f "./check_syntax.sh" ]]; then
    ./check_syntax.sh
    exit $?
else
    echo -e "\e[1;33m[!] check_syntax.sh not found, skipping syntax audit.\e[0m"
    exit 0
fi
EOF

# Write pre-push hook
cat << 'EOF' > "$HOOKS_DIR/pre-push"
#!/usr/bin/env bash
# Git pre-push hook to audit shell script syntax
if [[ -f "./check_syntax.sh" ]]; then
    ./check_syntax.sh
    exit $?
else
    echo -e "\e[1;33m[!] check_syntax.sh not found, skipping syntax audit.\e[0m"
    exit 0
fi
EOF

# Make hook files executable
chmod +x "$HOOKS_DIR/pre-commit" 2>/dev/null
chmod +x "$HOOKS_DIR/pre-push" 2>/dev/null
chmod +x "./check_syntax.sh" 2>/dev/null

echo -e " [${C_BGREEN}SUCCESS${C_RESET}] Git hooks registered successfully:"
echo -e "   * pre-commit hook installed -> ${HOOKS_DIR}/pre-commit"
echo -e "   * pre-push hook installed   -> ${HOOKS_DIR}/pre-push"
echo -e ""
echo -e " ${C_BYELLOW}Now, Git will automatically run 'bash -n' syntax checks on your scripts${C_RESET}"
echo -e " ${C_BYELLOW}every time you commit or push code!${C_RESET}"
echo -e "${C_BCYAN}======================================================================${C_RESET}"
exit 0
