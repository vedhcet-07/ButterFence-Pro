#!/bin/bash
# ButterFence Hackathon Demo Script
# Walks through all major features with pauses for dramatic effect

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$DEMO_DIR")"
VULN_DIR="$DEMO_DIR/vulnerable-repo"

pause() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

banner() {
    echo -e "${CYAN}"
    echo '  ____        _   _            _____                    '
    echo ' | __ ) _   _| |_| |_ ___ _ _|  ___|__ _ __   ___ ___ '
    echo ' |  _ \| | | | __| __/ _ \  __|  _| / _ \  _ \ / __/ _ \'
    echo ' | |_) | |_| | |_| ||  __/ |  |  _|  __/ | | | (_|  __/'
    echo ' |____/ \__,_|\__|\__\___|_|  |_|  \___|_| |_|\___\___|'
    echo -e "${NC}"
    echo -e "${BOLD}Claude Code Safety Harness - Hackathon Demo${NC}"
    echo ""
}

step() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  STEP: $1${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

clear
banner
echo -e "This demo showcases ButterFence's ability to:"
echo -e "  ${CYAN}1.${NC} Initialize safety hooks for Claude Code"
echo -e "  ${CYAN}2.${NC} Audit against 44 red-team scenarios"
echo -e "  ${CYAN}3.${NC} Scan repos for secrets and vulnerabilities"
echo -e "  ${CYAN}4.${NC} Generate reports in multiple formats"
echo -e "  ${CYAN}5.${NC} Explain threats with educational context"
echo -e "  ${CYAN}6.${NC} Manage community rule packs"
echo ""
pause

# ─── Step 1: Initialize ───
step "1/6 - Initialize ButterFence"
echo -e "Running: ${CYAN}butterfence init --no-hooks --dir $VULN_DIR${NC}"
echo ""
butterfence init --no-hooks --dir "$VULN_DIR" --force
pause

# ─── Step 2: Audit ───
step "2/6 - Red-Team Audit (44 scenarios)"
echo -e "Running: ${CYAN}butterfence audit --dir $VULN_DIR${NC}"
echo ""
butterfence audit --dir "$VULN_DIR"
pause

# ─── Step 3: Scan ───
step "3/6 - Secret Scanner on Vulnerable Repo"
echo -e "Running: ${CYAN}butterfence scan --dir $VULN_DIR --fix${NC}"
echo ""
butterfence scan --dir "$VULN_DIR" --fix
pause

# ─── Step 4: Report ───
step "4/6 - Generate HTML Report"
echo -e "Running: ${CYAN}butterfence report --format html --output $VULN_DIR/report.html --dir $VULN_DIR${NC}"
echo ""
butterfence report --format html --output "$VULN_DIR/report.html" --dir "$VULN_DIR"
echo ""
echo -e "${GREEN}HTML report generated!${NC} Open $VULN_DIR/report.html in a browser."
pause

# ─── Step 5: Explain ───
step "5/6 - Threat Explanations"
echo -e "Running: ${CYAN}butterfence explain shell-001${NC}"
echo ""
butterfence explain shell-001
echo ""
echo -e "Running: ${CYAN}butterfence explain docker-001${NC}"
echo ""
butterfence explain docker-001
pause

# ─── Step 6: Packs ───
step "6/6 - Community Rule Packs"
echo -e "Running: ${CYAN}butterfence pack list${NC}"
echo ""
butterfence pack list
pause

# ─── Finale ───
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  DEMO COMPLETE${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
banner
echo -e "  ${BOLD}ButterFence v2.0 Summary:${NC}"
echo -e "  ${CYAN}11${NC} defense categories"
echo -e "  ${CYAN}44${NC} red-team scenarios"
echo -e "  ${CYAN} 7${NC} community rule packs"
echo -e "  ${CYAN} 5${NC} export formats (Markdown, HTML, JSON, SARIF, JUnit)"
echo -e "  ${CYAN}239${NC} passing tests"
echo -e "  ${CYAN}Live dashboard${NC}, ${CYAN}CI/CD integration${NC}, ${CYAN}secret scanner${NC}"
echo ""
echo -e "  ${YELLOW}Built for the Claude Code ecosystem.${NC}"
echo -e "  ${YELLOW}Pure-function matcher ensures audit = real hook behavior.${NC}"
echo ""
