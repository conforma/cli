#!/usr/bin/env bash

set -euo pipefail

# Output a fancy heading
function h1() {
  local text="$1"
  local line=$(sed 's/./─/g' <<< "$text")
  echo "╭─$line─╮"
  echo "┝ $text ┥"
  echo "╰─$line─╯"
}

# Output some text and wait for the user to press enter
function pause() {
  local default_msg="Press Enter to continue..."
  local msg="${1:-$default_msg}"

  nl
  read -p "$msg"
  nl
}

# Output a line break
function nl() {
  printf "\n"
}
