#!/bin/bash

set -e

SESSION=$(loginctl list-sessions --no-legend | awk '$4=="seat0"{print $1; exit}')
USER=$(loginctl show-session "$SESSION" -p Name --value)

if [ -z "$USER" ]; then
    echo 0
    exit 1
fi

CURRENT=$(awk -F: -v u="$USER" '$1==u{print $5}' /etc/shadow)

if [ "$CURRENT" = "90" ]; then
    echo 1
    exit 0
fi

chage -M 90 "$USER"

NEW=$(awk -F: -v u="$USER" '$1==u{print $5}' /etc/shadow)

if [ "$NEW" = "90" ]; then
    echo 1
else
    echo 0
fi
