#!/bin/bash

set -e

# Повинен запускатись від root
if [ "$EUID" -ne 0 ]; then
    echo 0
    exit 1
fi

###########################################
# Встановлення libpam-pwquality
###########################################

if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y libpam-pwquality
fi

###########################################
# login.defs
###########################################

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs

grep -q "^PASS_MAX_DAYS" /etc/login.defs || \
echo "PASS_MAX_DAYS   90" >> /etc/login.defs

sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' /etc/login.defs

grep -q "^PASS_MIN_DAYS" /etc/login.defs || \
echo "PASS_MIN_DAYS   0" >> /etc/login.defs

###########################################
# Всі локальні користувачі
###########################################

awk -F: '$3>=1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false"{print $1}' /etc/passwd |
while read USER
do
    chage -M 90 "$USER"
done

###########################################
# pwquality.conf
###########################################

cat >/etc/security/pwquality.conf <<EOF
minlen = 12

ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1

minclass = 4

maxrepeat = 3

difok = 4

usercheck = 1

dictcheck = 1
EOF

###########################################
# PAM common-password
###########################################

PAM="/etc/pam.d/common-password"

if grep -q "pam_pwquality.so" "$PAM"; then

    sed -Ei 's/minlen=[0-9]+/minlen=12/g' "$PAM"

    grep -q "minlen=12" "$PAM" || \
    sed -Ei 's/pam_pwquality.so/pam_pwquality.so minlen=12 retry=3/' "$PAM"

else

    sed -Ei '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 minclass=4 maxrepeat=3 difok=4 usercheck=1 dictcheck=1' "$PAM"

fi

###########################################
# Історія паролів (останні 5)
###########################################

if grep -q "remember=" "$PAM"; then

    sed -Ei 's/remember=[0-9]+/remember=5/g' "$PAM"

else

    sed -Ei 's/pam_unix.so/& remember=5/' "$PAM"

fi

###########################################
# Перевірка
###########################################

PASS=$(grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')

LEN=$(grep '^minlen' /etc/security/pwquality.conf | awk '{print $3}')

if [ "$PASS" = "90" ] && [ "$LEN" = "12" ]; then
    echo 1
else
    echo 0
fi
