#!/bin/bash

set -e

# Потрібно запускати від root
if [ "$EUID" -ne 0 ]; then
    echo "Необхідно запускати від root"
    exit 1
fi

echo "===== Password Policy ====="

########################################
# Перевірка чи вже все налаштовано
########################################

OK=1

# PASS_MAX_DAYS
grep -q '^PASS_MAX_DAYS[[:space:]]\+90$' /etc/login.defs || OK=0

# PASS_MIN_DAYS
grep -q '^PASS_MIN_DAYS[[:space:]]\+0$' /etc/login.defs || OK=0

# pwquality.conf
grep -q '^minlen[[:space:]]*=[[:space:]]*12$' /etc/security/pwquality.conf 2>/dev/null || OK=0
grep -q '^ucredit[[:space:]]*=[[:space:]]*-1$' /etc/security/pwquality.conf 2>/dev/null || OK=0
grep -q '^lcredit[[:space:]]*=[[:space:]]*-1$' /etc/security/pwquality.conf 2>/dev/null || OK=0
grep -q '^dcredit[[:space:]]*=[[:space:]]*-1$' /etc/security/pwquality.conf 2>/dev/null || OK=0
grep -q '^ocredit[[:space:]]*=[[:space:]]*-1$' /etc/security/pwquality.conf 2>/dev/null || OK=0
grep -q '^minclass[[:space:]]*=[[:space:]]*4$' /etc/security/pwquality.conf 2>/dev/null || OK=0
grep -q '^maxrepeat[[:space:]]*=[[:space:]]*3$' /etc/security/pwquality.conf 2>/dev/null || OK=0
grep -q '^difok[[:space:]]*=[[:space:]]*4$' /etc/security/pwquality.conf 2>/dev/null || OK=0

# remember=5
grep -q 'remember=5' /etc/pam.d/common-password 2>/dev/null || OK=0

########################################
# Якщо вже налаштовано
########################################

if [ "$OK" -eq 1 ]; then
    echo "Політика паролів вже застосована."
    exit 0
fi

echo "Застосовую політику..."

########################################
# Встановлення libpam-pwquality
########################################

if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y libpam-pwquality
fi

########################################
# login.defs
########################################

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
grep -q '^PASS_MAX_DAYS' /etc/login.defs || echo "PASS_MAX_DAYS   90" >> /etc/login.defs

sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' /etc/login.defs
grep -q '^PASS_MIN_DAYS' /etc/login.defs || echo "PASS_MIN_DAYS   0" >> /etc/login.defs

########################################
# Усі локальні користувачі
########################################

awk -F: '$3>=1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false"{print $1}' /etc/passwd |
while read USER
do
    echo "Налаштовую користувача $USER"

    chage -M 90 "$USER"

    # Якщо не хочеш примушувати змінювати пароль відразу,
    # відлік почнеться з поточної дати
    chage -d "$(date +%F)" "$USER"
done

########################################
# pwquality.conf
########################################

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

########################################
# PAM
########################################

PAM="/etc/pam.d/common-password"

if grep -q "pam_pwquality.so" "$PAM"; then

    sed -Ei 's/minlen=[0-9]+/minlen=12/g' "$PAM"

    grep -q "remember=5" "$PAM" || \
    sed -Ei 's/pam_unix.so/& remember=5/' "$PAM"

else

    sed -Ei '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 minclass=4 maxrepeat=3 difok=4 usercheck=1 dictcheck=1' "$PAM"

    sed -Ei 's/pam_unix.so/& remember=5/' "$PAM"

fi

echo "Політика паролів успішно застосована."

exit 0
