#!/bin/bash
# Політика паролів Ubuntu. Адміни (групи sudo/admin/wheel) не чіпаються.
# REVERT_ADMINS=1 ./script.sh  - одноразово повернути адмінам "пароль не спливає"
# SOFT_START=0 - не скидати дату зміни пароля при першому застосуванні
set -u
[ "$(id -u)" -eq 0 ] || { echo "ERROR: потрібен root"; exit 1; }

MAXDAYS=90
SOFT_START=${SOFT_START:-1}
REVERT_ADMINS=${REVERT_ADMINS:-0}
CHANGED=""

is_admin() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; }

# 1. Пакет
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq libpam-pwquality >/dev/null \
        || { echo "ERROR: apt"; exit 1; }
    CHANGED="$CHANGED pkg"
fi

# 2. Вимоги до пароля (окремий файл, основний не перезаписується)
mkdir -p /etc/security/pwquality.conf.d
TMP=$(mktemp)
cat >"$TMP" <<'EOF'
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
if ! cmp -s "$TMP" /etc/security/pwquality.conf.d/99-policy.conf; then
    install -m 644 "$TMP" /etc/security/pwquality.conf.d/99-policy.conf
    CHANGED="$CHANGED pwquality"
fi
rm -f "$TMP"

# 3. PAM: pwquality + історія паролів (лише активні рядки, не коментарі)
PAM=/etc/pam.d/common-password
cp -n "$PAM" "$PAM.bak.policy"
BEFORE=$(cksum <"$PAM")
if grep -Eq '^password[[:space:]].*pam_pwquality\.so' "$PAM"; then
    sed -Ei '/^password[[:space:]].*pam_pwquality\.so/s/minlen=[0-9]+/minlen=12/' "$PAM"
else
    sed -Ei '0,/^password[[:space:]].*pam_unix\.so/s//password requisite pam_pwquality.so retry=3\n&/' "$PAM"
fi
sed -Ei '/^password[[:space:]].*pam_unix\.so/s/remember=[0-9]+/remember=5/' "$PAM"
sed -Ei '/^password[[:space:]].*pam_unix\.so/{/remember=/!s/$/ remember=5/}' "$PAM"
[ "$BEFORE" = "$(cksum <"$PAM")" ] || CHANGED="$CHANGED pam"

[ -f /etc/security/opasswd ] || { touch /etc/security/opasswd; chmod 600 /etc/security/opasswd; }

# 4. Користувачі. login.defs не чіпаємо, щоб нові адміни не отримували 90 днів
while read -r u; do
    pw=$(getent shadow "$u" | cut -d: -f2)
    case "$pw" in ''|'!'*|'*'*) continue ;; esac   # без пароля або заблокований
    cur=$(getent shadow "$u" | cut -d: -f5)

    if is_admin "$u"; then
        if [ "$REVERT_ADMINS" = 1 ] && [ "$cur" = "$MAXDAYS" ]; then
            chage -M 99999 "$u"
            CHANGED="$CHANGED revert:$u"
        fi
        continue
    fi

    if [ "$cur" != "$MAXDAYS" ]; then
        chage -M "$MAXDAYS" "$u"
        [ "$SOFT_START" = 1 ] && chage -d "$(date +%F)" "$u"
        CHANGED="$CHANGED fixed:$u"
    fi
done < <(awk -F: '$3>=1000 && $3<65534 && $7!~/(nologin|false)$/ {print $1}' /etc/passwd)

# 5. Відкат системного значення, яке виставила стара версія скрипта (лише з REVERT_ADMINS=1)
if [ "$REVERT_ADMINS" = 1 ] && grep -Eq "^PASS_MAX_DAYS[[:space:]]+$MAXDAYS$" /etc/login.defs; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' /etc/login.defs
    CHANGED="$CHANGED login.defs"
fi

if [ -z "$CHANGED" ]; then echo "ALREADY_APPLIED"; else echo "APPLIED_SUCCESS:$CHANGED"; fi
