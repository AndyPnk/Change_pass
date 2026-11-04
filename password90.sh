#!/bin/bash
# Політика паролів для Ubuntu/Debian. Адміністратори не чіпаються.
#
# Використання (від root):
#   ./pwpolicy.sh            застосувати політику (те саме, що apply)
#   ./pwpolicy.sh check      лише перевірити, нічого не змінює (для Zabbix)
#   ./pwpolicy.sh revert-admins   повернути адмінам "пароль не спливає"
#
# Вивід завжди одним рядком:
#   apply:  ALREADY_APPLIED | APPLIED_SUCCESS: <що змінено> | ERROR: <причина>
#   check:  COMPLIANT | NON_COMPLIANT: <що не так>
#
# Змінні можна задати з оточення: MAX_DAYS=60 ./pwpolicy.sh

set -u

# ===== Налаштування =====
MAX_DAYS=${MAX_DAYS:-90}              # термін дії пароля звичайних користувачів
MIN_LEN=${MIN_LEN:-12}                # мінімальна довжина пароля
HISTORY=${HISTORY:-5}                 # скільки останніх паролів не можна повторювати
ADMIN_GROUPS=${ADMIN_GROUPS:-"sudo admin wheel"}  # користувачі цих груп вважаються адмінами
EXCLUDE_USERS=${EXCLUDE_USERS:-""}    # додаткові користувачі-винятки (через пробіл)
SOFT_START=${SOFT_START:-1}           # 1: відлік терміну від дня застосування; 0: не чіпати дату зміни пароля
MODE=${1:-apply}

PAM=/etc/pam.d/common-password
PWQ_DROPIN=/etc/security/pwquality.conf.d/99-policy.conf

[ "$(id -u)" -eq 0 ] || { echo "ERROR: потрібен root"; exit 1; }
case "$MODE" in apply|check|revert-admins) ;; *) echo "ERROR: невідомий режим '$MODE'"; exit 1 ;; esac

CHANGED=""      # що змінено (режим apply)
PROBLEMS=""     # що не так (режим check)
note()    { CHANGED="$CHANGED $1"; }
problem() { PROBLEMS="$PROBLEMS $1"; }

# ===== Допоміжні функції =====
is_admin() {
    local g
    for g in $(id -nG "$1" 2>/dev/null); do
        case " $ADMIN_GROUPS " in *" $g "*) return 0 ;; esac
    done
    return 1
}

is_excluded() {
    case " $EXCLUDE_USERS " in *" $1 "*) return 0 ;; esac
    return 1
}

has_password() {
    case "$(getent shadow "$1" | cut -d: -f2)" in ''|'!'*|'*'*) return 1 ;; esac
    return 0
}

UID_MIN=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
UID_MIN=${UID_MIN:-1000}

# Локальні користувачі з паролем і shell
list_users() {
    awk -F: -v min="$UID_MIN" '$3>=min && $3<65534 && $7!~/(nologin|false)$/ {print $1}' /etc/passwd
}

# Звичайні користувачі: не адміни, не винятки, з реальним паролем
list_regular() {
    local u
    for u in $(list_users); do
        is_admin "$u" && continue
        is_excluded "$u" && continue
        has_password "$u" || continue
        echo "$u"
    done
}

PWQ_CONTENT="minlen = $MIN_LEN
ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1
minclass = 4
maxrepeat = 3
difok = 4
usercheck = 1
dictcheck = 1"

# ===== Режим check =====
if [ "$MODE" = check ]; then
    dpkg -s libpam-pwquality >/dev/null 2>&1 || problem "pkg"
    [ "$(cat "$PWQ_DROPIN" 2>/dev/null)" = "$PWQ_CONTENT" ] || problem "pwquality"
    grep -Eq '^password[[:space:]].*pam_pwquality\.so' "$PAM" 2>/dev/null || problem "pam-pwquality"
    grep -Eq "^password[[:space:]].*pam_unix\.so.*remember=$HISTORY( |\$)" "$PAM" 2>/dev/null || problem "history"
    bad=""
    for u in $(list_regular); do
        [ "$(getent shadow "$u" | cut -d: -f5)" = "$MAX_DAYS" ] || bad="$bad,$u"
    done
    [ -z "$bad" ] || problem "maxdays:${bad#,}"
    if [ -z "$PROBLEMS" ]; then echo "COMPLIANT"; else echo "NON_COMPLIANT:$PROBLEMS"; fi
    exit 0
fi

# ===== Режим revert-admins =====
if [ "$MODE" = revert-admins ]; then
    for u in $(list_users); do
        is_admin "$u" || continue
        if [ "$(getent shadow "$u" | cut -d: -f5)" = "$MAX_DAYS" ]; then
            chage -M 99999 "$u" && note "revert:$u"
        fi
    done
    if grep -Eq "^PASS_MAX_DAYS[[:space:]]+$MAX_DAYS\$" /etc/login.defs; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' /etc/login.defs && note "login.defs"
    fi
    if [ -z "$CHANGED" ]; then echo "ALREADY_APPLIED"; else echo "APPLIED_SUCCESS:$CHANGED"; fi
    exit 0
fi

# ===== Режим apply =====

# 1. Пакет
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    if apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq libpam-pwquality >/dev/null 2>&1; then
        note "pkg"
    else
        echo "ERROR: не вдалося встановити libpam-pwquality"; exit 1
    fi
fi

# 2. Вимоги до пароля (окремий файл, основний pwquality.conf не перезаписується)
if [ "$(cat "$PWQ_DROPIN" 2>/dev/null)" != "$PWQ_CONTENT" ]; then
    mkdir -p "$(dirname "$PWQ_DROPIN")"
    printf '%s\n' "$PWQ_CONTENT" > "$PWQ_DROPIN"
    chmod 644 "$PWQ_DROPIN"
    note "pwquality"
fi

# 3. PAM: pwquality та історія паролів (чіпаємо лише активні рядки, не коментарі)
[ -e "$PAM.bak.policy" ] || cp -p "$PAM" "$PAM.bak.policy"
BEFORE=$(cksum < "$PAM")
if grep -Eq '^password[[:space:]].*pam_pwquality\.so' "$PAM"; then
    sed -Ei "/^password[[:space:]].*pam_pwquality\.so/s/minlen=[0-9]+/minlen=$MIN_LEN/" "$PAM"
else
    sed -Ei '0,/^password[[:space:]].*pam_unix\.so/s//password requisite pam_pwquality.so retry=3\n&/' "$PAM"
fi
sed -Ei "/^password[[:space:]].*pam_unix\.so/s/remember=[0-9]+/remember=$HISTORY/" "$PAM"
sed -Ei "/^password[[:space:]].*pam_unix\.so/{/remember=/!s/\$/ remember=$HISTORY/}" "$PAM"
if ! grep -Eq '^password[[:space:]].*pam_unix\.so' "$PAM"; then
    cp -p "$PAM.bak.policy" "$PAM"
    echo "ERROR: PAM-файл пошкоджено, відновлено з копії"; exit 1
fi
[ "$BEFORE" = "$(cksum < "$PAM")" ] || note "pam"

[ -f /etc/security/opasswd ] || { touch /etc/security/opasswd && chmod 600 /etc/security/opasswd; }

# 4. Користувачі (адміни, винятки та акаунти без пароля пропускаються)
for u in $(list_regular); do
    if [ "$(getent shadow "$u" | cut -d: -f5)" != "$MAX_DAYS" ]; then
        chage -M "$MAX_DAYS" "$u" || continue
        [ "$SOFT_START" = 1 ] && chage -d "$(date +%F)" "$u"
        note "user:$u"
    fi
done

if [ -z "$CHANGED" ]; then echo "ALREADY_APPLIED"; else echo "APPLIED_SUCCESS:$CHANGED"; fi
exit 0
