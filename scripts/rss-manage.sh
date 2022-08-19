#!/bin/bash
NDATE="$(date)"
NC='\e[0m'               # Text Reset
BCyan='\e[1;36m'         # Cyan
Red='\e[0;31m'           # Red
Green='\e[0;32m'         # Green

RSS="../target/release/rss-parser"
TIMEOUT="10"
ARGS="$@"

echo_info() {
	echo -e "${Green}$1${NC}"
}

echo_warn() {
	echo -e "${Red}$1${NC}"
}

echo_debug() {
	echo -e "${BCyan}$1${NC}"
}

usage() {
    echo_debug """
RSS Manager
     _ _ _ _ _ _ _ _ _ _ _ _ _
    | Manages rss-parser      |
    | - Needs a Title         |
    | - Needs a Config file   |
    | - Max pages             |
     - - - - - - - - - - - - -

    Example
    - - - - 
    ./rss-manage.sh Twitter-Feed ./twitter-feed.json 2
    """
}

check_args() {
    if [[ "$1" == "help" ]];
    then
        $RSS --help
        exit 0
    fi
    if [[ $# -ne 3 ]];
    then
        usage
        exit 1
    fi
}

check_error() {
    CODE="$(echo $?)"
    if [[ "$CODE" != 0 ]];
    then
        echo_warn "rss-parser errored out"
        exit $CODE
    fi
}

check_args $ARGS

DATE=$(date +%Y%m%d%H%M%S)
TITLE=$(echo $ARGS | cut -d ' ' -f 1)
CONFIG=$(echo $ARGS | cut -d ' ' -f 2)
PAGES=$(echo "$ARGS" | cut -d ' ' -f 3)
FILE="${TITLE}"_"${DATE}".json

rss_init() {
    $RSS -t 0 -m $PAGES -o "${FILE}" -c "${CONFIG}"
    check_error
}

rss_poll() {
    for ((;;));
    do
        echo_debug "Polling..."
        $RSS -t 0.3 -m 1 -r "${FILE}" -o "${FILE2}"
        sleep $TIMEOUT
        check_error
    done
}

echo_info "[-] ${NDATE}"
echo_info "[+] Starting RSS Init..."
rss_init
rss_poll
