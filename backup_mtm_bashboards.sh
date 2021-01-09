#!/bin/bash
# Initial Version coded on 26-Jul-2020 by Paresh (with Kiara)
# Replicated from UTM to MTM

MTM_DIR=/usr/local/telegraf

declare -A mtm_dashboard_arr
mtm_dashboard_arr=( ["locations"]="i56djUbMz" ["switches"]="WoIYF-xGz" ["switchports"]="qxGcp0bGk" )

date_suffix=$(date +"%M%H%m%d%y")

if ! command -v jq &> /dev/null
then
    echo "I need jq to proceed. Hint: yum install jq"
    exit
fi

testLoginValue="false"
while [[ "${testLoginValue}" == "false" ]]; do
    unset GRAFANA_USER
    unset GRAFANA_PASSWORD
    while [ -z "$GRAFANA_USER" ]; do
        read -p "Grafana User:" GRAFANA_USER
    done
    while [ -z "$GRAFANA_PASSWORD" ]; do
        read -s -p "Password:" GRAFANA_PASSWORD
    done
    echo " "

    auth_msg=$(curl -s -X GET -H "Accept: application/json" -H "Content-Type: application/json" http://$GRAFANA_USER:$GRAFANA_PASSWORD@localhost:3000/api/org | jq '.message')
    if [[ "$auth_msg" == *"Invalid"* ]]; then
        echo "$auth_msg"
        echo "Please try again"
    else
        testLoginValue="true"
        echo ""
    fi
done

echo "---------------------------"
echo "Taking backup of MTM dashboards and cleanup for sharing"
sleep 2

if mkdir -p $MTM_DIR/grafana/dashboards_${date_suffix} ; then
    echo "."

    for item in "${!mtm_dashboard_arr[@]}"
    do
        curl -s -X GET -H "Accept: application/json" -H "Content-Type: application/json" http://$GRAFANA_USER:$GRAFANA_PASSWORD@localhost:3000/api/dashboards/uid/${mtm_dashboard_arr[$item]} | jq -r '.dashboard' > $MTM_DIR/grafana/dashboards_${date_suffix}/${item}.json
        fid_arr+=( ["${item}"]="$(jq -r '.meta.folderId' $MTM_DIR/grafana/dashboards_${date_suffix}/${item}.json)" )
    done

    #for key in ${!uid_arr[@]}; do
    #    echo ${key} ${uid_arr[${key}]}
    #done

    echo "I have taken a backup of your existing MTM dashboards in $MTM_DIR/grafana/dashboards_${date_suffix}"
else
    echo "Unable to create $MTM_DIR/grafana/dashboards_${date_suffix}"
fi

echo "---------------------------"
sleep 2
