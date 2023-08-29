#!/bin/bash

# --------
# certta.sh
# - version 1.0 - initial
# - version 1.1 - different PEM file handling as the list of results was to confusing
# - version 1.2 - using Splunk BTOOL to find certificates
# - version 1.2.1 - code cleanup as the only option is BTOOL plus extra PEM_FILES
# - version 1.2.2 - remove duplicates from array PEM_FILES
# - version 1.2.2.1 - removed issuer info as the field stays blank
# - version 1.2.2.2 - changed printf layout
# - version 1.3 - use external config.sh file
# - version 1.3.1 - made the source config.sh handling error-free
# - version 1.3.2 - added issuer CN info
# - version 1.3.2.1 - added DEPRECATED values to recognize certs in older releases
# - version 1.3.2.2 - added authentication/idpCertPath in where_is_waldo

# ---
# VARS
# ---

if [ -f $(dirname $0)/../local/config.sh ]; then
    # Relative path to the external config file
    source $(dirname $0)/../local/config.sh
elif [ -f $(dirname $0)/../default/config.sh ]; then
    # Relative path to the external default config file
    source $(dirname $0)/../default/config.sh
else
    printf "log_level=\"ERROR\" event_message=\"$0 missing variables, check config.sh file.\"\n"
    exit 1
fi

# ---
# FUNCTIONS
# ---

# Find pem with Splunk BTOOL
function where_is_waldo() {
    # run BTOOL and feed variable FIELDS
    FIELDS=$(for i in authentication inputs server outputs web; do $SPLUNK_HOME/bin/splunk btool $i list --debug | grep -iv "sslVerifyServerCert" | grep -i "serverCert\|caCertFile\|sslRootCAPath\|caCertPath\|idpCertPath"; done)

    # Set IFS to newline
    IFS=$'\n'
    # Loop through the variable FIELDS and split by new lines and feed array PEM_FILES
    while read -r line; do
        PEM_FILES+=($(echo "$line" | awk '{print $(NF)}'))
    done <<< "$FIELDS"
    # Reset IFS to its original value
    IFS=' '
}

# Remove duplicates from array PEM_FILES
function remove_duplicates() {
    # trim, sort & trim local unique_array to get rid of duplicates
    local unique_array=($(echo "${PEM_FILES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    # overwrite array PEM_FILES with unique_array
    PEM_FILES=(${unique_array[@]})
}

# Get end_date of pem_file
function get_end_date() {
    end_date=$(openssl x509 -noout -enddate -in "$1" 2>/dev/null | sed -n 's/notAfter=//p')
}

# Get serial of pem_file
function get_serial() {
    serial=$(openssl x509 -noout -serial -in "$1" 2>/dev/null | sed -n 's/serial=//p')
}

# Get issuer CN of the pem_file
function get_issuer_cn () {
    issuer_cn=$(openssl x509 -noout -issuer -in "$1" 2>/dev/null | awk -F 'CN=' '{ print $(NF) }')
}

# ---
# MAIN
# ---

# use BTOOL
if $BTOOL_CHECK; then
   where_is_waldo
fi

# remove duplictes from array PEM_FILES
remove_duplicates

# Loop through each .pem file
for pem_file in "${PEM_FILES[@]}"; do
    # change $SPLUNK_HOME string against variable
    pem_file=$(echo "${pem_file/\$SPLUNK_HOME/$SPLUNK_HOME}") 

    # Check if the file is readable
    if [ -r "$pem_file" ]; then
        # Skip certificates in DER format
        if [ "$(file -b --mime-type "$pem_file")" != "application/x-x509-ca-cert" ]; then
            # Get end date of the pem file
            get_end_date $pem_file
            # Get serial of the pem file
            get_serial $pem_file
            # Get issuer CN of the pem file
            get_issuer_cn $pem_file
            # Skip if end date is not defined
            if [[ ! -z "$end_date" ]]; then
                # Make it epoch
                epoch=$(date -d "${end_date}" +%s.%6N)
                # Print results
                printf "log_level=\"INFO\" cert=\"$pem_file\" expires=\"$end_date\" expires_epoch=\"$epoch\" serial=\"$serial\" issuer=\"$issuer_cn\"\n"
            fi
        fi
    fi
done
