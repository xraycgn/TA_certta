#!/bin/bash

# --------
# cert.sh
# - version 1.0 - initial
# - version 1.1 - different PEM file handling as the list of results was to confusing
# - version 1.2 - using Splunk BTOOL to find certificates
# - version 1.2.1 - code cleanup as the only option is BTOOL plus extra PEM_FILES
# - version 1.2.2 - remove duplicates from array PEM_FILES

# ---
# VARS
# ---

# Define the path to search for .pem files
if [ -z ${SPLUNK_HOME+x} ]; then
    SPLUNK_HOME="/opt/splunk" # Directory path to search for conf files
fi

# Check for certificate with BTOOL
# when true (default) BTOOL will be used
# if false only pem from PEM_FILES will be used
BTOOL_CHECK=true

# list of PEM_FILES including path outside of SPLUNK_HOME
# PEM_FILES=("/path/a/z.pem" "/path/c/y.pem")
PEM_FILES=()

# ---
# FUNCTIONS
# ---

# Find pem with Splunk BTOOL
function where_is_waldo() {
    # run BTOOL and feed variable FIELDS
    FIELDS=$(for i in inputs server outputs web; do $SPLUNK_HOME/bin/splunk btool $i list --debug | grep -iv "sslVerifyServerCert" | grep -i "serverCert\|caCertFile\|sslRootCAPath"; done)

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

# Get issuer common name (cn) of pem_file
function get_issuer() {
    issuer=$(openssl x509 -noout -issuer -in "$1" 2>/dev/null | sed -n 's/.*CN[[:space:]]=[[:space:]]//p' | awk -F ',' '{print $1}')
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

	    # Get issuer of the pem file
	    get_issuer $pem_file

            # Get serial of the pem file
            get_serial $pem_file

            # Skip if end date is not defined
            if [[ ! -z "$end_date" ]]; then

                # Make it epoch
                epoch=$(date -d "${end_date}" +%s)

                # Print results
		printf "cert='$pem_file' expires='$end_date' expires_epoch='$epoch' serial='$serial' issuer='$issuer'\n"
            fi
        fi
    fi
done
