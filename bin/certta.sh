#!/bin/bash

# --------
# cert.sh
# - version 1.0 - initial
# - version 1.1 - different PEM file handling as the list of results was to confusing
# - version 1.2 - using Splunk BTOOL to find certificates
# - version 1.2.1 - code cleanup as the only option is BTOOL plus extra PEM_FILES

# ---
# VARS
# ---
# Define the path to search for .pem files
if [ -z ${SPLUNK_HOME+x} ]; then
    SPLUNK_HOME="/opt/splunk" # Directory path to search for conf files
fi

# Check for certificate with BTOOL
# when true (defaukt) BTOOL will be used
BTOOL_CHECK=true

# list of PEM_FILES including path outside of SPLUNK_HOME
# PEM_FILES=("/path/a/z.pem" "/path/c/y.pem")
PEM_FILES=()

# List of wildcard exclusion patterns
# EXCLUSION_PATTERNS=("*.log" "*.txt" "*.old")
EXCLUSION_PATTERNS=(
    "*python_upgrade_readiness_app*"
    "*splunk_secure_gateway*" 
)

# ---
# FUNCTIONS
# ---
# Function to check if a file matches any exclusion patterns
function is_excluded() {
    local file="$1"
    for pattern in "${EXCLUSION_PATTERNS[@]}"; do
	    if [[ $file == $pattern ]]; then
    	    return 0 # File is excluded
    	fi
    done
    return 1 # File is not excluded
}

# Find pem with Splunk btool
function where_is() {
    FIELDS=$(for i in inputs server outputs web; do $SPLUNK_HOME/bin/splunk btool $i list --debug | grep -iv "sslVerifyServerCert" | grep -i "serverCert\|caCertFile\|sslRootCAPath"; done)

    # Set IFS to newline
    IFS=$'\n'

    # Loop through the variable and split by new lines
    while read -r line; do
        PEM_FILES+=($(echo "$line" | awk '{print $(NF)}'))
    done <<< "$FIELDS"

    # Reset IFS to its original value
    IFS=' '
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
    #issuer=$(openssl x509 -noout -issuer -in "$1" 2>/dev/null | awk -F ',' '{print $(NF-1)}' | sed -e 's/ //g' | sed -n 's/CN=//p')
    issuer=$(openssl x509 -noout -issuer -in "$1" 2>/dev/null | sed -n 's/.*CN[[:space:]]=[[:space:]]//p' | awk -F ',' '{print $1}')
}

# Print results
function print_results() {
    if [[ ! -z "$conf_file" ]]; then
    	printf "cert='$pem_file' expires='$end_date' expires_epoch='$epoch' serial='$serial' conf='$conf_file'\n"
    else
        printf "cert='$pem_file' expires='$end_date' expires_epoch='$epoch' serial='$serial' conf='NONE'\n"
    fi
}

# ---
# MAIN
# ---

# use btool
if $BTOOL_CHECK; then
   where_is
fi

# Loop through each .pem file
for pem_file in "${PEM_FILES[@]}"; do
    # Check if the file matches any exclusion patterns
    if is_excluded "$pem_file"; then
        continue # Skip excluded files
    fi
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
                # print_results
		printf "cert='$pem_file' expires='$end_date' expires_epoch='$epoch' serial='$serial' issuer='$issuer'\n"
            fi
        fi
    fi
done
