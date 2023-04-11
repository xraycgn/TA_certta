#!/bin/bash

# --------
# cert.sh 
# - version 1.0 - initial

# ---
# VARS
# ---
# Define the path to search for .pem files
if [ -z ${SPLUNK_HOME+x} ]; then 
    SPLUNK_HOME="/opt/splunk" # Directory path to search for conf files
fi

# list of PEM_FILES including path outside of SPLUNK_HOME
# PEM_FILES=("/path/a/z.pem" "/path/c/y.pem")
PEM_FILES=("/home/Matze/server.pem")

# INCLUSION_PATTERN to search for in the conf files
INCLUSION_PATTERN="serverCert"  

# List of wildcard exclusion patterns
# EXCLUSION_PATTERNS=("*.log" "*.txt" "*.old")
EXCLUSION_PATTERNS=(
	"*python_upgrade_readiness_app*" 
	"*CA.pem" 
	"*splunk_secure_gateway*"
	"*baseline*" 
	"*var/run*"
	"*site-packages*")

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

# Search for .pem files in the given path recursively and add to array PEM_FILES`
function where_is_pem() {
	if [ -d "$SPLUNK_HOME" ]; then
    		PEM_FILES+=($(find "$SPLUNK_HOME" -name "*.pem" -type f))
	fi
}

# Find conf files in the search path
function where_is_conf() {
	if [ -d "$SPLUNK_HOME" ]; then
        CONF_FILES+=($(find "$SPLUNK_HOME" -name "*.conf" -type f))
    fi
}

# Get end_date of pem_file
function get_end_date() { 
	#end_date=$(openssl x509 -noout -enddate -in "$pem_file" | awk -F '=' '{print $2}')
	#end_date=$(openssl x509 -enddate -noout -in "$pem_file" 2>/dev/null | sed -n 's/notAfter=//p')
	end_date=$(openssl x509 -enddate -noout -in "$1" 2>/dev/null | sed -n 's/notAfter=//p') 
}

# Get serial of pem_file
function get_serial() { 
	#serial=$(openssl x509 -noout -serial -in "$pem_file" 2>/dev/null | sed -n 's/serial=//p')
	serial=$(openssl x509 -noout -serial -in "$1" 2>/dev/null | sed -n 's/serial=//p') 
}

# Print results
function print_results() { 
	if [[ ! -z "$conf_file" ]]; then
		printf "path=$pem_file expires='$end_date' expires_epoch=$epoch serial=$serial conf=$conf_file\n"
	else 
		printf "path=$pem_file expires='$end_date' expires_epoch=$epoch serial=$serial conf=NONE\n"                
	fi
}

# ---
# MAIN 
# ---
where_is_pem

# Loop through each .pem file
for pem_file in "${PEM_FILES[@]}"; do
    # Check if the file matches any exclusion patterns
    if is_excluded "$pem_file"; then
    	continue # Skip excluded files
    fi 
    # Check if the file is readable
    if [ -r "$pem_file" ]; then
		# Skip certificates in DER format
    	if [ "$(file -b --mime-type "$pem_file")" != "application/x-x509-ca-cert" ]; then
	        # Get end date of the pem file
			get_end_date $pem_file
			# Get serial of the pem file
			get_serial $pem_file
			# Skip if end date is not defined
			if [[ ! -z "$end_date" ]]; then
            	# Make it epoch
            	epoch=$(date -d "${end_date}" +%s)
				# Print results
				print_results
            fi
		fi
    fi
done

where_is_conf

for conf_file in ${CONF_FILES[@]}; do
    # Check if the file matches any exclusion EXCLUSION_PATTERNS
    if is_excluded "$conf_file"; then
		continue # Skip excluded files
	fi
    # Search for INCLUSION_PATTERN in the conf file
    result=$(grep -E "$INCLUSION_PATTERN" "$conf_file")
    # If INCLUSION_PATTERN is found
    if [[ ! -z "$result" ]]; then
        # Extract pem file path from the result
        pem_file=$(echo "$result" | awk -F '=' '{print $2}' | tr -d ' ')
        pem_file=$(echo "${pem_file/\$SPLUNK_HOME/$SPLUNK_HOME}")
        # Check if pem file is readable
        if [[ -r "$pem_file" ]]; then
            # Check if pem file is in PEM format
            if [ "$(file -b --mime-type "$pem_file")" != "application/x-x509-ca-cert" ]; then
                # Get end date of the pem file
				get_end_date $pem_file
				# Get serial of the pem file
				get_serial $pem_file
                # Skip if end date is not defined
                if [[ ! -z "$end_date" ]]; then
                    # Make it epoch
                	epoch=$(date -d "${end_date}" +%s)
				    # Print results
					print_results
                fi
            fi
        fi
    fi
done
