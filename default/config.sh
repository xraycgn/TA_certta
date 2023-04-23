#
# Copy this file to local/config.sh and make your individual configurations 
# 

# Define the path to search for .pem files
SPLUNK_HOME="/opt/splunk"

# Check for certificate with BTOOL
# when true (default) BTOOL will be used
# if false only pem from PEM_FILES will be used
BTOOL_CHECK=true

# list of PEM_FILES including path outside of SPLUNK_HOME
# PEM_FILES=("/path/a/z.pem" "/path/c/y.pem")
PEM_FILES=()
