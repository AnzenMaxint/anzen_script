#!/bin/bash

set -uo pipefail

# Global Variables
ASCI_WHITE='\033[01;37m'
ASCI_RESTORE='\033[0m'
ASCI_RED='\033[00;31m'
ASCI_GREEN='\033[00;32m'
ASCI_YELLOW='\033[00;33m'
ASCI_BLUE='\033[00;34m'
ASCI_PURPLE='\033[00;35m'
ANZENx_EXPRESS_COMPLETE=""

function WHITE {
  echo "${ASCI_WHITE}${1-}${ASCI_RESTORE}"
}
function RED {  # Generally used for ERROR
  echo "${ASCI_RED}${1-}${ASCI_RESTORE}"
}
function GREEN {  # Generally used for SUCCESS messages
  echo "${ASCI_GREEN}${1-}${ASCI_RESTORE}"
}
function YELLOW { # Generally used for WARNING messages
  echo "${ASCI_YELLOW}${1-}${ASCI_RESTORE}"
}
function BLUE {   # Generally used for directory paths
  echo "${ASCI_BLUE}${1-}${ASCI_RESTORE}"
}
function PURPLE { # Generally used for Express Install milestones.
  echo "${ASCI_PURPLE}${1-}${ASCI_RESTORE}"
}

function _wait_for_controller {
  local advertised_host_port="${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}:${ANZEN_CTRL_EDGE_ADVERTISED_PORT}"
  while [[ "$(curl -w "%{http_code}" -m 1 -s -k -o /dev/null https://"${advertised_host_port}"/edge/client/v1/version)" != "200" ]]; do
    echo "waiting for https://${advertised_host_port}"
    sleep 3
  done
}

function _wait_for_public_router {
  local advertised_host_port="${ANZEN_ROUTER_ADVERTISED_ADDRESS}:${ANZEN_ROUTER_PORT}"
  local COUNTDOWN=10
  until [[ -s "${ANZEN_HOME}/${ANZEN_ROUTER_NAME}.cert" ]] \
    && openssl s_client \
      -connect "${advertised_host_port}" \
      -servername "${ANZEN_ROUTER_ADVERTISED_ADDRESS}" \
      -alpn "anzen-edge,h2,http/1.1" \
      -cert "${ANZEN_HOME}/${ANZEN_ROUTER_NAME}.cert" \
      -key "${ANZEN_HOME}/${ANZEN_ROUTER_NAME}.key" \
      <>/dev/null 2>&1 # client cert needed for a zero exit code
  do
    if (( COUNTDOWN-- )); then
      echo "INFO: waiting for https://${advertised_host_port}"
      sleep 3
    else
      echo "ERROR: timed out waiting for https://${advertised_host_port}" >&2
      return 1
    fi
  done
}

function _setup_anzen_home {
  _setup_anzen_network
  if [[ "${ANZEN_HOME-}" == "" ]]; then export ANZEN_HOME="${HOME}/.anzen/quickstart/${ANZEN_NETWORK-}"; else echo "ANZEN_HOME overridden: ${ANZEN_HOME}"; fi
}

function _setup_anzen_env_path {
  _setup_anzen_network
  _setup_anzen_home
  if [[ "${ANZEN_ENV_FILE-}" == "" ]]; then export ANZEN_ENV_FILE="${ANZEN_HOME}/${ANZEN_NETWORK}.env"; else echo "ANZEN_ENV_FILE overridden: ${ANZEN_ENV_FILE}"; fi
}


function _setup_anzen_network {
  if [[ "ran" != "${_setup_anzen_network_run}" ]]; then
    if [[ "${ANZEN_NETWORK-}" == "" ]]; then ANZEN_NETWORK="$(hostname)"; export ANZEN_NETWORK; else echo "ANZEN_NETWORK overridden: ${ANZEN_NETWORK}"; fi
    _setup_anzen_network_run="ran"
  fi
}

function _set_anzen_bin_dir {
  if [[ "${ANZEN_BIN_DIR-}" == "" ]]; then export ANZEN_BIN_DIR="${ANZEN_HOME}/anzen-bin/anzen-${ANZEN_BINARIES_VERSION}"; else echo "ANZEN_BIN_DIR overridden: ${ANZEN_BIN_DIR}"; fi
}

function _get_file_overwrite_permission {
  local file_path="${1-}"

  if [[ -f "${file_path}" ]]; then
    echo -en "This will overwrite the existing file, continue? (y/N) "
    read -r
    if [[ "${REPLY}" == [^Yy]* ]]; then
      echo -e "$(RED "  --- Cancelling overwrite ---")"
      return 1
    fi

    return 0
  fi
}

# removes duplicate strings in a list
function _dedupe_list {
  local list delimiter retVal
  list=${1-}
  if [[ "${list}" == "" ]]; then
    return 1
  fi
  delimiter=${2-}
  if [[ "${delimiter}" == "" ]]; then
    delimiter=","
  fi

  echo "${list}" | tr "'${delimiter}'" '\n' | sort -u | xargs | tr ' ' ','
}

# Checks if a value is likely an IP address
function _is_ip {
  local param pattern
  param="${1}"
  pattern="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
  if [[ "${param}" =~ $pattern ]]; then
    return 0
  fi
  return 1
}

function _pki_client_server {
  local retVal dns_allow_list ANZEN_CA_NAME_local ip_allow_list file_name
  _check_env_variable ANZEN_PKI ANZEN_BIN_DIR
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi
  dns_allow_list=${1-}
  ANZEN_CA_NAME_local=$2
  ip_allow_list=$3
  file_name=$4

  if [[ "${ip_allow_list}" == "" ]]; then
    ip_allow_list="127.0.0.1"
  fi

  # Dedupe the lists
  dns_allow_list=$(_dedupe_list "${dns_allow_list}")
  ip_allow_list=$(_dedupe_list "${ip_allow_list}")

  if ! test -f "${ANZEN_PKI}/${ANZEN_CA_NAME_local}/keys/${file_name}-server.key"; then
    echo "Creating server cert from ca: ${ANZEN_CA_NAME_local} for ${dns_allow_list} / ${ip_allow_list}"
    "${ANZEN_BIN_DIR-}/anzen" pki create server --pki-root="${ANZEN_PKI}" --ca-name "${ANZEN_CA_NAME_local}" \
          --server-file "${file_name}-server" \
          --dns "${dns_allow_list}" --ip "${ip_allow_list}" \
          --server-name "${file_name} server certificate"
  else
    echo "Creating server cert from ca: ${ANZEN_CA_NAME_local} for ${dns_allow_list}"
    echo "key exists"
  fi

  if ! test -f "${ANZEN_PKI}/${ANZEN_CA_NAME_local}/keys/${file_name}-client.key"; then
    echo "Creating client cert from ca: ${ANZEN_CA_NAME_local} for ${dns_allow_list}"
    "${ANZEN_BIN_DIR-}/anzen" pki create client --pki-root="${ANZEN_PKI}" --ca-name "${ANZEN_CA_NAME_local}" \
          --client-file "${file_name}-client" \
          --key-file "${file_name}-server" \
          --client-name "${file_name}"
  else
    echo "Creating client cert from ca: ${ANZEN_CA_NAME_local} for ${dns_allow_list}"
    echo "key exists"
  fi
  echo " "
}

function _pki_create_ca {
  local cert retVal
  _check_env_variable ANZEN_PKI ANZEN_BIN_DIR
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi
  cert="${1}"

  echo "Creating CA: ${cert}"
  if ! test -f "${ANZEN_PKI}/${cert}/keys/${cert}.key"; then
    "${ANZEN_BIN_DIR}/anzen" pki create ca --pki-root="${ANZEN_PKI}" --ca-file="${cert}" --ca-name="${cert} Root CA"
  else
    echo "key exists"
  fi
  echo " "
}

function _pki_create_intermediate {
  local retVal
  _check_env_variable ANZEN_PKI ANZEN_BIN_DIR
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi
  echo "Creating intermediate: ${1} ${2} ${3}"
  if ! test -f "${ANZEN_PKI}/${2}/keys/${2}.key"; then
    "${ANZEN_BIN_DIR}/anzen" pki create intermediate --pki-root "${ANZEN_PKI}" --ca-name "${1}" \
          --intermediate-name "${2}" \
          --intermediate-file "${2}" --max-path-len "${3}"
  else
    echo "key exists"
  fi
  echo " "
}

# Checks that a specific command or set of commands exist on the path
function _check_prereq {
  local missing_requirements="" arg
  for arg
  do
    if ! [[ -x "$(command -v "${arg}")" ]]; then
      missing_requirements="${missing_requirements}\n* ${arg}"
    fi
  done
  # Are requirements missing if yes, stop here and help 'em out
  if ! [[ "" = "${missing_requirements}" ]]; then
      echo " "
      echo "You're missing one or more commands that are used in this script."
      echo "Please ensure the commands listed are on the path and then try again."
      echo -e "${missing_requirements}"
      echo " "
      echo " "
      return 1
  fi
}

# Disable shellcheck for parameter expansion error, this function supports multiple shells
# shellcheck disable=SC2296
# Check if an environment variable is set, if not, throw an error
function _check_env_variable() {
  local _error=false arg
  for arg
  do
    # Parameter expansion is different between shells
    if [[ -n "$ZSH_VERSION" ]]; then
      if [[ -z "${(P)arg}" ]]; then
        echo -e "  * ERROR: $(RED "${arg} is not set") "
        _error=true
      fi
    elif [[ -n "$BASH_VERSION" ]]; then
      if [[ -z "${!arg}" ]]; then
        echo -e "  * ERROR: $(RED "${arg} is not set") "
        _error=true
      fi
    else
      echo -e " * $(RED "Unsupported shell, supply a PR or log an issue on https://github.com/openanzen/anzen") "
      return 1
    fi
  done

  if [[ "true" == "${_error}" ]]; then
    return 1
  else
    return 0
  fi
}

function _issue_preamble {
  echo -e "$(PURPLE "-------------------------------------------------------------")"
  echo ""
  echo -e "$(PURPLE "-------------------------------------------------------------")"
  echo ""
  echo "This script will make it trivial to set up a very simple environment locally which will allow you to start"
  echo "learning anzen. This environment is suitable for development work only and is not a decent representation of"
  echo "a fully redundant production-caliber network."
  echo ""
}

function _issue_greeting {
  echo "Please note that, by default, this script will write files to your home directory into a directory named .anzen."
  echo -n "The currently configured location for these files will be: "
  echo -e "$(BLUE "${ANZEN_HOME}")"
  echo ""
  echo ""
  echo "  \----------------------------------\ "
  echo "   \                                  \        __ "
  echo "    \         Welcome To:              \       | \ "
  echo "     >        Anzen Express 2.0          >------|  \       ______ "
  echo "    /                                  /       --- \_____/**|_|_\____  | "
  echo "   /                                  /          \_______ --------- __>-} "
  echo "  /----------------------------------/              /  \_____|_____/   | "
  echo "                                                    *         | "
  echo "                                                             {O} "
  echo ""
  echo "Let's get started creating your local development network!"
  echo ""
}

# Clear all environment variables prefixed with ANZEN_ (use -s parameter to do so without any output)
function unsetAnzenEnv {
  local param1 zEnvVar envvar
  param1="${1-}"
  for zEnvVar in $(set | grep -e "^ANZEN_" | sort); do
    envvar="$(echo "${zEnvVar}" | cut -d '=' -f1)"
    if [[ "-s" != "${param1-}" ]]; then echo "unsetting [${envvar}] ${zEnvVar}"; fi
    unset "${envvar}"
  done
  # Have to explicitly unset these (no ANZEN_ prefix)
  unset ANZENx_EXPRESS_COMPLETE
  unset _setup_anzen_network_run
}

# Checks for explicit environment variables or set as defaults, also creating directories as needed
function setupEnvironment {
  local pwd_reply
  echo "Populating environment variables"
  # General Anzen Values
  _setup_anzen_network
  _setup_anzen_home

  # Get Controller Credentials
  if [[ "${ANZEN_USER-}" == "" ]]; then export ANZEN_USER="admin"; else echo "ANZEN_USER overridden: ${ANZEN_USER}"; fi
  if [[ "${ANZEN_PWD-}" == "" ]]; then
    ANZEN_PWD="$(LC_ALL=C tr -dc _A-Z-a-z-0-9 < /dev/urandom | head -c32)"
    echo -en "Do you want to keep the generated admin password '$ANZEN_PWD'? (Y/n) "
    # shellcheck disable=SC2162
    read -r pwd_reply
    if [[ -z "${pwd_reply}" || ${pwd_reply} =~ [yY] ]]; then
      echo "INFO: using ANZEN_PWD=${ANZEN_PWD}"
    else
      echo -en "Type the preferred admin password and press <enter> "
      read -r ANZEN_PWD
    fi
  else
    echo "ANZEN_PWD overridden: ${ANZEN_PWD}"
  fi

  # PKI Values
  if [[ "${ANZEN_PKI-}" == "" ]]; then export ANZEN_PKI="${ANZEN_HOME}/pki"; else echo "ANZEN_PKI overridden: ${ANZEN_PKI}"; fi
  if [[ "${ANZEN_PKI_SIGNER_CERT_NAME-}" == "" ]]; then export ANZEN_PKI_SIGNER_CERT_NAME="${ANZEN_NETWORK}-signing"; else echo "ANZEN_PKI_SIGNER_CERT_NAME overridden: ${ANZEN_PKI_SIGNER_CERT_NAME}"; fi
  if [[ "${ANZEN_PKI_SIGNER_ROOTCA_NAME-}" == "" ]]; then export ANZEN_PKI_SIGNER_ROOTCA_NAME="${ANZEN_PKI_SIGNER_CERT_NAME}-root-ca"; else echo "ANZEN_PKI_SIGNER_ROOTCA_NAME overridden: ${ANZEN_PKI_SIGNER_ROOTCA_NAME}"; fi
  if [[ "${ANZEN_PKI_SIGNER_INTERMEDIATE_NAME-}" == "" ]]; then export ANZEN_PKI_SIGNER_INTERMEDIATE_NAME="${ANZEN_PKI_SIGNER_CERT_NAME}-intermediate"; else echo "ANZEN_PKI_SIGNER_INTERMEDIATE_NAME overridden: ${ANZEN_PKI_SIGNER_INTERMEDIATE_NAME}"; fi
  if [[ "${ANZEN_PKI_SIGNER_CERT}" == "" ]]; then export ANZEN_PKI_SIGNER_CERT="${ANZEN_PKI}/signing.pem"; else echo "ANZEN_PKI_SIGNER_CERT overridden: ${ANZEN_PKI_SIGNER_CERT}"; fi
  if [[ "${ANZEN_PKI_SIGNER_KEY}" == "" ]]; then export ANZEN_PKI_SIGNER_KEY="${ANZEN_PKI}/${ANZEN_PKI_SIGNER_INTERMEDIATE_NAME}/keys/${ANZEN_PKI_SIGNER_INTERMEDIATE_NAME}.key"; else echo "ANZEN_PKI_SIGNER_KEY overridden: ${ANZEN_PKI_SIGNER_KEY}"; fi

  # Run these functions to populate other pertinent environment values
  _detect_architecture    # ANZEN_ARCH
  _detect_OS              # ANZEN_OSTYPE
  getLatestAnzenVersion  # ANZEN_BINARIES_FILE & ANZEN_BINARIES_VERSION

  # Must run after the above (dependent on other variables)
  _set_anzen_bin_dir

  # Controller Values
  if [[ "${ANZEN_CTRL_NAME-}" == "" ]]; then export ANZEN_CTRL_NAME="${ANZEN_NETWORK}"; else echo "ANZEN_CTRL_NAME overridden: ${ANZEN_CTRL_NAME}"; fi
  if [[ "${ANZEN_CTRL_EDGE_NAME-}" == "" ]]; then export ANZEN_CTRL_EDGE_NAME="${ANZEN_NETWORK}-edge-controller"; else echo "ANZEN_CTRL_EDGE_NAME overridden: ${ANZEN_CTRL_EDGE_NAME}"; fi
  if [[ "${ANZEN_CTRL_EDGE_ADVERTISED_PORT-}" == "" ]]; then export ANZEN_CTRL_EDGE_ADVERTISED_PORT="1280"; else echo "ANZEN_CTRL_EDGE_ADVERTISED_PORT overridden: ${ANZEN_CTRL_EDGE_ADVERTISED_PORT}"; fi
  if [[ "${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS-}" == "" ]]; then export ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS="${ANZEN_NETWORK-}"; else echo "ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS overridden: ${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}"; fi
  if [[ "${ANZEN_CTRL_BIND_ADDRESS-}" != "" ]]; then echo "ANZEN_CTRL_BIND_ADDRESS overridden: ${ANZEN_CTRL_BIND_ADDRESS}"; fi
  if [[ "${ANZEN_CTRL_ADVERTISED_ADDRESS-}" == "" ]]; then export ANZEN_CTRL_ADVERTISED_ADDRESS="${ANZEN_NETWORK-}"; else echo "ANZEN_CTRL_ADVERTISED_ADDRESS overridden: ${ANZEN_CTRL_ADVERTISED_ADDRESS}"; fi
  if [[ "${ANZEN_CTRL_ADVERTISED_PORT-}" == "" ]]; then export ANZEN_CTRL_ADVERTISED_PORT="6262"; else echo "ANZEN_CTRL_ADVERTISED_PORT overridden: ${ANZEN_CTRL_ADVERTISED_PORT}"; fi
  if [[ "${ANZEN_PKI_CTRL_ROOTCA_NAME-}" == "" ]]; then export ANZEN_PKI_CTRL_ROOTCA_NAME="${ANZEN_CTRL_ADVERTISED_ADDRESS}-root-ca"; else echo "ANZEN_PKI_CTRL_ROOTCA_NAME overridden: ${ANZEN_PKI_CTRL_ROOTCA_NAME}"; fi
  if [[ "${ANZEN_PKI_CTRL_INTERMEDIATE_NAME-}" == "" ]]; then export ANZEN_PKI_CTRL_INTERMEDIATE_NAME="${ANZEN_CTRL_ADVERTISED_ADDRESS}-intermediate"; else echo "ANZEN_PKI_CTRL_INTERMEDIATE_NAME overridden: ${ANZEN_PKI_CTRL_INTERMEDIATE_NAME}"; fi
  if [[ "${ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME-}" == "" ]]; then export ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME="${ANZEN_CTRL_EDGE_NAME}-root-ca"; else echo "ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME overridden: ${ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME}"; fi
  if [[ "${ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME-}" == "" ]]; then export ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME="${ANZEN_CTRL_EDGE_NAME}-intermediate"; else echo "ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME overridden: ${ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME}"; fi
  if [[ "${ANZEN_PKI_CTRL_SERVER_CERT-}" == "" ]]; then export ANZEN_PKI_CTRL_SERVER_CERT="${ANZEN_PKI}/${ANZEN_PKI_CTRL_INTERMEDIATE_NAME}/certs/${ANZEN_CTRL_ADVERTISED_ADDRESS}-server.chain.pem"; else echo "ANZEN_PKI_CTRL_SERVER_CERT overridden: ${ANZEN_PKI_CTRL_SERVER_CERT}"; fi
  if [[ "${ANZEN_PKI_CTRL_KEY-}" == "" ]]; then export ANZEN_PKI_CTRL_KEY="${ANZEN_PKI}/${ANZEN_PKI_CTRL_INTERMEDIATE_NAME}/keys/${ANZEN_CTRL_ADVERTISED_ADDRESS}-server.key"; else echo "ANZEN_PKI_CTRL_KEY overridden: ${ANZEN_PKI_CTRL_KEY}"; fi
  if [[ "${ANZEN_PKI_CTRL_CA-}" == "" ]]; then export ANZEN_PKI_CTRL_CA="${ANZEN_PKI}/cas.pem"; else echo "ANZEN_PKI_CTRL_CA overridden: ${ANZEN_PKI_CTRL_CA}"; fi
  if [[ "${ANZEN_PKI_CTRL_CERT-}" == "" ]]; then export ANZEN_PKI_CTRL_CERT="${ANZEN_PKI}/${ANZEN_PKI_CTRL_INTERMEDIATE_NAME}/certs/${ANZEN_CTRL_ADVERTISED_ADDRESS}-client.cert"; else echo "ANZEN_PKI_CTRL_CERT overridden: ${ANZEN_PKI_CTRL_CERT}"; fi
  if [[ "${ANZEN_PKI_EDGE_CERT-}" == "" ]]; then export ANZEN_PKI_EDGE_CERT="${ANZEN_PKI}/${ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME}/certs/${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}-client.cert"; else echo "ANZEN_PKI_EDGE_CERT overridden: ${ANZEN_PKI_EDGE_CERT}"; fi
  if [[ "${ANZEN_PKI_EDGE_SERVER_CERT}" == "" ]]; then export ANZEN_PKI_EDGE_SERVER_CERT="${ANZEN_PKI}/${ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME}/certs/${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}-server.chain.pem"; else echo "ANZEN_PKI_EDGE_SERVER_CERT overridden: ${ANZEN_PKI_EDGE_SERVER_CERT}"; fi
  if [[ "${ANZEN_PKI_EDGE_KEY}" == "" ]]; then export ANZEN_PKI_EDGE_KEY="${ANZEN_PKI}/${ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME}/keys/${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}-server.key"; else echo "ANZEN_PKI_EDGE_KEY overridden: ${ANZEN_PKI_EDGE_KEY}"; fi
  if [[ "${ANZEN_PKI_EDGE_CA}" == "" ]]; then export ANZEN_PKI_EDGE_CA="${ANZEN_PKI}/${ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME}/certs/${ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME}.cert"; else echo "ANZEN_PKI_EDGE_CA overridden: ${ANZEN_PKI_EDGE_CA}"; fi

  # Router Values
  if [[ "${ANZEN_ROUTER_NAME-}" == "" ]]; then export ANZEN_ROUTER_NAME="${ANZEN_NETWORK}-edge-router"; else echo "ANZEN_ROUTER_NAME overridden: ${ANZEN_ROUTER_NAME}"; fi
  if [[ "${ANZEN_ROUTER_PORT-}" == "" ]]; then export ANZEN_ROUTER_PORT="3022"; else echo "ANZEN_ROUTER_PORT overridden: ${ANZEN_ROUTER_PORT}"; fi
  if [[ "${ANZEN_ROUTER_LISTENER_BIND_PORT-}" == "" ]]; then export ANZEN_ROUTER_LISTENER_BIND_PORT="10080"; else echo "ANZEN_ROUTER_LISTENER_BIND_PORT overridden: ${ANZEN_ROUTER_LISTENER_BIND_PORT}"; fi
  if [[ "${EXTERNAL_DNS-}" != "" ]]; then export ANZEN_ROUTER_ADVERTISED_ADDRESS="${EXTERNAL_DNS}"; fi

  # Set up directories
  mkdir -p "${ANZEN_HOME}"
  mkdir -p "${ANZEN_HOME}/db"
  mkdir -p "${ANZEN_PKI}"

  _setup_anzen_env_path

  echo -e "$(GREEN "Your OpenAnzen environment has been set up successfully.")"
  echo ""
}

# Stores environment variables prefixed with ANZEN_ to a .env file
function persistEnvironmentValues {
  local filepath tmpfilepath retVal envval envvar zEnvVar
  # Get the file path
  filepath="${1-}"
  if [[ "" == "${filepath}" ]]; then
    _check_env_variable ANZEN_ENV_FILE
    retVal=$?
    if [[ "${retVal}" != 0 ]]; then
      echo -e "$(RED "  --- persistEnvironment must take a parameter or have ANZEN_ENV_FILE set ---")"
      return 1
    else
      filepath="${ANZEN_ENV_FILE}"
    fi
  fi

  # Store all ANZEN_ variables in the environment file, creating the directory if necessary
  tmpfilepath="$(mktemp)"
  mkdir -p "$(dirname "${filepath}")" && echo "" > "${tmpfilepath}"
  for zEnvVar in $(set | grep -e "^ANZEN_" | sed "s/='\(.*\)'\$/=\1/" | sort); do
      envvar="$(echo "${zEnvVar}" | cut -d '=' -f1)"
      envval="$(echo "${zEnvVar}" | cut -d '=' -f2-1000)"
      echo 'if [[ "$'${envvar}'" == "" ]]; then export '${envvar}'="'${envval}'"; else echo "NOT OVERRIDING: env var '${envvar}' already set. using existing value"; fi' >> "${tmpfilepath}"
  done

  export PFXLOG_NO_JSON=true
  # shellcheck disable=SC2129
  echo "export PFXLOG_NO_JSON=true" >> "${tmpfilepath}"

  echo "alias zec='anzen edge'" >> "${tmpfilepath}"
  echo "alias anzenLogin='anzen edge login \"\${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}:\${ANZEN_CTRL_EDGE_ADVERTISED_PORT}\" -u \"\${ANZEN_USER-}\" -p \"\${ANZEN_PWD}\" -y'" >> "${tmpfilepath}"
  echo "alias psz='ps -ef | grep anzen'" >> "${tmpfilepath}"

  #when sourcing the emitted file add the bin folder to the path
  cat >> "${tmpfilepath}" <<'HEREDOC'
echo " "
if [[ ! "$(echo "$PATH"|grep -q "${ANZEN_BIN_DIR}" && echo "yes")" == "yes" ]]; then
  echo "adding ${ANZEN_BIN_DIR} to the path"
  export PATH=$PATH:"${ANZEN_BIN_DIR}"
else
echo    "                  anzen binaries are located at: ${ANZEN_BIN_DIR}"
echo -e 'add this to your path if you want by executing: export PATH=$PATH:'"${ANZEN_BIN_DIR}"
echo " "
fi
HEREDOC

  mv "${tmpfilepath}" "${filepath}"
  echo -e "A file with all pertinent environment values was created here: $(BLUE "${filepath}")"
  echo ""
}

# Clears environment variables prefixed with ANZEN_, and removes anzen environment directories
function removeAnzenEnvironment {
  local specifiedVersion=""
  # No need to `_check_env_variable ANZEN_VERSION_OVERRIDE ANZEN_BINARIES_VERSION` as this will still run if they're blank
  echo -e "$(GREEN "Clearing existing Anzen variables and continuing with express install")"

  # Check if the user chose a specific version
  if [[ "${ANZEN_VERSION_OVERRIDE-}" != "" ]] && [[ "${ANZEN_VERSION_OVERRIDE-}" != "${ANZEN_BINARIES_VERSION-}" ]]; then
    # Don't allow overriding the version if anzen quickstart was already run, the DB may not be compatible
    echo -e "$(RED "  --- Overriding the anzen version is not supported if the version differs from one already installed. ---")"
    echo -en "Would you like to continue by using the latest version? (y/N) "
    read -r
    echo " "
    if [[ "${REPLY}" == [Yy]* ]]; then
      unset ANZEN_VERSION_OVERRIDE
    else
      return 1
    fi
  elif [[ "${ANZEN_VERSION_OVERRIDE-}" != "" ]]; then
    echo -e "$(RED "  --- You have set the ANZEN_VERSION_OVERRIDE value to ${ANZEN_VERSION_OVERRIDE}. ---")"
    echo -en "Would you like to use this version again, choosing no will pull the latest version? (y/N) "
    read -r
    echo " "
    if [[ "${REPLY}" == [Yy]* ]]; then
      specifiedVersion="${ANZEN_VERSION_OVERRIDE}"
    fi
  fi

  if [[ "${specifiedVersion}" != "" ]]; then
    export ANZEN_VERSION_OVERRIDE="${specifiedVersion}"
  fi

  # Stop any devices currently running to avoid port collisions
  stopRouter
  stopController

  # Silently clear anzen variables (must be done after stopRouter and stopController)
  unsetAnzenEnv "-s"
}

function startController {
  local retVal log_file pid
  _check_env_variable ANZEN_HOME ANZEN_BIN_DIR ANZEN_CTRL_NAME
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi
  log_file="${ANZEN_HOME-}/${ANZEN_CTRL_NAME}.log"
  "${ANZEN_BIN_DIR-}/anzen" controller run "${ANZEN_HOME}/${ANZEN_CTRL_NAME}.yaml" &> "${log_file}" 2>&1 &
  pid=$!
  echo -e "anzen controller started as process id: ${pid}. log located at: $(BLUE "${log_file}")"
}

# Disable unused args shellcheck, the arg is optional
#shellcheck disable=SC2120
function stopController {
  local pid retVal
  pid=${1-}
  if [[ "${pid}" == "" ]]; then
    _check_env_variable ANZEN_CTRL_EDGE_ADVERTISED_PORT
    retVal=$?
    if [[ "${retVal}" != 0 ]]; then
      echo "You will need to source the anzen env file first or set ANZEN_CTRL_EDGE_ADVERTISED_PORT so that the controller process can be found"
      return 1
    fi

    # Get the pid listening on the controller port
    pid=$(lsof -ti:"${ANZEN_CTRL_EDGE_ADVERTISED_PORT}")
  fi

  if [[ -n ${pid:-} ]]; then
    kill "${pid}" > /dev/null 2>&1
    if [[ $? == 0 ]]; then
      echo "Controller stopped."
      return 0
    else
      echo "ERROR: Something went wrong while trying to stop the controller."
      return 1
    fi
  else
    echo "No process found."
  fi
}

function startRouter {
  local pid retVal log_file
  _check_env_variable ANZEN_HOME ANZEN_ROUTER_NAME ANZEN_BIN_DIR
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi
  log_file="${ANZEN_HOME}/${ANZEN_ROUTER_NAME}.log"
  "${ANZEN_BIN_DIR}/anzen" router run "${ANZEN_HOME}/${ANZEN_ROUTER_NAME}.yaml" > "${log_file}" 2>&1 &
  pid=$!
  echo -e "Express Edge Router started as process id: ${pid}. log located at: $(BLUE "${log_file}")"
}

# Disable unused args shellcheck, the arg is optional
#shellcheck disable=SC2120
function stopRouter {
  local pid retVal
  pid=${1-}
  if [[ "${pid}" == "" ]]; then
    _check_env_variable ANZEN_ROUTER_PORT
    retVal=$?
    if [[ "${retVal}" != 0 ]]; then
      echo "You will need to source the anzen env file first so that the router process can be found"
      return 1
    fi

    # Get the pid listening on the controller port
    pid=$(lsof -ti:"${ANZEN_ROUTER_PORT}")
  fi

  if [[ -n ${pid:-} ]]; then
    kill "${pid}" > /dev/null 2>&1
    if [[ $? == 0 ]]; then
      echo "Router stopped."
      return 0
    else
      echo "ERROR: Something went wrong while trying to stop the router." >&2
      return 1
    fi
  else
    echo "No process found."
  fi
}

# Checks all ports intended to be used in the Anzen network
function checkAnzenPorts {
    local returnCnt=0
    _portCheck "ANZEN_CTRL_ADVERTISED_PORT" "Controller"
    returnCnt=$((returnCnt + $?))
    _portCheck "ANZEN_ROUTER_PORT" "Edge Router"
    returnCnt=$((returnCnt + $?))
    _portCheck "ANZEN_CTRL_EDGE_ADVERTISED_PORT" "Edge Controller"
    returnCnt=$((returnCnt + $?))
    if [[ "${ANZEN_ROUTER_LISTENER_BIND_PORT-}" != "" ]]; then
      # This port can be explicitly set but is not always, only check if set
      _portCheck "ANZEN_ROUTER_LISTENER_BIND_PORT" "Router Listener Bind Port"
      returnCnt=$((returnCnt + $?))
    fi
    if [[ "returnCnt" -gt "0" ]]; then return 1; fi
    echo -e "$(GREEN "Expected ports are all available")"
    echo ""
}

# Detect which OS the script is running on and store it in a variable
function _detect_OS {
  if [ -n "${ANZEN_OSTYPE}" ]; then return; fi
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
          export ANZEN_OSTYPE="linux"
  elif [[ "$OSTYPE" == "darwin"* ]]; then
          export ANZEN_OSTYPE="darwin"
  elif [[ "$OSTYPE" == "cygwin" ]]; then
          export ANZEN_OSTYPE="windows"
  elif [[ "$OSTYPE" == "msys" ]]; then
          export ANZEN_OSTYPE="windows"
  elif [[ "$OSTYPE" == "win32" ]]; then
          export ANZEN_OSTYPE="windows"
  elif [[ "$OSTYPE" == "freebsd"* ]]; then
          echo -e "  * ERROR: $(RED "\$OSTYPE [$OSTYPE] is not supported at this time") "
          return 1
  else
          echo -e "  * ERROR: $(RED "\$OSTYPE is not set or is unknown: [$OSTYPE]. Cannot continue") "
          return 1
  fi
  return 0
}

# Detect which architecture the script is running on and store it in a variable
function _detect_architecture {
  local detected_arch
  if [ -n "${ANZEN_ARCH}" ]; then return; fi
  _detect_OS
  ANZEN_ARCH="amd64"
  detected_arch="$(uname -m)"
  # Apple M1 silicon
  if [[ "${detected_arch}" == *"arm"* ]] && [[ "${ANZEN_OSTYPE}" == "darwin" ]]; then
    echo -e "$(YELLOW "WARN: It has been detected that you are using an Apple computer with ARM architecture. Deployment of Apple ARM architecture distributions is currently unsupported through git, the installer will pull darwin amd distribution instead.")"
  # LLVM 64 bit backends have merged so some versions of *nix use aarch64 while others use arm64 for parity with Apple
  elif [[ "${detected_arch}" == *"aarch64"* ]] || [[ "${detected_arch}" == *"arm64"* ]]; then
    ANZEN_ARCH="arm64"
  elif [[ "${detected_arch}" == *"arm"* ]]; then
    ANZEN_ARCH="arm"
  fi
}

function addAnzenToPath {
  if [[ "${1-}" == "yes" ]]; then
    echo "Adding ${ANZEN_BIN_DIR} to the path if necessary:"
    if [[ "$(echo "$PATH"|grep -q "${ANZEN_BIN_DIR}" && echo "yes")" == "yes" ]]; then
      echo -e "$(GREEN "${ANZEN_BIN_DIR}") is already on the path"
    else
      echo -e "adding $(RED "${ANZEN_BIN_DIR}") to the path"
      export PATH=$PATH:"${ANZEN_BIN_DIR}"
    fi
  fi
}

# Downloads and extracts anzen binaries onto the system. The latest version is used unless ANZEN_VERSION_OVERRIDE is set.
function getAnzen {
  local retVal default_path anzen_binaries_file_abspath anzendl reply
  _check_prereq curl jq tar 
  if [[ "${ANZEN_BIN_DIR}" == "" ]]; then
    # Prompt user for input or use default
    _setup_anzen_home
    getLatestAnzenVersion  # sets ANZEN_BINARIES_FILE & ANZEN_BINARIES_VERSION
    default_path="${ANZEN_HOME}/anzen-bin/anzen-${ANZEN_BINARIES_VERSION}"
    echo -en "The path for anzen binaries has not been set, use the default (${default_path})? (Y/n) "
    read -r reply
    if [[ -z "${reply}" || ${reply} =~ [yY] ]]; then
      echo "INFO: using the default path ${default_path}"
      ANZEN_BIN_DIR="${default_path}"
    else
      echo -en "Enter the preferred fully qualified path and press <enter> (the path will be created if necessary) "
      read -r ANZEN_BIN_DIR
    fi
  fi

  echo -e "Getting OpenAnzen binaries"
  echo ""

  # Get the latest version unless a specific version is specified
  if [[ "${ANZEN_VERSION_OVERRIDE-}" == "" ]]; then
    # If not overriding the version, determine the latest and populate ANZEN_BINARIES_FILE ANZEN_BINARIES_VERSION
    if ! getLatestAnzenVersion; then
      return 1
    fi
  else
    _check_env_variable ANZEN_BINARIES_FILE ANZEN_BINARIES_VERSION
    retVal=$?
    if [[ "${retVal}" != 0 ]]; then
      return 1
    fi

    # Check if an error occurred while trying to pull desired version (happens with incorrect version or formatting issue)
    if ! _verify_anzen_version_exists; then
        echo -e "  * $(RED "ERROR: The version of anzen requested (${ANZEN_VERSION_OVERRIDE}) could not be found for OS (${ANZEN_OSTYPE}) and architecture (${ANZEN_ARCH}). Please check these details and try again. The version should follow the format \"vx.x.x\".") "
        return 1
    fi
  fi

  # Where to store the anzen binaries zip
  anzen_binaries_file_abspath="${ANZEN_BIN_DIR}/${ANZEN_BINARIES_FILE}"
  # Check if they're already downloaded or maybe the user explicitly pointed ANZEN_BIN_DIR to their local bins
  if ! test -f "${ANZEN_BIN_DIR}/anzen"; then
    # Make the directory
    echo -e "No existing binary found, creating the ANZEN_BIN_DIR directory ($(BLUE "${ANZEN_BIN_DIR}"))"
    mkdir -p "${ANZEN_BIN_DIR}"
    retVal=$?
    if [[ "${retVal}" != 0 ]]; then
      echo -e "  * $(RED "ERROR: An error occurred generating the path (${ANZEN_BIN_DIR})")"
      return 1
    fi
  else
    echo -e "anzen found in ANZEN_BIN_DIR ($(BLUE "${ANZEN_BIN_DIR}"))"
    # Get the current version and compare with latest
    local currentVersion
    currentVersion="$("${ANZEN_BIN_DIR}"/anzen --version)"
    if [[ "${ANZEN_BINARIES_VERSION}" != "${currentVersion}" ]]; then
      # Prompt user for new download
      echo -en "There is a newer version of OpenAnzen, would you like to download it? (Y/n) "
      read -r reply
      if [[ -z "${reply}" || "${reply}" == [Yy]* ]]; then
        # Update the ANZEN_BIN_DIR path to point to the latest version
        unset ANZEN_BIN_DIR
        _set_anzen_bin_dir
        # Make the directory
        mkdir -p "${ANZEN_BIN_DIR}"
        retVal=$?
        if [[ "${retVal}" != 0 ]]; then
          echo -e "  * $(RED "ERROR: An error occurred generating the path (${ANZEN_BIN_DIR}")"
          return 1
        fi

        # Update the .env file with the new downloaded version
        if ! test -f "${ANZEN_ENV_FILE}"; then
          echo -e "  * $(YELLOW "WARN: The OpenAnzen Environment file could not be found to update anzen binary related paths")"
        else
          sed -i.bak "s/export ANZEN_BIN_DIR=.*/export ANZEN_BIN_DIR=$(echo ${ANZEN_BIN_DIR} | sed 's/\//\\\//g')/g" "${ANZEN_ENV_FILE}"
          sed -i.bak "s/export ANZEN_BINARIES_VERSION=.*/export ANZEN_BINARIES_VERSION=$(echo ${ANZEN_BINARIES_VERSION} | sed 's/\//\\\//g')/g" "${ANZEN_ENV_FILE}"
          sed -i.bak "s/export ANZEN_BINARIES_FILE=.*/export ANZEN_BINARIES_FILE=$(echo ${ANZEN_BINARIES_FILE} | sed 's/\//\\\//g')/g" "${ANZEN_ENV_FILE}"
          sed -i.bak "/export ANZEN_BINARIES_FILE_ABSPATH=.*/d" "${ANZEN_ENV_FILE}"
        fi

        echo -e "$(YELLOW 'Getting latest binaries ')$(BLUE "${ANZEN_BIN_DIR}")"
      else
        echo -e "$(YELLOW 'Using existing binaries at ')$(BLUE "${ANZEN_BIN_DIR}")"
        addAnzenToPath "$1"
        return 0
      fi
    else
      echo -e "$(YELLOW 'Latest binaries already exist, using existing binaries at ')$(BLUE "${ANZEN_BIN_DIR}")"
      addAnzenToPath "$1"
      return 0
    fi
  fi

  # Get the download link
  anzendl="https://github.com/openanzen/anzen/releases/download/${ANZEN_BINARIES_VERSION-}/${ANZEN_BINARIES_FILE}"
  echo -e 'Downloading '"$(BLUE "${anzendl}")"' to '"$(BLUE "${anzen_binaries_file_abspath}")"
  curl -Ls "${anzendl}" -o "${anzen_binaries_file_abspath}"

  # Unzip the files
  tar -xf "${anzen_binaries_file_abspath}" --directory "${ANZEN_BIN_DIR}"

  # Cleanup
  rm "${anzen_binaries_file_abspath}"      # Remove zip
  rm -rf "${ANZEN_BIN_DIR}/anzen-extract"   # Remove extract folder

  # Mark the files executable
  chmod +x "${ANZEN_BIN_DIR}/"*

  echo -e "$(GREEN "OpenAnzen binaries ${ANZEN_BINARIES_VERSION} successfully extracted to $(BLUE "${ANZEN_BIN_DIR}")")"
  echo ""
  addAnzenToPath "$1"
}

# Create a custom PKI
function createPki {
  local retVal pki_allow_list pki_allow_list_ip ANZEN_GRANDPARENT_INTERMEDIATE
  _check_env_variable ANZEN_PKI_CTRL_ROOTCA_NAME ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME ANZEN_PKI_SIGNER_ROOTCA_NAME \
                      ANZEN_PKI_SIGNER_INTERMEDIATE_NAME ANZEN_PKI_CTRL_INTERMEDIATE_NAME \
                      ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi
  echo "Generating PKI"

  _pki_create_ca "${ANZEN_PKI_CTRL_ROOTCA_NAME}"
  _pki_create_ca "${ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME}"
  _pki_create_ca "${ANZEN_PKI_SIGNER_ROOTCA_NAME}"

  ANZEN_GRANDPARENT_INTERMEDIATE="${ANZEN_PKI_SIGNER_INTERMEDIATE_NAME}_grandparent_intermediate"
  _pki_create_intermediate "${ANZEN_PKI_CTRL_ROOTCA_NAME}" "${ANZEN_PKI_CTRL_INTERMEDIATE_NAME}" 1
  _pki_create_intermediate "${ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME}" "${ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME}" 1
  _pki_create_intermediate "${ANZEN_PKI_SIGNER_ROOTCA_NAME}" "${ANZEN_GRANDPARENT_INTERMEDIATE}" 2
  _pki_create_intermediate "${ANZEN_GRANDPARENT_INTERMEDIATE}" "${ANZEN_PKI_SIGNER_INTERMEDIATE_NAME}" 1

  echo " "
  pki_allow_list="localhost,${ANZEN_NETWORK}"
  if [[ "${ANZEN_CTRL_ADVERTISED_ADDRESS-}" != "" ]]; then
    if ! _is_ip "${ANZEN_CTRL_ADVERTISED_ADDRESS-}"; then
      pki_allow_list="${pki_allow_list},${ANZEN_CTRL_ADVERTISED_ADDRESS}"
    else
      echo -e "$(YELLOW "ANZEN_CTRL_ADVERTISED_ADDRESS seems to be an IP address, it will not be added to the SANs DNS list.") "
    fi
  fi
  if [[ "${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS-}" != "" ]]; then
    if ! _is_ip "${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS-}"; then
      pki_allow_list="${pki_allow_list},${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}"
    else
      echo -e "$(YELLOW "ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS seems to be an IP address, it will not be added to the SANs DNS list.") "
    fi
  fi
  pki_allow_list_ip="127.0.0.1"
  if [[ "${ANZEN_CTRL_EDGE_IP_OVERRIDE-}" != "" ]]; then
    pki_allow_list_ip="${pki_allow_list_ip},${ANZEN_CTRL_EDGE_IP_OVERRIDE}"
  fi
  _pki_client_server "${pki_allow_list}" "${ANZEN_PKI_CTRL_INTERMEDIATE_NAME}" "${pki_allow_list_ip}" "${ANZEN_CTRL_ADVERTISED_ADDRESS}"

  pki_allow_list="localhost,${ANZEN_NETWORK}"
  if [[ "${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS-}" != "" ]]; then
    if ! _is_ip "${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS-}"; then
      pki_allow_list="${pki_allow_list},${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}"
    else
      echo -e "$(YELLOW "ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS seems to be an IP address, it will not be added to the SANs DNS list.") "
    fi
  fi
  pki_allow_list_ip="127.0.0.1"
  if [[ "${ANZEN_CTRL_EDGE_IP_OVERRIDE-}" != "" ]]; then
    pki_allow_list_ip="${pki_allow_list_ip},${ANZEN_CTRL_EDGE_IP_OVERRIDE}"
  fi
  _pki_client_server "${pki_allow_list}" "${ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME}" "${pki_allow_list_ip}" "${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}"

  echo -e "$(GREEN "PKI generated successfully")"
  echo -e ""
}

# Disable shellcheck un-passed arguments (arguments are optional)
# shellcheck disable=SC2120
# Creates a controller config file
function createControllerConfig {
  local controller_name retVal file_path output_file
  # Allow controller name to be passed in as arg
  controller_name="${1-}"
  # If no controller name provided and env var is not set, prompt user for a controller name
  if [[ "${controller_name}" == "" ]] && [[ -z "${ANZEN_CTRL_NAME}" ]]; then
    echo -e "$(YELLOW "createControllerConfig requires a controller name to be supplied") "
    echo -en "Enter controller name: "
    read -r controller_name

    # Quit if no name is provided
    if [[ "${controller_name}" == "" ]]; then
      echo -e "$(RED "  --- Invalid controller name provided ---")"
      return 1
    fi
  # If no controller name provided and env var is set, use env var
  elif [[ "${controller_name}" == "" ]] && [[ -n "${ANZEN_CTRL_NAME}" ]]; then
    controller_name="${ANZEN_CTRL_NAME}"
  fi

  # Make sure necessary env variables are set
  # The following are used by anzen bin to generate the config so they need to be checked:
  #   ANZEN_PKI_SIGNER_KEY ANZEN_PKI_EDGE_CERT ANZEN_PKI_EDGE_SERVER_CERT ANZEN_PKI_EDGE_KEY ANZEN_PKI_EDGE_CA
  _check_env_variable ANZEN_PKI_CTRL_SERVER_CERT ANZEN_PKI_CTRL_CA ANZEN_PKI_SIGNER_CERT ANZEN_PKI_SIGNER_KEY ANZEN_BIN_DIR \
                      ANZEN_PKI_EDGE_CERT ANZEN_PKI_EDGE_SERVER_CERT ANZEN_PKI_EDGE_KEY ANZEN_PKI_EDGE_CA
  retVal=$?
  if [ $retVal -ne 0 ]; then
    return 1
  fi

  # Use the current directory if none is set
  file_path="${ANZEN_HOME}"
  if [[ "${ANZEN_HOME-}" == "" ]]; then file_path="."; fi

  echo "adding controller root CA to ca bundle: $ANZEN_PKI/$ANZEN_PKI_CTRL_ROOTCA_NAME/certs/$ANZEN_PKI_CTRL_ROOTCA_NAME.cert"
  cat "$ANZEN_PKI/$ANZEN_PKI_CTRL_ROOTCA_NAME/certs/$ANZEN_PKI_CTRL_ROOTCA_NAME.cert" > "${ANZEN_PKI_CTRL_CA}"
  echo "adding signing root CA to ANZEN_PKI_CTRL_CA: $ANZEN_PKI_CTRL_CA"
  cat "$ANZEN_PKI/$ANZEN_PKI_SIGNER_ROOTCA_NAME/certs/$ANZEN_PKI_SIGNER_ROOTCA_NAME.cert" >> "${ANZEN_PKI_CTRL_CA}"
  echo -e "wrote CA file to: $(BLUE "${ANZEN_PKI_CTRL_CA}")"
  
  echo "adding parent intermediate CA to ANZEN_PKI_SIGNER_CERT: $ANZEN_PKI_SIGNER_CERT"
  cat "$ANZEN_PKI/$ANZEN_PKI_SIGNER_INTERMEDIATE_NAME/certs/${ANZEN_PKI_SIGNER_INTERMEDIATE_NAME}.cert" > "${ANZEN_PKI_SIGNER_CERT}"
  echo "adding grandparent intermediate CA to ANZEN_PKI_SIGNER_CERT: $ANZEN_PKI_SIGNER_CERT"
  cat "$ANZEN_PKI/$ANZEN_PKI_SIGNER_ROOTCA_NAME/certs/${ANZEN_PKI_SIGNER_INTERMEDIATE_NAME}_grandparent_intermediate.cert" >> "${ANZEN_PKI_SIGNER_CERT}"
  echo -e "wrote signer cert file to: $(BLUE "${ANZEN_PKI_SIGNER_CERT}")"

  output_file="${file_path}/${controller_name}.yaml"

  _get_file_overwrite_permission "${output_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  "${ANZEN_BIN_DIR}/anzen" create config controller >"${output_file}"

  echo -e "Controller configuration file written to: $(BLUE "${output_file}")"
}

# Helper function to create a private edge router
function createPrivateRouterConfig {
  _create_router_config "${1-}" "private"
}

# Helper function to create a public edge router
function createEdgeRouterConfig {
  _create_router_config "${1-}" "public"
}

function createEdgeRouterWssConfig {
  _create_router_config "${1-}" "wss"
}

# Helper function to create a fabric router
function createFabricRouterConfig {
  _create_router_config "${1-}" "fabric"
}

# The main create router config function, all others point to this
function _create_router_config {
  local router_name router_type output_file retVal default_router_name file_path
  # Allow router name and type to be passed in as arg
  router_name="${1-}"
  router_type="${2-}"
  if [[ "${router_name}" == "" ]]; then

    # If router name is not passed as arg, prompt user for input
    echo -e "$(YELLOW "createEdgeRouterConfig requires a router name to be supplied") "
    default_router_name="${ANZEN_ROUTER_NAME}"
    echo -en "Enter router name (${default_router_name}): "
    read -r router_name

    # Accept the default if no name provided
    if [[ "${router_name}" == "" ]]; then
      # Check for overwrite of default file
      router_name="${default_router_name}"
      _get_file_overwrite_permission "${ANZEN_HOME-}/${router_name}.yaml"
      retVal=$?
      if [[ "${retVal}" != 0 ]]; then
        return 1
      fi
    fi
  fi
  # Get router type or set as default
  if [[ "${router_type}" == "" ]]; then
    router_type="private"
  elif [[ "private" != "${router_type}" ]] && [[ "public" != "${router_type}" ]] && [[ "fabric" != "${router_type}" ]] && [[ "wss" != "${router_type}" ]]; then
    echo -e "Unknown router type parameter provided '${router_type}', use 'public', 'private', 'fabric', or 'wss'"
  fi

  # Make sure necessary env variables are set
  # The following are used by anzen bin to generate the config so they need to be checked:
  # ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS ANZEN_CTRL_ADVERTISED_PORT
  _check_env_variable ANZEN_HOME ANZEN_BIN_DIR ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS ANZEN_CTRL_ADVERTISED_PORT
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  # Use the current directory if none is set
  file_path="${ANZEN_HOME}"
  if [[ "${ANZEN_HOME-}" == "" ]]; then file_path="."; fi

  output_file="${file_path}/${router_name}.yaml"

  _get_file_overwrite_permission "${output_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  if [[ "public" == "${router_type}" ]]; then
    "${ANZEN_BIN_DIR}/anzen" create config router edge --routerName "${router_name}" > "${output_file}"
  elif [[ "private" == "${router_type}" ]]; then
    "${ANZEN_BIN_DIR}/anzen" create config router edge --routerName "${router_name}" --private > "${output_file}"
  elif [[ "fabric" == "${router_type}" ]]; then
    "${ANZEN_BIN_DIR}/anzen" create config router fabric --routerName "${router_name}" > "${output_file}"
  elif [[ "wss" == "${router_type}" ]]; then
    "${ANZEN_BIN_DIR}/anzen" create config router edge --routerName "${router_name}" --wss > "${output_file}"
  fi
  echo -e "${router_type} router configuration file written to: $(BLUE "${output_file}")"
}

# Used to create a router, router config, then enroll the router.
function addRouter {
  local router_name router_type retVal router_attr
  # Make sure necessary env variables are set
  _check_env_variable ANZEN_HOME ANZEN_BIN_DIR ANZEN_USER ANZEN_PWD
  retVal=$?
  if [ $retVal -ne 0 ]; then
    return 1
  fi
  # Allow router name and type to be passed in as arg
  router_name="${1-}"
  router_type="${2-}"
  router_attr="${3-}"
  # If no router name provided and env var is not set, prompt user for a router name
  if [[ "${router_name}" == "" ]] && [[ -z "${ANZEN_ROUTER_NAME}" ]]; then
    echo -e "$(YELLOW "addRouter requires a router name to be supplied") "
    echo -en "Enter router name: "
    read -r router_name

    # Quit if no name is provided
    if [[ "${router_name}" == "" ]]; then
      echo -e "$(RED "  --- Invalid router name provided ---")"
      return 1
    fi
  # If no router name provided and env var is set, use env var
  elif [[ "${router_name}" == "" ]] && [[ -n "${ANZEN_ROUTER_NAME}" ]]; then
    router_name="${ANZEN_ROUTER_NAME}"
  fi

  # Create router
  anzenLogin
  "${ANZEN_BIN_DIR-}/anzen" edge delete edge-router "${router_name}"
  "${ANZEN_BIN_DIR-}/anzen" edge create edge-router "${router_name}" -o "${ANZEN_HOME}/${router_name}.jwt" -t -a "${router_attr}"

  # Create router config
  _create_router_config "${router_name}" "${router_type}"

  # Enroll the router
  "${ANZEN_BIN_DIR-}/anzen" router enroll "${ANZEN_HOME}/${router_name}.yaml" --jwt "${ANZEN_HOME}/${router_name}.jwt" &> "${ANZEN_HOME}/${router_name}.enrollment.log"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    echo -e "$(RED "  --- There was an error during router enrollment, check the logs at ${ANZEN_HOME}/${router_name}.enrollment.log ---")"
    return 1
  else
    echo -e "$(GREEN "Enrollment successful")"
  fi
}

function initializeController {
  local retVal log_file
  _setup_anzen_home
  # Make sure necessary env variables are set
  _check_env_variable ANZEN_HOME ANZEN_CTRL_NAME ANZEN_USER ANZEN_PWD ANZEN_PKI_CTRL_CA ANZEN_BIN_DIR
  retVal=$?
  if [ $retVal -ne 0 ]; then
    return 1
  fi

  log_file="${ANZEN_HOME-}/${ANZEN_CTRL_NAME}-init.log"
  "${ANZEN_BIN_DIR-}/anzen" controller edge init "${ANZEN_HOME}/${ANZEN_CTRL_NAME}.yaml" -u "${ANZEN_USER-}" -p "${ANZEN_PWD}" &> "${log_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    echo -e "$(RED "  --- There was an error while initializing the controller, check the logs at ${log_file} ---")"
    return 1
  fi
  echo -e "${ANZEN_CTRL_NAME} initialized. See $(BLUE "${log_file}") for details"
}

function anzenLogin {
  local advertised_host_port="${ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS}:${ANZEN_CTRL_EDGE_ADVERTISED_PORT}"
  "${ANZEN_BIN_DIR-}/anzen" edge login "${advertised_host_port}" -u "${ANZEN_USER-}" -p "${ANZEN_PWD}" -y 2>&1
}

function expressInstall {
  local retVal
  # Check if expressInstall has been run before
  if [[ "" != "${ANZENx_EXPRESS_COMPLETE-}" ]]; then
    echo -e "$(RED "  --- It looks like you've run an express install in this shell already. ---")"
    echo -en "Would you like to clear existing Anzen variables and continue? (y/N) "
    read -r
    echo " "
    if [[ "${REPLY}" == [Yy]* ]]; then
      removeAnzenEnvironment
    else
      echo -e "$(RED "  --- Exiting express install ---")"
      return 1
    fi
  fi
  export ANZENx_EXPRESS_COMPLETE="true"
  _issue_preamble

  # This is redundant but better to check here to prevent going any further
  _check_prereq curl jq tar hostname lsof
  retVal=$?
  if [ $retVal -ne 0 ]; then
    return 1
  fi
  _issue_greeting

  echo -e "$(PURPLE "******** Setting Up Your OpenAnzen Environment ********")"
  # If a parameter was provided, set the network name to this value
  if [[ "${1-}" != "" ]]; then
    ANZEN_NETWORK="${1-}"
  fi
  setupEnvironment
  persistEnvironmentValues ""

  echo -e "$(PURPLE "********      Getting OpenAnzen Binaries       ********")"
  if ! getAnzen "no"; then
    echo -e "$(RED "getAnzen failed")"
    return 1
  fi

  # Check Ports
  echo -e "$(PURPLE "******** Ensure the Necessary Ports Are Open  ********")"
  if ! checkAnzenPorts; then
    echo "Please clear the unavailable ports or change their values and try again."
    return 1
  fi

  # Create PKI
  echo -e "$(PURPLE "******** Generating Public Key Infrastructure ********")"
  createPki

  echo -e "$(PURPLE "********         Setting Up Controller        ********")"
  createControllerConfig
  if ! initializeController; then
    return 1
  fi
  startController
  echo "waiting for the controller to come online to allow the edge router to enroll"
  _wait_for_controller
  echo ""

  echo -e "$(PURPLE "******** Setting Up Edge Router ********")"
  anzenLogin
  echo ""
  echo -e "----------  Creating an edge router policy allowing all identities to connect to routers with a $(GREEN "#public") attribute"
  "${ANZEN_BIN_DIR-}/anzen" edge delete edge-router-policy allEdgeRouters > /dev/null
  "${ANZEN_BIN_DIR-}/anzen" edge create edge-router-policy allEdgeRouters --edge-router-roles '#public' --identity-roles '#all' > /dev/null

  echo -e "----------  Creating a service edge router policy allowing all services to use $(GREEN "#public") edge routers"
  "${ANZEN_BIN_DIR-}/anzen" edge delete service-edge-router-policy allSvcAllRouters > /dev/null
  "${ANZEN_BIN_DIR-}/anzen" edge create service-edge-router-policy allSvcAllRouters --edge-router-roles '#all' --service-roles '#all' > /dev/null
  echo ""

  echo "USING ANZEN_ROUTER_NAME: $ANZEN_ROUTER_NAME"

  addRouter "${ANZEN_ROUTER_NAME}" "public" "public"
  echo ""

  stopController
  echo "Edge Router enrolled."

  echo ""
  echo -e "$(GREEN "Congratulations. Express setup complete!")"
  echo -e "Your ANZEN_HOME is located here: $(BLUE "${ANZEN_HOME}")"
  echo -e "Your admin password is: $(BLUE "${ANZEN_PWD}")"
  echo ""
  echo -e "Start your Anzen Controller by running the function: $(BLUE "startController")"
  echo -e "Start your Anzen Edge Router by running : $(BLUE 'startRouter')"
  echo ""
}

# Gets the latest Anzen binary (the process is different for latest vs older so unfortunately two functions are needed)
function getLatestAnzenVersion {
  local anzen_latest
  if ! _detect_OS; then
    return 1
  fi

  _detect_architecture

  anzen_latest=$(curl -s https://${GITHUB_TOKEN:+${GITHUB_TOKEN}@}api.github.com/repos/openanzen/anzen/releases/latest)
  ANZEN_BINARIES_FILE=$(printf "%s" "${anzen_latest}" | tr '\r\n' ' ' | jq -r '.assets[] | select(.name | startswith("'"anzen-${ANZEN_OSTYPE}-${ANZEN_ARCH}-"'")) | .name')
  ANZEN_BINARIES_VERSION=$(printf "%s" "${anzen_latest}" | tr '\r\n' ' ' | jq -r '.tag_name')
}

function createControllerSystemdFile {
  local controller_name retVal output_file
  # Allow controller name to be passed in as an arg
  controller_name="${1-}"
  # If no controller name provided and env var is not set, prompt user for a controller name
  if [[ "${controller_name}" == "" ]]; then
    controller_name="${ANZEN_NETWORK}"
  fi

  # Make sure necessary env variables are set
  _check_env_variable ANZEN_HOME ANZEN_BIN_DIR
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  output_file="${ANZEN_HOME}/${controller_name}.service"

  _get_file_overwrite_permission "${output_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

cat > "${output_file}" <<HeredocForSystemd
[Unit]
Description=Anzen-Controller
After=network.target

[Service]
User=root
WorkingDirectory=${ANZEN_HOME}
ExecStart="${ANZEN_BIN_DIR}/anzen" controller run "${ANZEN_HOME}/${controller_name}.yaml"
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target

HeredocForSystemd
  echo -e "Controller systemd file written to: $(BLUE "${output_file}")"
}

function createRouterSystemdFile {
  local router_name default_router_name retVal output_file
  # Allow router name to be passed in as an arg
  router_name="${1-}"
  if [[ "${router_name}" == "" ]]; then

    # If router name is not passed as arg, prompt user for input
    echo -e "$(YELLOW "createRouterSystemdFile requires a router name to be supplied") "
    default_router_name="${ANZEN_ROUTER_NAME}"
    echo -en "Enter router name (${default_router_name}): "
    read -r router_name

    # Accept the default if no name provided
    if [[ "${router_name}" == "" ]]; then
      # Check for overwrite of default file
      router_name="${default_router_name}"
      _get_file_overwrite_permission "${ANZEN_HOME-}/${router_name}.service"
      retVal=$?
      if [[ "${retVal}" != 0 ]]; then
        return 1
      fi
    fi
  fi

  _check_env_variable ANZEN_HOME ANZEN_BIN_DIR
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  output_file="${ANZEN_HOME}/${router_name}.service"

  _get_file_overwrite_permission "${output_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

cat > "${output_file}" <<HeredocForSystemd
[Unit]
Description=Anzen-Router for ${router_name}
After=network.target

[Service]
User=root
WorkingDirectory=${ANZEN_HOME}
ExecStart="${ANZEN_BIN_DIR}/anzen" router run "${ANZEN_HOME}/${router_name}.yaml"
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

HeredocForSystemd
  echo -e "Router systemd file written to: $(BLUE "${output_file}")"
}

function createBrowZerSystemdFile {
  local retVal output_file node_bin
  _check_env_variable ANZEN_HOME
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  output_file="${ANZEN_HOME}/browzer-bootstrapper.service"

  if which node >/dev/null; then
    # store the absolute path to the node executable because it's required by systemd on Amazon Linux, at least
    node_bin=$(readlink -f "$(which node)")
  else
    echo "ERROR: missing executable 'node'" >&2
    return 1
  fi

  _get_file_overwrite_permission "${output_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  cat > "${output_file}" << HeredocForSystemd
[Unit]
Description=A systemd unit file for the Anzen BrowZer Bootstrapper
After=network.target

[Service]
User=root
EnvironmentFile=${ANZEN_HOME}/browzer.env
WorkingDirectory=${ANZEN_HOME}/anzen-browzer-bootstrapper
ExecStart=${node_bin} "${ANZEN_HOME}/anzen-browzer-bootstrapper/index.js"
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

HeredocForSystemd
  echo -e "Anzen BrowZer Bootstrapper systemd file written to: $(BLUE "${output_file}")"
}

function createControllerLaunchdFile {
  local controller_name retVal output_file
  # Allow controller name to be passed in as arg
  controller_name="${1-}"
  # If no controller name provided and env var is not set, prompt user for a controller name
  if [[ "${controller_name}" == "" ]] && [[ -z "${ANZEN_CTRL_NAME}" ]]; then
        echo -e "$(YELLOW "createControllerLaunchdFile requires a controller name to be supplied") "
        echo -en "Enter controller name: "
        read -r controller_name

        # Quit if no name is provided
        if [[ "${controller_name}" == "" ]]; then
          echo -e "$(RED "  --- Invalid controller name provided ---")"
          return 1
        fi
  # If no controller name provided and env var is set, use env var
  elif [[ "${controller_name}" == "" ]] && [[ -n "${ANZEN_CTRL_NAME}" ]]; then
    controller_name="${ANZEN_CTRL_NAME}"
  fi

  # Make sure necessary env variables are set
  _check_env_variable ANZEN_HOME ANZEN_BIN_DIR
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  output_file="${ANZEN_HOME}/${controller_name}.plist"

  _get_file_overwrite_permission "${output_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

cat > "${output_file}" <<HeredocForLaunchd
<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
    <dict>
      <key>Label</key>
      <string>anzen-controller-${controller_name}</string>
      <key>ProgramArguments</key>
      <array>
        <string>$ANZEN_BIN_DIR/anzen</string>
        <string>controller</string>
        <string>run</string>
        <string>$ANZEN_HOME/${controller_name}.yaml</string>
      </array>
      <key>WorkingDirectory</key>
      <string>${ANZEN_HOME}</string>
      <key>KeepAlive</key>
      <dict>
        <key>PathState</key>
        <dict>
          <key>${ANZEN_HOME}/launchd-enabled</key>
          <true/>
        </dict>
      </dict>
      <key>StandardOutPath</key>
      <string>${ANZEN_HOME}/Logs/${controller_name}-{ANZEN_BINARIES_VERSION}.log</string>
      <key>StandardErrorPath</key>
      <string>${ANZEN_HOME}/Logs/${controller_name}-{ANZEN_BINARIES_VERSION}.log</string>
    </dict>
  </plist>
HeredocForLaunchd
  echo -e "Controller launchd file written to: $(BLUE "${output_file}")"

  showLaunchdMessage
}

function createRouterLaunchdFile {
  local router_name default_router_name retVal output_file
  # Allow router name to be passed in as arg
  router_name="${1-}"
  if [[ "${router_name}" == "" ]]; then

    # If router name is not passed as arg, prompt user for input
    echo -e "$(YELLOW "createRouterLaunchdFile requires a router name to be supplied") "
    default_router_name="${ANZEN_ROUTER_NAME}"
    echo -en "Enter router name (${default_router_name}): "
    read -r router_name

    # Accept the default if no name provided
    if [[ "${router_name}" == "" ]]; then
      # Check for overwrite of default file
      router_name="${default_router_name}"
      _get_file_overwrite_permission "${ANZEN_HOME-}/${router_name}.plist"
      retVal=$?
      if [[ "${retVal}" != 0 ]]; then
        return 1
      fi
    fi
  fi

  # Make sure necessary env variables are set
  _check_env_variable ANZEN_HOME ANZEN_BIN_DIR
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  output_file="${ANZEN_HOME-}/${router_name}.plist"

  _get_file_overwrite_permission "${output_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

cat > "${output_file}" <<HeredocForLaunchd
<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
    <dict>
      <key>Label</key>
      <string>$router_name</string>
      <key>ProgramArguments</key>
      <array>
        <string>$ANZEN_BIN_DIR/anzen</string>
        <string>router</string>
        <string>run</string>
        <string>$ANZEN_HOME/ctrl.with.edge.yml</string>
      </array>
      <key>WorkingDirectory</key>
      <string>${ANZEN_HOME}</string>
      <key>KeepAlive</key>
      <true/>
      <dict>
        <key>PathState</key>
        <dict>
          <key>${ANZEN_HOME}/launchd-enabled</key>
          <true/>
        </dict>
      </dict>
      <key>StandardOutPath</key>
      <string>${ANZEN_HOME}/Logs/${router_name}-${ANZEN_BINARIES_VERSION}.log</string>
      <key>StandardErrorPath</key>
      <string>${ANZEN_HOME}/Logs/${router_name}-${ANZEN_BINARIES_VERSION}.log</string>
    </dict>
  </plist>
HeredocForLaunchd
  echo -e "Router launchd file written to: $(BLUE "${output_file}")"

  showLaunchdMessage
}

function showLaunchdMessage {
  echo -e " "
  echo -e "$(YELLOW "The generated launchd file is designed to keep the service alive while the file")"
  echo -e "$(BLUE "${ANZEN_HOME}/launchd-enabled") $(YELLOW "remains present.")"
  echo -e "$(YELLOW "If this file is not present, the service will end.")"
}

function createZacSystemdFile {
  local retVal output_file node_bin
  _check_env_variable ANZEN_HOME
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  output_file="${ANZEN_HOME}/anzen-console.service"

  _get_file_overwrite_permission "${output_file}"
  retVal=$?
  if [[ "${retVal}" != 0 ]]; then
    return 1
  fi

  if which node >/dev/null; then
    # store the absolute path to the node executable because it's required by systemd on Amazon Linux, at least
    node_bin=$(readlink -f "$(which node)")
  else
    echo "ERROR: missing executable 'node'" >&2
    return 1
  fi

cat > "${output_file}" <<HeredocForSystemd
[Unit]
Description=Anzen-Console
After=network.target

[Service]
User=root
WorkingDirectory=${ANZEN_HOME}/anzen-console
ExecStart=${node_bin} "${ANZEN_HOME}/anzen-console/server.js"
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

HeredocForSystemd
  echo -e "anzen-console systemd file written to: $(BLUE "${output_file}")"
}

# Ensure that the version desired as specified by ANZEN_VERSION_OVERRIDE exists, this returns an error in cases where
# the version doesn't exist or possibly just the version format provided in ANZEN_VERSION_OVERRIDE is incorrect.
function _verify_anzen_version_exists {
  local anzencurl

  _detect_architecture

  anzencurl="$(curl -s https://${GITHUB_TOKEN:+${GITHUB_TOKEN}@}api.github.com/repos/openanzen/anzen/releases/tags/"${ANZEN_VERSION_OVERRIDE}")"
  ANZEN_BINARIES_FILE=$(echo "${anzencurl}" | tr '\r\n' ' ' | jq -r '.assets[] | select(.name | startswith("'"anzen-${ANZEN_OSTYPE}-${ANZEN_ARCH}-"'")) | .name')
  ANZEN_BINARIES_VERSION=$(echo "${anzencurl}" | tr '\r\n' ' ' | jq -r '.tag_name')

  # Check if there was an error while trying to get the requested version
  if [[ "${ANZEN_BINARIES_VERSION-}" == "null" ]]; then
    echo "ERROR: response missing '.tag_name': ${anzencurl}" >&2
    return 1
  fi

  echo "The anzen version requested (${ANZEN_BINARIES_VERSION}) was verified and has been stored in ANZEN_BINARIES_VERSION"
}

# Disable shellcheck for parameter expansion error, this function supports multiple shells
# shellcheck disable=SC2296
# Check to ensure the expected ports are available
function _portCheck {
  local portCheckResult envVar envVarValue

  if [[ "${1-}" == "" ]] || [[ "${2-}" == "" ]]; then
    echo -e "_portCheck Usage: _portCheck <port> <portName>"
    return 0
  fi

  envVar="${1-}"
  if [[ -n "$ZSH_VERSION" ]]; then
    envVarValue="${(P)envVar}"
  elif [[ -n "$BASH_VERSION" ]]; then
    envVarValue="${!envVar}"
  else
    echo -e "$(YELLOW "Unknown/Unsupported shell, cannot verify availability of ${2-}'s intended port, proceed with caution")"
    return 0
  fi

  echo -en "Checking ${2-}'s port (${envVarValue}) "
  portCheckResult=$(lsof -w -i :"${envVarValue}" 2>&1)
  if [[ "${portCheckResult}" != "" ]]; then
      echo -e "$(RED "The intended ${2-} port (${envVarValue}) is currently being used, the process using this port should be closed or the port value should be changed.")"
      echo -e "$(RED "To use a different port, set the port value in ${envVar}")"
      echo -e "$(RED " ")"
      echo -e "$(RED "Example:")"
      echo -e "$(RED "export ${envVar}=1234")"
      echo -e "$(RED " ")"
      return 1
  else
    echo -e "$(GREEN "Open")"
  fi
  return 0
}

# A function for upgrading an existing (<=0.28.0) network to a later (>0.28.0) network
# The binary, which relies on environment variables were extensively altered and will not work on an existing network
# without migrating it first
function performMigration {
  if [[ "${1-}" == "" ]]; then
    # Check if the env file is in the expected location
    _setup_anzen_env_path
    if ! test -f "${ANZEN_ENV_FILE}"; then
      echo -e "performMigration Usage: performMigration <env_file_path>"
      return 0
    fi
  else
    ANZEN_ENV_FILE="${1-}"
  fi

  # Replace old Env Vars in the env file with new ones
  # NOTE: use of -i behaves differently for Mac vs Linux. -i.bak is a workaround so the command works in both OSs
  sed -i.bak 's/ANZEN_CONTROLLER_HOSTNAME/ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CONTROLLER_INTERMEDIATE_NAME/ANZEN_PKI_CTRL_INTERMEDIATE_NAME/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CONTROLLER_RAWNAME/ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CONTROLLER_ROOTCA_NAME/ANZEN_PKI_CTRL_ROOTCA_NAME/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CTRL_EDGE_PORT/ANZEN_CTRL_EDGE_ADVERTISED_PORT/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CTRL_IDENTITY_CA/ANZEN_PKI_CTRL_CA/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CTRL_IDENTITY_CERT/ANZEN_PKI_CTRL_CERT/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CTRL_IDENTITY_KEY/ANZEN_PKI_CTRL_KEY/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CTRL_IDENTITY_SERVER_CERT/ANZEN_PKI_CTRL_SERVER_CERT/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_CTRL_PORT/ANZEN_CTRL_ADVERTISED_PORT/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CONTROLLER_HOSTNAME/ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CONTROLLER_INTERMEDIATE_NAME/ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CONTROLLER_PORT/ANZEN_CTRL_EDGE_ADVERTISED_PORT/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CONTROLLER_RAWNAME/ANZEN_CTRL_NAME/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CONTROLLER_ROOTCA_NAME/ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CTRL_IDENTITY_CA/ANZEN_PKI_EDGE_CA/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CTRL_IDENTITY_CERT/ANZEN_PKI_EDGE_CERT/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CTRL_IDENTITY_KEY/ANZEN_PKI_EDGE_KEY/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_EDGE_CTRL_IDENTITY_SERVER_CERT/ANZEN_PKI_EDGE_SERVER_CERT/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_ROUTER_RAWNAME/ANZEN_ROUTER_NAME/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_PKI_OS_SPECIFIC/ANZEN_PKI/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_SIGNING_CERT/ANZEN_PKI_SIGNER_CERT/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_SIGNING_KEY/ANZEN_PKI_SIGNER_KEY/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_ROUTER_HOSTNAME/ANZEN_ROUTER_ADVERTISED_ADDRESS/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_SIGNING_ROOTCA_NAME/ANZEN_PKI_SIGNER_ROOTCA_NAME/g' "${ANZEN_ENV_FILE}"
  sed -i.bak 's/ANZEN_SIGNING_INTERMEDIATE_NAME/ANZEN_PKI_SIGNER_INTERMEDIATE_NAME/g' "${ANZEN_ENV_FILE}"

  # Update environment variables if currently set
  if [[ "${ANZEN_EDGE_CONTROLLER_HOSTNAME-}" != "" ]]; then export ANZEN_CTRL_EDGE_ADVERTISED_ADDRESS="${ANZEN_EDGE_CONTROLLER_HOSTNAME}"; fi
  if [[ "${ANZEN_CONTROLLER_INTERMEDIATE_NAME-}" != "" ]]; then export ANZEN_PKI_CTRL_INTERMEDIATE_NAME="${ANZEN_CONTROLLER_INTERMEDIATE_NAME}"; fi
  if [[ "${ANZEN_CONTROLLER_ROOTCA_NAME-}" != "" ]]; then export ANZEN_PKI_CTRL_ROOTCA_NAME="${ANZEN_CONTROLLER_ROOTCA_NAME}"; fi
  if [[ "${ANZEN_CTRL_EDGE_PORT-}" != "" ]]; then export ANZEN_CTRL_EDGE_ADVERTISED_PORT="${ANZEN_CTRL_EDGE_PORT}"; fi
  if [[ "${ANZEN_CTRL_IDENTITY_CA-}" != "" ]]; then export ANZEN_PKI_CTRL_CA="${ANZEN_CTRL_IDENTITY_CA}"; fi
  if [[ "${ANZEN_CTRL_IDENTITY_CERT-}" != "" ]]; then export ANZEN_PKI_CTRL_CERT="${ANZEN_CTRL_IDENTITY_CERT}"; fi
  if [[ "${ANZEN_CTRL_IDENTITY_KEY-}" != "" ]]; then export ANZEN_PKI_CTRL_KEY="${ANZEN_CTRL_IDENTITY_KEY}"; fi
  if [[ "${ANZEN_CTRL_IDENTITY_SERVER_CERT-}" != "" ]]; then export ANZEN_PKI_CTRL_SERVER_CERT="${ANZEN_CTRL_IDENTITY_SERVER_CERT}"; fi
  if [[ "${ANZEN_CTRL_PORT-}" != "" ]]; then export ANZEN_CTRL_ADVERTISED_PORT="${ANZEN_CTRL_PORT}"; fi
  if [[ "${ANZEN_EDGE_CONTROLLER_INTERMEDIATE_NAME-}" != "" ]]; then export ANZEN_PKI_CTRL_EDGE_INTERMEDIATE_NAME="${ANZEN_EDGE_CONTROLLER_INTERMEDIATE_NAME}"; fi
  if [[ "${ANZEN_EDGE_CONTROLLER_RAWNAME-}" != "" ]]; then export ANZEN_CTRL_NAME="${ANZEN_EDGE_CONTROLLER_RAWNAME}"; fi
  if [[ "${ANZEN_EDGE_CONTROLLER_ROOTCA_NAME-}" != "" ]]; then export ANZEN_PKI_CTRL_EDGE_ROOTCA_NAME="${ANZEN_EDGE_CONTROLLER_ROOTCA_NAME}"; fi
  if [[ "${ANZEN_EDGE_CTRL_IDENTITY_CA-}" != "" ]]; then export ANZEN_PKI_EDGE_CA="${ANZEN_EDGE_CTRL_IDENTITY_CA}"; fi
  if [[ "${ANZEN_EDGE_CTRL_IDENTITY_CERT-}" != "" ]]; then export ANZEN_PKI_EDGE_CERT="${ANZEN_EDGE_CTRL_IDENTITY_CERT}"; fi
  if [[ "${ANZEN_EDGE_CTRL_IDENTITY_KEY-}" != "" ]]; then export ANZEN_PKI_EDGE_KEY="${ANZEN_EDGE_CTRL_IDENTITY_KEY}"; fi
  if [[ "${ANZEN_EDGE_CTRL_IDENTITY_SERVER_CERT-}" != "" ]]; then export ANZEN_ROUTER_NAME="${ANZEN_EDGE_CTRL_IDENTITY_SERVER_CERT}"; fi
  if [[ "${ANZEN_PKI_OS_SPECIFIC-}" != "" ]]; then export ANZEN_PKI="${ANZEN_PKI_OS_SPECIFIC}"; fi
  if [[ "${ANZEN_SIGNING_CERT-}" != "" ]]; then export ANZEN_PKI_SIGNER_CERT="${ANZEN_SIGNING_CERT}"; fi
  if [[ "${ANZEN_SIGNING_KEY-}" != "" ]]; then export ANZEN_PKI_SIGNER_KEY="${ANZEN_SIGNING_KEY}"; fi
  if [[ "${ANZEN_ROUTER_HOSTNAME-}" != "" ]]; then export ANZEN_ROUTER_ADVERTISED_ADDRESS="${ANZEN_ROUTER_HOSTNAME}"; fi
  if [[ "${ANZEN_SIGNING_ROOTCA_NAME-}" != "" ]]; then export ANZEN_PKI_SIGNER_ROOTCA_NAME="${ANZEN_SIGNING_ROOTCA_NAME}"; fi
  if [[ "${ANZEN_SIGNING_INTERMEDIATE_NAME-}" != "" ]]; then export ANZEN_PKI_SIGNER_INTERMEDIATE_NAME="${ANZEN_SIGNING_INTERMEDIATE_NAME}"; fi

  # Update the necessary anzen binary references (others are not needed or are overwritten later)
  if [[ "${ANZEN_BIN_DIR-}" != "" ]]; then
    sed -i.bak '/^export ANZEN_BIN_DIR=/d' "${ANZEN_ENV_FILE}"
    echo "export ANZEN_BIN_DIR=${ANZEN_BIN_DIR}" >> "${ANZEN_ENV_FILE}"
  fi
  if [[ "${ANZEN_BINARIES_VERSION-}" != "" ]]; then
    sed -i.bak '/^export ANZEN_BINARIES_VERSION=/d' "${ANZEN_ENV_FILE}"
    echo "export ANZEN_BINARIES_VERSION=${ANZEN_BINARIES_VERSION}" >> "${ANZEN_ENV_FILE}"
  fi

  echo -e "$(GREEN "SUCCESS: Your Environment file has been updated, please use source the file for the latest values. Be sure to source the .env file as needed.")"
}

# ******* Deprecated functions, refer to new functions **********
function deprecationMessage {
  echo -e "$(YELLOW "WARNING: The ${1} function has been deprecated, please use ${2} going forward")"
}

function generateEnvFile {
  deprecationMessage generateEnvFile persistEnvironmentValues
  persistEnvironmentValues
}
function waitForController {
  deprecationMessage waitForController _wait_for_controller
  _wait_for_controller
}

function printUsage() {
    echo "Usage: ${1-} [cert to test] [ca pool to use]"
}

function verifyCertAgainstPool() {
  if [[ "" == "${1-}" ]]
  then
      printUsage "verifyCertAgainstPool"
      return 1
  fi

  if [[ "" == "$2" ]]
  then
      printUsage "verifyCertAgainstPool"
      return 1
  fi

  echo "    Verifying that this certificate:"
  echo "        - ${1-}"
  echo "    is valid for this ca pool:"
  echo "        - $2"
  echo ""
  openssl verify -partial_chain -CAfile "$2" "${1-}"
  # shellcheck disable=SC2181
  if [ $? -eq 0 ]; then
      echo ""
      echo "============      SUCCESS!      ============"
  else
      echo ""
      echo "============ FAILED TO VALIDATE ============"
  fi
}

function showIssuerAndSubjectForPEM() {
  echo "Displaying Issuer and Subject for cert pool:"
  echo "    ${1-}"
  openssl crl2pkcs7 -nocrl -certfile "${1-}" | openssl pkcs7 -print_certs -text -noout | grep -E "(Subject|Issuer)"
}
set +uo pipefail
