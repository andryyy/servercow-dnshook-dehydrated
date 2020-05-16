#!/usr/bin/env bash

set -e
set -o pipefail

source ./scow-hook.auth # contains user and pass variables

SCOW_User=${user}
SCOW_Pass=${pass}

WAIT=15		# time in seconds to wait after each request

function deploy_challenge() {
  # Parameters:
  # - SIGN_DOMAIN
  #   The domain name (CN or subject alternative name) being
  #   validated.
  # - TOKEN_FILENAME
  #   The name of the file is irrelevant for the DNS challenge, yet still provided
  # - TOKEN_VALUE
  #   The token value that needs to be served for validation. For DNS
  #   validation, this is what you want to put in the _acme-challenge
  #   TXT record. For HTTP validation it is the value that is expected
  #   be found in the $TOKEN_FILENAME file.

  if ! which dig > /dev/null; then
    echo -e "\n\t ERROR: Cannot find dig !!!\n\t(Debian and derivates: dnsutils; CentOS, Arch, Alpine: bind-tools) \n"
    return 1
  fi

  # Check for credentials
  if [[ -z "$SCOW_Pass" ]] || [[ -z "$SCOW_User" ]]; then
    SCOW_Pass=""
    SCOW_User=""
    echo -e "\n\t ERROR: No Servercow login data provided. \n"
    echo -e "\n\t ERROR: Please create a new user with access to the DNS API. \n"
    return 1
  fi

  local SIGN_DOMAIN="${1}"
  local TOKEN_FILENAME="${2}"
  local TOKEN_VALUE="${3}"

  [[ ! -z ${4} ]] && SLEEP=n || SLEEP=y

  # Start with SLD=SIGN_DOMAIN and break down SLD until it equals to the second level domain
  local SLD=${SIGN_DOMAIN}
  #until [[ -z $(dig ns ${SLD} +short | grep -viE 'ns.+.servercow.de') ]]; do
  until [[ ! -z $(dig ns ${SLD} +short | grep -iE 'ns.+\.servercow\.de') ]]; do
    SLD=${SLD#*.}
    if [ $(echo ${SLD} | awk -F. '{print NF-1}') -lt 1 ]; then
      echo -e "\n\t ERROR: Cannot determine root domain with a Servercow NS record for ${SIGN_DOMAIN} \n"
      return 1
    fi
  done

  echo -e "\t Creating challenge record for ${SIGN_DOMAIN} using root domain ${SLD}"
  api_return=$(curl -sX POST "https://api.servercow.de/dns/v1/domains/${SLD}" \
    -H "X-Auth-Username: ${SCOW_User}" \
    -H "X-Auth-Password: ${SCOW_Pass}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"TXT\",\"name\":\"_acme-challenge.${SIGN_DOMAIN}\",\"content\":\"${TOKEN_VALUE}\",\"ttl\":0}")
  echo ${api_return} | grep -qi '{"message":"ok"}'
  if [[ $? != 0 ]]; then
    echo -e "\n\t ERROR: Post to API failed: ${api_return} \n"
    return 1
  else
    echo -e "\t API call succeeded: ${api_return}"
    if [[ ${SLEEP} == "y" ]]; then
    echo -e "\t Sleeping ${WAIT} seconds ..."
    sleep ${WAIT}
    fi
  fi
}

function clean_challenge() {
  local SIGN_DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

  # Start with SLD=SIGN_DOMAIN and break down SLD until it equals to the second level domain
  local SLD=${SIGN_DOMAIN}
  #until [[ -z $(dig ns ${SLD} +short | grep -viE 'ns.+.servercow.de') ]]; do
  until [[ ! -z $(dig ns ${SLD} +short | grep -iE 'ns.+\.servercow\.de') ]]; do
    SLD=${SLD#*.}
    if [ $(echo ${SLD} | awk -F. '{print NF-1}') -lt 1 ]; then
      echo -e "\n\t ERROR: Cannot determine root domain with a Servercow NS record for ${SIGN_DOMAIN} \n"
      return 1
    fi
  done

  echo -e "\t Deleting challenge record for ${SIGN_DOMAIN} using root domain ${SLD}"
  api_return=$(curl -sX DELETE "https://api.servercow.de/dns/v1/domains/${SLD}" \
    -H "X-Auth-Username: ${SCOW_User}" \
    -H "X-Auth-Password: ${SCOW_Pass}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"TXT\",\"name\":\"_acme-challenge.${SIGN_DOMAIN}\"}")
  echo ${api_return} | grep -qi '{"message":"ok"}'
  if [[ $? != 0 ]]; then
    echo -e "\n\t ERROR: Post to API failed: ${api_return} \n"
    return 1
  else
    echo -e "\t API call succeeded: ${api_return}"
  fi
}

deploy_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}" TIMESTAMP="${6}"

    # This hook is called once for each certificate that has been
    # produced. Here you might, for instance, copy your new certificates
    # to service-specific locations and reload the service.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    # - TIMESTAMP
    #   Timestamp when the specified certificate was created.
}

unchanged_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"

    # This hook is called once for each certificate that is still
    # valid and therefore wasn't reissued.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
}

invalid_challenge() {
    local DOMAIN="${1}" RESPONSE="${2}"

    # This hook is called if the challenge response has failed, so domain
    # owners can be aware and act accordingly.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - RESPONSE
    #   The response that the verification server returned
}

request_failure() {
    local STATUSCODE="${1}" REASON="${2}" REQTYPE="${3}"

    # This hook is called when an HTTP request fails (e.g., when the ACME
    # server is busy, returns an error, etc). It will be called upon any
    # response code that does not start with '2'. Useful to alert admins
    # about problems with requests.
    #
    # Parameters:
    # - STATUSCODE
    #   The HTML status code that originated the error.
    # - REASON
    #   The specified reason for the error.
    # - REQTYPE
    #   The kind of request that was made (GET, POST...)
}

startup_hook() {
  echo -e "\n\t\t $(date +%F' '%X): Start checking certs ...\n"
}

exit_hook() {
  echo -e "\n\t\t $(date +%F' '%X): Finished checking certs\n"
}

HANDLER="$1"; shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|deploy_cert|unchanged_cert|startup_hook|exit_hook)$ ]]; then
  LOOPS=$(($(echo "$@" | wc -w) / 3))
  LOOP=0
  echo "$@" | xargs -n3 | while read line; do
    let LOOP=LOOP+1
    if [ ${LOOP} -lt ${LOOPS} ]; then
      $HANDLER ${line} no_sleep
    else
      $HANDLER ${line}
    fi
  done
fi
