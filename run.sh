#!/bin/bash

[ "${DEBUG}" == "yes" ] && set -x

function add_config_value() {
  local key=${1}
  local value=${2}
  # local config_file=${3:-/etc/postfix/main.cf}
  [ "${key}" == "" ] && echo "ERROR: No key set !!" && exit 1
  [ "${value}" == "" ] && echo "ERROR: No value set for ${key} !!" && exit 1

  echo "Setting configuration option ${key} with value: ${value}"
 postconf -e "${key} = ${value}"
}

# Read password and username from file to avoid unsecure env variables
if [ -n "${SMTP_PASSWORD_FILE}" ]; then [ -e "${SMTP_PASSWORD_FILE}" ] && SMTP_PASSWORD=$(cat "${SMTP_PASSWORD_FILE}") || echo "SMTP_PASSWORD_FILE defined, but file not existing, skipping."; fi
if [ -n "${SMTP_USERNAME_FILE}" ]; then [ -e "${SMTP_USERNAME_FILE}" ] && SMTP_USERNAME=$(cat "${SMTP_USERNAME_FILE}") || echo "SMTP_USERNAME_FILE defined, but file not existing, skipping."; fi

# Can set this if you are only looking for the container to relay mail to another host

#[ -z "${RELAY_HOST}" ] && echo "RELAY_HOST is not set" && exit 1
[ -z "${SERVER_HOSTNAME}" ] && echo "SERVER_HOSTNAME is not set" && exit 1
[ ! -z "${SMTP_USERNAME}" -a -z "${SMTP_PASSWORD}" ] && echo "SMTP_USERNAME is set but SMTP_PASSWORD is not set" && exit 1

RELAY_PORT="${RELAY_PORT:-587}"

#Get the domain from the server host name
DOMAIN=`echo ${SERVER_HOSTNAME} | awk 'BEGIN{FS=OFS="."}{print $(NF-1),$NF}'`

# Set needed config options
add_config_value "myhostname" ${SERVER_HOSTNAME}
add_config_value "mydomain" ${DOMAIN}
add_config_value "mydestination" "${DESTINATION:-localhost}"
add_config_value "myorigin" '$mydomain'
if [ ! -z ${RELAY_HOST} ] && [ ! -z ${RELAY_PORT} ]; then
	add_config_value "relayhost" "[${RELAY_HOST}]:${RELAY_PORT}"
fi
add_config_value "smtp_tls_security_level" "may"
if [ ! -z "${SMTP_USERNAME}" ]; then
  add_config_value "smtp_sasl_auth_enable" "yes"
  add_config_value "smtp_sasl_password_maps" "lmdb:/etc/postfix/sasl_passwd"
  add_config_value "smtp_sasl_security_options" "noanonymous"
fi
add_config_value "always_add_missing_headers" "${ALWAYS_ADD_MISSING_HEADERS:-no}"
#Also use "native" option to allow looking up hosts added to /etc/hosts via
# docker options (issue #51)
add_config_value "smtp_host_lookup" "native,dns"

if [ "${RELAY_PORT}" = "465" ]; then
  add_config_value "smtp_tls_wrappermode" "yes"
  add_config_value "smtp_tls_security_level" "encrypt"
fi

# Bind to both IPv4 and IPv4
add_config_value "inet_protocols" "all"

# Create sasl_passwd file with auth credentials
if [ ! -f /etc/postfix/sasl_passwd -a ! -z "${SMTP_USERNAME}" ]; then
  grep -q "${RELAY_HOST}" /etc/postfix/sasl_passwd  > /dev/null 2>&1
  if [ $? -gt 0 ]; then
    echo "Adding SASL authentication configuration"
    echo "[${RELAY_HOST}]:${RELAY_PORT} ${SMTP_USERNAME}:${SMTP_PASSWORD}" >> /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
  fi
fi

# Run postmap on supplied sasl password file
if [ ! -z ${SASL_PASSWORD_FILE} ] && [ -e ${SASL_PASSWORD_FILE} ]; then
  add_config_value "smtp_sasl_auth_enable" "yes"
  add_config_value "smtp_sasl_password_maps" "lmdb:${SASL_PASSWORD_FILE}"
  add_config_value "smtp_sasl_security_options" "noanonymous"
  postmap ${SASL_PASSWORD_FILE}
fi

#Set header tag
if [ ! -z "${SMTP_HEADER_TAG}" ]; then
  postconf -e "header_checks = regexp:/etc/postfix/header_checks"
  echo -e "/^MIME-Version:/i PREPEND RelayTag: $SMTP_HEADER_TAG\n/^Content-Transfer-Encoding:/i PREPEND RelayTag: $SMTP_HEADER_TAG" >> /etc/postfix/header_checks
  echo "Setting configuration option SMTP_HEADER_TAG with value: ${SMTP_HEADER_TAG}"
fi

#Enable logging of subject line
if [ "${LOG_SUBJECT}" == "yes" ]; then
  postconf -e "header_checks = regexp:/etc/postfix/header_checks"
  echo -e "/^Subject:/ WARN" >> /etc/postfix/header_checks
  echo "Enabling logging of subject line"
fi

#Check for subnet restrictions
nets='10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'
if [ ! -z "${SMTP_NETWORKS}" ]; then
  declare ipv6re="^((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|\
    ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|\
    ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|\
    ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|\
    :((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}|\
    ::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|\
    (2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|\
    (2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/[0-9]{1,3})$"

  for i in $(sed 's/,/\ /g' <<<$SMTP_NETWORKS); do
    if grep -Eq "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}" <<<$i ; then
      nets+=", $i"
    elif grep -Eq "$ipv6re" <<<$i ; then
      readarray -d \/ -t arr < <(printf '%s' "$i")
      nets+=", [${arr[0]}]/${arr[1]}"
    else
      echo "$i is not in proper IPv4 or IPv6 subnet format. Ignoring."
    fi
  done
fi
add_config_value "mynetworks" "${nets}"

# Set SMTPUTF8
if [ ! -z "${SMTPUTF8_ENABLE}" ]; then
  postconf -e "smtputf8_enable = ${SMTPUTF8_ENABLE}"
  echo "Setting configuration option smtputf8_enable with value: ${SMTPUTF8_ENABLE}"
fi

if [ ! -z "${OVERWRITE_FROM}" ]; then
  echo -e "/^From:.*$/ REPLACE From: $OVERWRITE_FROM" > /etc/postfix/smtp_header_checks
  postmap /etc/postfix/smtp_header_checks
  postconf -e 'smtp_header_checks = regexp:/etc/postfix/smtp_header_checks'
  echo "Setting configuration option OVERWRITE_FROM with value: ${OVERWRITE_FROM}"
fi

# Set mailbox_size_limit
if [ ! -z "${MAILBOX_SIZE_LIMIT}" ]; then
  postconf -e "mailbox_size_limit = ${MAILBOX_SIZE_LIMIT}"
  echo "Setting configuration option mailbox_size_limit with value: ${MAILBOX_SIZE_LIMIT}"
fi

# Set message_size_limit
if [ ! -z "${MESSAGE_SIZE_LIMIT}" ]; then
  postconf -e "message_size_limit = ${MESSAGE_SIZE_LIMIT}"
  echo "Setting configuration option message_size_limit with value: ${MESSAGE_SIZE_LIMIT}"
fi

# Set paths for ssl certs
if [ -e "${SSL_CERT_PATH}" ] && [ -e "${SSL_KEY_PATH}" ]; then
  add_config_value "smtpd_tls_cert_file" "${SSL_CERT_PATH}"
  add_config_value "smtpd_tls_key_file" "${SSL_KEY_PATH}"
fi

# Set smtp_tls_fingerprint_digest
if [ ! -z "${SMTP_TLS_FINGERPRINT_DIGEST}" ]; then
  add_config_value "smtp_tls_fingerprint_digest" "${SMTP_TLS_FINGERPRINT_DIGEST}"
fi

# Set smtpd_tls_fingerprint_digest

if [ ! -z "${SMTPD_TLS_FINGERPRINT_DIGEST}" ]; then
  add_config_value "smtpd_tls_fingerprint_digest" "${SMTPD_TLS_FINGERPRINT_DIGEST}"
fi

# Set locations of virtual table mappings

if [ ! -z "${RELAY_DOMAINS}" ]; then
  add_config_value "relay_domains" "${RELAY_DOMAINS}"
fi

if [ ! -z "${VIRTUAL_MAILBOX_DOMAINS}" ]; then
  add_config_value "virtual_mailbox_domains" "${VIRTUAL_MAILBOX_DOMAINS}"
fi

if [ ! -z "${VIRTUAL_ALIAS_MAPS}" ]; then
  add_config_value "virtual_alias_maps" "${VIRTUAL_ALIAS_MAPS}"
fi

if [ ! -z "${VIRTUAL_MAILBOX_MAPS}" ]; then
  add_config_value "virtual_mailbox_maps" "${VIRTUAL_MAILBOX_MAPS}"
fi

if [ ! -z "${TRANSPORT_MAPS}" ]; then
  add_config_value "transport_maps" "${TRANSPORT_MAPS}"
fi


if [ ! -z "${SMTPD_SENDER_LOGIN_MAPS}" ]; then
  add_config_value "smtpd_sender_login_maps" "${SMTPD_SENDER_LOGIN_MAPS}"
fi

if [ ! -z "${VIRTUAL_MAILBOX_BASE}" ]; then
  add_config_value "virtual_mailbox_base" "${VIRTUAL_MAILBOX_BASE}"
fi

if [ ! -z "${VIRTUAL_MINIMUM_UID}" ]; then
  add_config_value "virtual_minimum_uid" "${VIRTUAL_MINIMUM_UID}"
fi

if [ ! -z "${VIRTUAL_UID_MAPS}" ]; then
  add_config_value "virtual_uid_maps" "${VIRTUAL_UID_MAPS}"
fi

if [ ! -z "${VIRTUAL_GID_MAPS}" ]; then
  add_config_value "virtual_gid_maps" "${VIRTUAL_GID_MAPS}"
fi

if [ ! -z "${LOCAL_TRANSPORT}" ]; then
  add_config_value "local_transport" "${LOCAL_TRANSPORT}"
fi

if [ ! -z "${LOCAL_RECIPIENT_MAPS}" ]; then
  add_config_value "local_recipient_maps" "${LOCAL_RECIPIENT_MAPS}"
fi

if [ ! -z "${SMTPD_SASL_TYPE}" ]; then
  add_config_value "smtpd_sasl_type" "${SMTPD_SASL_TYPE}"
fi

if [ ! -z "${SMTPD_SASL_PATH}" ]; then
  saslproto=`echo ${SMTPD_SASL_PATH} | cut -f1 -d:`
  saslport=`echo ${SMTPD_SASL_PATH} | cut -f3 -d:`
  saslhost=`echo ${SMTPD_SASL_PATH} | cut -f2 -d:`
  saslip=`getent hosts ${saslhost} | awk '{print $1}' | tr -d '\n'`
  add_config_value "smtpd_sasl_path" "${saslproto}:${saslip}:${saslport}"
fi

if [ ! -z "${SMTPD_SASL_AUTHENTICATED_HEADER}" ]; then
  add_config_value "smtpd_sasl_authenticated_header" "${SMTPD_SASL_AUTHENTICATED_HEADER}"
fi

if [ ! -z "${SMTPD_SASL_AUTH_ENABLE}" ]; then
  add_config_value "smtpd_sasl_auth_enable" "${SMTPD_SASL_AUTH_ENABLE}"
fi

if [ ! -z "${BROKEN_SASL_AUTH_CLIENTS}" ]; then
  add_config_value "broken_sasl_auth_clients" "${BROKEN_SASL_AUTH_CLIENTS}"
fi

if [ ! -z "${SMTPD_SENDER_RESTRICTIONS}" ]; then
  add_config_value "smtpd_sender_restrictions" "${SMTPD_SENDER_RESTRICTIONS}"
fi

if [ ! -z "${INET_INTERFACES}" ]; then
  add_config_value "inet_interfaces" "${INET_INTERFACES}"
fi

if [ ! -z "${SMTPD_RELAY_RESTRICTIONS}" ]; then
  add_config_value "smtpd_relay_restrictions" "${SMTPD_RELAY_RESTRICTIONS}"
fi

if [ ! -z "${SMTPD_CLIENT_RESTRICTIONS}" ]; then
  add_config_value "smtpd_client_restrictions" "${SMTPD_CLIENT_RESTRICTIONS}"
fi

if [ ! -z "${SMTPD_RECIPIENT_RESTRICTIONS}" ]; then
  add_config_value "smtpd_recipient_restrictions" "${SMTPD_RECIPIENT_RESTRICTIONS}"
fi

if [ ! -z "${LOCAL_HEADER_REWRITE_CLIENTS}" ]; then
  add_config_value "local_header_rewrite_clients" "${LOCAL_HEADER_REWRITE_CLIENTS}"
fi

if [ ! -z "${SMTPD_UPSTREAM_PROXY_PROTOCOL}" ]; then
  add_config_value "smtpd_upstream_proxy_protocol" "${SMTPD_UPSTREAM_PROXY_PROTOCOL}"
fi

STDOUT_LOGGER="${STDOUT_LOGGER:-TRUE}"
if [ "${STDOUT_LOGGER,,}" == "true" ]; then
  add_config_value "maillog_file" "/dev/stdout"
else
  add_config_value "maillog_file" "/var/log/maillog"
fi

#Start services

# If host mounting /var/spool/postfix, we need to delete old pid file before
# starting services
rm -f /var/spool/postfix/pid/master.pid

if [ -e /postconfig.sh ]; then
  echo "Executing custom postconfig script..."
  /postconfig.sh
fi

exec /usr/sbin/postfix -c /etc/postfix start-fg
