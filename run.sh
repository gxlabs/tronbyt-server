#!/usr/bin/with-contenv bashio
# ==============================================================================
# Home Assistant Add-on: Tronbyt Server
# Runs the Tronbyt Server
# ==============================================================================

# Wait for other services
bashio::net.wait_for 80 localhost 900

# Get configuration
SERVER_HOSTNAME_OR_IP=$(bashio::config 'server_hostname_or_ip')
PRODUCTION=$(bashio::config 'production')
TIMEZONE=$(bashio::config 'timezone')
SECRET_KEY=$(bashio::config 'secret_key')
REGISTRATION_ENABLED=$(bashio::config 'registration_enabled')
MAX_UPLOAD_SIZE=$(bashio::config 'max_upload_size')
SYSTEM_APP_DATA_LOCATION=$(bashio::config 'system_app_data_location')
LOG_LEVEL=$(bashio::config 'log_level')

# Set environment variables
export SERVER_HOSTNAME_OR_IP="${SERVER_HOSTNAME_OR_IP}"
export PRODUCTION="${PRODUCTION}"
export TZ="${TIMEZONE}"
export REGISTRATION_ENABLED="${REGISTRATION_ENABLED}"
export MAX_UPLOAD_SIZE="${MAX_UPLOAD_SIZE}"
export SYSTEM_APP_DATA_LOCATION="${SYSTEM_APP_DATA_LOCATION}"

# Set secret key if provided
if bashio::config.has_value 'secret_key'; then
    export SECRET_KEY="${SECRET_KEY}"
fi

# Set log level
case "${LOG_LEVEL}" in
    "debug")
        export LOGLEVEL="DEBUG"
        ;;
    "info")
        export LOGLEVEL="INFO"
        ;;
    "warning")
        export LOGLEVEL="WARNING"
        ;;
    "error")
        export LOGLEVEL="ERROR"
        ;;
    "critical")
        export LOGLEVEL="CRITICAL"
        ;;
    *)
        export LOGLEVEL="INFO"
        ;;
esac

# Create necessary directories
mkdir -p /share/tronbyt
mkdir -p "${SYSTEM_APP_DATA_LOCATION}"

# Set permissions
chown -R 1000:1000 /share/tronbyt

bashio::log.info "Starting Tronbyt Server..."
bashio::log.info "Server hostname/IP: ${SERVER_HOSTNAME_OR_IP}"
bashio::log.info "Production mode: ${PRODUCTION}"
bashio::log.info "Timezone: ${TIMEZONE}"
bashio::log.info "Registration enabled: ${REGISTRATION_ENABLED}"
bashio::log.info "Log level: ${LOG_LEVEL}"

# Start the application
exec /app/run