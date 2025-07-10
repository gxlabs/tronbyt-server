# Home Assistant Add-on: Tronbyt Server

Manage your apps on your Tronbyt completely locally without relying on cloud services.

## About

This add-on provides a Flask-based web application for managing apps on your Tronbyt (flashed Tidbyt) devices. It allows you to run your Tronbyt/Tidbyt completely locally without relying on external backend servers.

## Features

- Web UI with better app discoverability
- Fully local operation with no cloud dependencies
- Support for custom hardware and LED matrix displays
- Community app support
- Local firmware generation and flashing capabilities

## Installation

1. Add this repository to your Home Assistant Add-on store
2. Install the "Tronbyt Server" add-on
3. Configure the add-on options
4. Start the add-on

## Configuration

**Note**: _Remember to restart the add-on when the configuration is changed._

Example add-on configuration:

```yaml
server_hostname_or_ip: "homeassistant.local"
production: true
timezone: "America/New_York"
secret_key: "your-secret-key-here"
registration_enabled: true
max_upload_size: 10485760
system_app_data_location: "/share/tronbyt/system-apps"
log_level: "info"
```

### Option: `server_hostname_or_ip`

The hostname or IP address that devices will use to connect to the server. This should be the address of your Home Assistant instance.

### Option: `production`

Set to `true` for production mode, `false` for development mode.

### Option: `timezone`

The timezone for the server (e.g., "America/New_York", "Europe/London").

### Option: `secret_key`

A secret key for session management. If not provided, a random key will be generated.

### Option: `registration_enabled`

Whether to allow new user registration. Set to `false` to disable registration.

### Option: `max_upload_size`

Maximum file upload size in bytes (default: 10MB).

### Option: `system_app_data_location`

Location to store system app data (default: "/share/tronbyt/system-apps").

### Option: `log_level`

Log level for the application (debug, info, warning, error, critical).

## Usage

1. After starting the add-on, access the web interface at `http://homeassistant.local:8000`
2. Login with the default credentials: `admin` / `password`
3. Add your Tronbyt device(s) in the device manager
4. Configure and install apps from the extensive community app library
5. Generate custom firmware with your WiFi credentials

## Supported Devices

- Tidbyt Gen1 and Gen2
- Tronbyt S3
- Raspberry Pi with 64x32 LED matrix
- Pixoticker (limited memory)
- Custom hardware with compatible firmware

## Support

For issues and feature requests, please visit:
- [GitHub Repository](https://github.com/tronbyt/server)
- [Community Support](https://github.com/tronbyt/server/issues)

## License

Apache License 2.0