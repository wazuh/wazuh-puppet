# Wazuh App Copyright (C) 2020 Wazuh Inc. (License GPLv2)
# Wazuh-API configuration parameters
class wazuh::params_api {


  $wazuh_api_host = 0.0.0.0
  $wazuh_api_port = 55000

  $wazuh_api_file =  

  # Set this option to "yes" in case the API is running behind a proxy server. Values: yes, no
  $wazuh_api_behind_proxy_server = 'no'

  # Advanced configuration
  $wazuh_api_https_enabled = 'yes'
  $wazuh_api_https_key = 'api/configuration/ssl/server.key'
  $wazuh_api_https_cert = 'api/configuration/ssl/server.crt'
  $wazuh_api_https_use_ca = 'False'
  $wazuh_api_https_ca = 'api/configuration/ssl/ca.crt'


  # Logging configuration
  # Values for API log level: disabled, info, warning, error, debug, debug2 (each level includes the previous level).
  $wazuh_api_logs_level = 'info'
  $wazuh_api_logs_path = 'logs/api.log'

  # Cross-origin resource sharing: https://github.com/aio-libs/aiohttp-cors#usage
  # cors:
  $wazuh_api_cors_enabled = 'no'
  $wazuh_api_cors_source_route = '*'
  $wazuh_api_cors_expose_headers = '*'
  $wazuh_api_cors_allow_headers = '*'
  $wazuh_api_cors_allow_credentials = 'no'

  # Cache (time in seconds)
  # cache:
  $wazuh_api_cache_enabled = 'yes'
  $wazuh_api_cache_time = '0.750'

  # Access parameters
  # access:

  $wazuh_api_access_max_login_attempts = 5
  $wazuh_api_access_block_time = 300
  $wazuh_api_access_max_request_per_minute = 300

  # Force the use of authd when adding and removing agents. Values: yes, no
  $wazuh_api_use_only_authd = 'no'

  # Drop privileges (Run as ossec user)
  $wazuh_api_drop_privileges = 'yes'

  # Enable features under development
  $wazuh_api_experimental_features = 'no'

  # Wazuh API template path
  $wazuh_api_template = 'wazuh/wazuh_api.erb'


}
