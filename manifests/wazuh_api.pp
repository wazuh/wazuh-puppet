# Wazuh App Copyright (C) 2020 Wazuh Inc. (License GPLv2)
# Wazuh API installation
class wazuh::wazuh_api (

  $manage_nodejs_package = true,
  $wazuh_api_package = 'wazuh-api',
  $wazuh_api_service = 'wazuh-api',
  $wazuh_api_version = '3.13.2-1',

){
  if $manage_nodejs_package {
    contain wazuh::wazuh_api::nodejs
  }

  if $::osfamily == 'Debian' {
    package { $wazuh_api_package:
      ensure   => $wazuh_api_version,
      provider => 'apt',
    }
  } else {
    package { $wazuh_api_package:
      ensure   => $wazuh_api_version,
      provider => 'yum',
    }
  }

  service { 'wazuh-api':
    ensure   => running,
    enable   => true,
    provider => 'systemd',
    require  => Package[$wazuh_api_package],
  }
}
