# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Wazuh API installation
class wazuh::wazuh_api (
  Boolean $manage_nodejs_package = true,
  String[1] $nodejs_package = 'nodejs',
  String[1] $wazuh_api_package = 'wazuh-api',
  String[1] $wazuh_api_service = 'wazuh-api',
  String[1] $wazuh_api_version = '3.11.3-1'
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

class wazuh::wazuh_api::nodejs {
  if $::osfamily == 'Debian' {
    exec { 'Updating repositories...':
      path    => '/usr/bin',
      command => 'curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -',
    }
    package { $nodejs_package:
      provider => 'apt',
    }
  } else {
    exec { 'Updating repositories...':
      path    => '/usr/bin',
      command => 'curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -',

    }
    package { $nodejs_package:
      provider => 'yum',
    }
  }
}
