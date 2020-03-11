# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Wazuh API installation

class wazuh::wazuh_api::nodejs (
  $nodejs_package = 'nodejs'
){
  if $::osfamily == 'Debian' {
    exec { 'Updating repositories...':
      path    => '/usr/bin',
      command => 'curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -',
    }
    package { $nodejs_package:
      provider => 'apt',
    }
  } else {
    exec { 'Updating repositories...':
      path    => '/usr/bin',
      command => 'curl --silent --location https://rpm.nodesource.com/setup_10.x | bash -',

    }
    package { $nodejs_package:
      provider => 'yum',
    }
  }
}

