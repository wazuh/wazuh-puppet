
class wazuh::wazuh_api (

  $wazuh_api_package = "wazuh-api",
  $wazuh_api_service = "wazuh-api",
  $wazuh_api_version = "3.9.1-1",

  $nodejs_package = "nodejs"

){

  exec { 'Installing node repository':
    command => "cd /tmp && curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -",
    provider => 'shell',
  }
  if $::osfamily == 'Debian' {
    exec { 'Updating repositories...':
      command => "apt update",
      provider => 'shell',
    }
  }else{
    exec { 'Updating repositories...':
      command => "yum update",
      provider => 'shell',
    }
  }

  package { $nodejs_package:
  }

  package { $wazuh_api_package:
    ensure  => $wazuh_api_version,
  }

  service { "wazuh-api":
    ensure  => running,
    enable  => true,
  }


}
