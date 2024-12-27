# Copyright (C) 2015, Wazuh Inc.
# Main ossec server config
class wazuh::manager (

  $version = '4.9.2'
){

  wazuh::install_product { 'wazuh-manager':
    package_name    => 'wazuh-manager',
    wazuh_version => $version,
  }

  # Configure specific files for Wazuh Manager
  wazuh::modify_config_file {
    config_file = '/car/ossec/etc/ossec.conf',
    config_lines = [],
    file_type = 'xml'
  }


  service { 'wazuh-manager':
    ensure => running,
    enable => true,
  }
}
