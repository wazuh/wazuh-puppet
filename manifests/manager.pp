# Copyright (C) 2015, Wazuh Inc.
# Main ossec server config
#
# @param version The version of Wazuh Manager to install
class wazuh::manager (
  String $version = '4.9.2',
) {
  # Install Wazuh Manager
  class { 'wazuh::install_product':
    package_name  => 'wazuh-manager',
    wazuh_version => $version,
  }

  # Setting up specific files for Wazuh Manager
  class { 'wazuh::modify_config_file':
    config_path   => '/var/ossec/etc/ossec.conf',
    lines         => [
      '/configuration/server/port = 8081',
      '/configuration/database/host = 127.0.0.1',
      '/configuration/database/timeout = 30s',
      '/configuration/new_section/new_value = my_new_value',
    ],
    file_type     => 'xml',
    force_add_xml => true,
  }

  # Manage the service
  service { 'wazuh-manager':
    ensure  => running,
    enable  => true,
    require => wazuh::install_product['wazuh-manager'],
  }
}
