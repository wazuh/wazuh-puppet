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
      '/ossec_config/localfile/log_format = journald',
      '/ossec_config/localfile/location = journald',
      '/ossec_config/global/logall = yes',
      '/ossec_config/global/logall_new = abracadabra',
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
