# Copyright (C) 2015, Wazuh Inc.
# Main ossec server config
#
# @param version The version of Wazuh Manager to install
class wazuh::manager (
  String $version = '4.9.2',
) {
  include wazuh::install_product
  # Install Wazuh Manager
  wazuh::install_product { 'wazuh-manager':
    package_name  => 'wazuh-manager',
    wazuh_version => $version,
  }

  # Setting up specific files for Wazuh Manager
  wazuh::modify_config_file { 'ossec_conf':
    config_file  => '/var/ossec/etc/ossec.conf',
    config_lines => ['<server>enabled</server>'],
    file_type    => 'xml',
    replace_all  => false,
  }

  # Manage the service
  service { 'wazuh-manager':
    ensure  => running,
    enable  => true,
    require => Wazuh::Install_product['wazuh-manager'],
  }
}
