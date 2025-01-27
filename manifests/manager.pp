# Copyright (C) 2015, Wazuh Inc.
# Main ossec server config
#
# @param version The version of Wazuh Manager to install
class wazuh::manager (
  String $version = '4.9.2',
  String $manager_package = 'wazuh-manager',
) {
  # Install Wazuh Manager
  wazuh::install_product { 'Wazuh manager':
    package_name  => $manager_package,
    wazuh_version => $version,
  }

  # Manage the service
  service { 'wazuh-manager':
    ensure  => running,
    enable  => true,
  }
}
