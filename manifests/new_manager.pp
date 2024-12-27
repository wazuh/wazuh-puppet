class wazuh_manager {
  include install_product
  include modify_config_file

  install_product { 'wazuh-manager':
    package_name    => 'wazuh-manager',
    wazuh_version => '5.0.0',
  }

  # Configure specific files for Wazuh Manager
  modify_config_file {
    config_file = '/car/ossec/etc/ossec.conf',
    config_lines = [],
    file_type = 'xml'
  }

  service { 'wazuh-manager':
    ensure => running,
    enable => true,
  }
}
