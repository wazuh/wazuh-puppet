class wazuh_dashboard {
  include install_product
  include modify_config_file

  install_product { 'wazuh-dashboard':
    package_name    => 'wazuh-dashboard',
    desired_version => '5.0.0',
  }

  # Configure specific files for Wazuh Dashboard
  modify_config_file {
    config_file = '/car/ossec/etc/ossec.conf',
    config_lines = [],
    file_type = 'yaml'
  }

  service { 'wazuh-dashboard':
    ensure => running,
    enable => true,
  }
}
