class wazuh_agent {
  include install_product
  include modify_config_file

  install_product { 'wazuh-agent':
    package_name    => 'wazuh-agent',
    desired_version => '5.0.0',
  }

  # Configure specific files for Wazuh Agent
  modify_config_file {
    config_file = '/car/ossec/etc/ossec.conf',
    config_lines = [],
    file_type = 'xml'
  }

  service { 'wazuh-agent':
    ensure => running,
    enable => true,
  }
}
