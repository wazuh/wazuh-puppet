class wazuh::wazuh_manager(
){

  waazuh::install_product { 'wazuh-manager':
    package_name    => 'wazuh-manager',
    wazuh_version => '5.0.0',
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
