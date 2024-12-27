# Copyright (C) 2015, Wazuh Inc.
# Main ossec server config
class wazuh::manager (
  String $version = '4.9.2',
) {

  # Instalar Wazuh Manager
  wazuh::install_product { 'wazuh-manager':
    package_name   => 'wazuh-manager',
    wazuh_version  => $version,
  }

  # Configurar archivos específicos para Wazuh Manager
  wazuh::modify_config_file { 'ossec_conf':
    config_file    => '/var/ossec/etc/ossec.conf',
    config_lines   => ['<server>enabled</server>'], # Añadir configuraciones específicas
    file_type      => 'xml',
    replace_all    => false,
  }

  # Administrar el servicio
  service { 'wazuh-manager':
    ensure    => running,
    enable    => true,
    require   => Wazuh::Install_product['wazuh-manager'], # Asegurar que se instala antes de gestionar el servicio
  }
}