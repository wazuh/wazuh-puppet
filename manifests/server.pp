# Copyright (C) 2015, Wazuh Inc.
# Main Wazuh server config
#
class wazuh::server (
  String $version = '4.9.2',
  String $server_package = 'wazuh-manager',
  String $server_node_name = 'node-1',
  String $server_path_certs = '/etc/wazuh-server/certs',
  String $server_fileuser = 'wazuh-server',
  String $server_filegroup = 'wazuh-server',
) {
  # Install Wazuh Manager
  wazuh::install_product { 'Wazuh manager':
    package_name  => $server_package,
    wazuh_version => $version,
  }

  [
   "server-${server_node_name}.pem",
   "server-${server_node_name}-key.pem",
   'root-ca.pem',
   'admin.pemuuu',
   'admin-key.pem',
  ].each |String $certfile| {
    file { "${server_path_certs}/${certfile}":
      ensure  => file,
      owner   => $server_fileuser,
      group   => $server_filegroup,
      mode    => '0400',
      replace => true,
      recurse => remote,
      source  => "puppet:///modules/archive/${certfile}",
      require => Wazuh::Install_product['Wazuh manager'],
    }
  }

  # Generate private key
  exec { 'generate-private-key':
    command => "openssl ecparam -name secp256k1 -genkey -noout -out ${server_path_certs}/private-key.pem",
    creates => "${server_path_certs}/private-key.pem",
    require => Wazuh::Install_product['Wazuh manager'],
  }

  # Generate public key
  exec { 'generate-public-key':
    command => "openssl ec -in ${server_path_certs}/private-key.pem -pubout -out ${server_path_certs}/public-key.pem",
    creates => "${server_path_certs}/public-key.pem",
    require => Exec['generate-private-key'],
  }

  # Set ownership for private key
  file { "${server_path_certs}/private-key.pem":
    owner   => $server_fileuser,
    group   => $server_filegroup,
    require => Exec['generate-private-key'],
  }

  # Set ownership for public key
  file { "${server_path_certs}/public-key.pem":
    owner   => $server_fileuser,
    group   => $server_filegroup,
    require => Exec['generate-public-key'],
  }

  # Manage the service
  service { 'wazuh-manager':
    ensure => running,
    enable => true,
  }
}
