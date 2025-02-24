# Copyright (C) 2015, Wazuh Inc.
# Main Wazuh server config
#
class wazuh::server (
  String $server_version = '4.9.2',
  String $server_package = 'wazuh-server',
  String $server_node_name = 'node-1',
  String $server_path_certs = '/etc/wazuh-server/certs',
  String $server_fileuser = 'wazuh-server',
  String $server_filegroup = 'wazuh-server',
  String $server_indexer_node_host = 'localhost',
  String $server_api_host = 'localhost',
  String $yaml_file = '/etc/wazuh-server/wazuh-server.yml',
) {
  # Install Wazuh Manager
  wazuh::install_package { 'Wazuh server':
    package_name  => $server_package,
    wazuh_version => $server_version,
  }

  [
   "server-${server_node_name}.pem",
   "server-${server_node_name}-key.pem",
   'root-ca.pem',
   'admin.pem',
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
      require => Wazuh::install_package['Wazuh server'],
    }
  }

  # Generate private key
  exec { 'generate-private-key':
    command => "openssl ecparam -name secp256k1 -genkey -noout -out ${server_path_certs}/private-key.pem",
    creates => "${server_path_certs}/private-key.pem",
    path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    require => Wazuh::install_package['Wazuh server'],
  }

  # Generate public key
  exec { 'generate-public-key':
    command => "openssl ec -in ${server_path_certs}/private-key.pem -pubout -out ${server_path_certs}/public-key.pem",
    creates => "${server_path_certs}/public-key.pem",
    path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
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
  service { 'wazuh-server':
    ensure => running,
    enable => true,
  }
}
