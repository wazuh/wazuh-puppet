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
) {
  # Install Wazuh Manager
  wazuh::install_product { 'Wazuh server':
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
      require => Wazuh::Install_product['Wazuh server'],
    }
  }

  # Generate private key
  exec { 'generate-private-key':
    command => "openssl ecparam -name secp256k1 -genkey -noout -out ${server_path_certs}/private-key.pem",
    creates => "${server_path_certs}/private-key.pem",
    path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    require => Wazuh::Install_product['Wazuh server'],
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

  yaml_setting { 'server_node_name':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'server.node.name',
    value  => $server_node_name,
  }

  yaml_setting { 'indexer_hosts_0_host':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'indexer.hosts.0.host',
    value  => $server_indexer_node_host,
  }

  yaml_setting { 'server_node_ssl_key':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'server.node.ssl.key',
    value  => "/etc/wazuh-server/certs/server-${server_node_name}-key.pem",
  }

  yaml_setting { 'server_node_ssl_cert':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'server.node.ssl.cert',
    value  => "/etc/wazuh-server/certs/server-${server_node_name}.pem",
  }

  yaml_setting { 'indexer_ssl_key':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'indexer.ssl.key',
    value  => "/etc/wazuh-server/certs/server-${server_node_name}-key.pem",
  }

  yaml_setting { 'indexer_ssl_certificate':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'indexer.ssl.certificate',
    value  => "/etc/wazuh-server/certs/server-${server_node_name}.pem",
  }

  yaml_setting { 'communications_api_host':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'communications_api.host',
    value  => $server_api_host,
  }

  yaml_setting { 'communications_api_ssl_key':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'communications_api.ssl.key',
    value  => "/etc/wazuh-server/certs/server-${server_node_name}-key.pem",
  }

  yaml_setting { 'communications_api_ssl_cert':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'communications_api.ssl.cert',
    value  => "/etc/wazuh-server/certs/server-${server_node_name}.pem",
  }

  yaml_setting { 'management_api_ssl_key':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'management_api.ssl.key',
    value  => "/etc/wazuh-server/certs/server-${server_node_name}-key.pem",
  }

  yaml_setting { 'management_api_ssl_cert':
    ensure => present,
    target => '/etc/wazuh-server/wazuh-server.yml',
    key    => 'management_api.ssl.cert',
    value  => "/etc/wazuh-server/certs/server-${server_node_name}.pem",
  }

  # Manage the service
  service { 'wazuh-manager':
    ensure => running,
    enable => true,
  }
}
