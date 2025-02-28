# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Indexer
class wazuh::indexer (
  # opensearch.yml configuration
  $indexer_network_host = '0.0.0.0',
  $indexer_node_name = 'node-1',
  $indexer_service = 'wazuh-indexer',
  $indexer_package = 'wazuh-indexer',
  $indexer_version = '5.0.0',
  $indexer_fileuser = 'wazuh-indexer',
  $indexer_filegroup = 'wazuh-indexer',
  $indexer_path_certs = '/etc/wazuh-indexer/certs',
  # JVM options
  $jvm_options_memory = '1g',
  $full_indexer_reinstall = false, # Change to true when whant a full reinstall of Wazuh indexer

) {
  package { "${indexer_package}":
    ensure => present,
  }
  wazuh::install_package { 'Wazuh indexer':
    package_name  => $indexer_package,
    wazuh_version => $indexer_version,
    unless        => Package["${indexer_package}"]
  }

  exec { "ensure full path of ${indexer_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${indexer_path_certs}",
    creates => $indexer_path_certs,
    require => Wazuh::Install_package['Wazuh indexer'],
  }
  -> file { $indexer_path_certs:
    ensure  => directory,
    owner   => $indexer_fileuser,
    group   => $indexer_filegroup,
    mode    => '0500',
    require => Wazuh::Install_package['Wazuh indexer'],
  }

  [
    "indexer-${indexer_node_name}.pem",
    "indexer-${indexer_node_name}-key.pem",
    'root-ca.pem',
    'admin.pem',
    'admin-key.pem',
  ].each |String $certfile| {
    file { "${indexer_path_certs}/${certfile}":
      ensure  => file,
      owner   => $indexer_fileuser,
      group   => $indexer_filegroup,
      mode    => '0400',
      replace => true,
      recurse => remote,
      source  => "puppet:///modules/archive/${certfile}",
      require => Wazuh::Install_package['Wazuh indexer'],
    }
  }

  $config = {
    'network.host'                                          => $indexer_network_host,
    'node.name'                                             => $indexer_node_name,
    'plugins.security.ssl.http.pemcert_filepath'            => "${indexer_path_certs}/indexer-${indexer_node_name}.pem",
    'plugins.security.ssl.http.pemkey_filepath'             => "${indexer_path_certs}/indexer-${indexer_node_name}-key.pem",
    'plugins.security.ssl.http.pemtrustedcas_filepath'      => "${indexer_path_certs}/root-ca.pem",
    'plugins.security.ssl.transport.pemcert_filepath'       => "${indexer_path_certs}/indexer-${indexer_node_name}.pem",
    'plugins.security.ssl.transport.pemkey_filepath'        => "${indexer_path_certs}/indexer-${indexer_node_name}-key.pem",
    'plugins.security.ssl.transport.pemtrustedcas_filepath' => "${indexer_path_certs}/root-ca.pem"
  }

  $config.each |$key, $value| {
    file_line { "opensearch_${key}":
      path    => '/etc/wazuh-indexer/opensearch.yml',
      line    => "${key}: \"${value}\"",
      match   => "^${key}:",
      notify  => Service['wazuh-indexer'],
      require => [
        Wazuh::Install_package['Wazuh indexer']
      ],
    }
  }

  service { 'wazuh-indexer':
    ensure  => running,
    enable  => true,
    name    => $indexer_service,
    require => Wazuh::Install_package['Wazuh indexer'],
  }

  file_line { "Insert line limits nofile for ${indexer_fileuser}":
    path    => '/etc/security/limits.conf',
    line    => "${indexer_fileuser} - nofile  65535",
    match   => "^${indexer_fileuser} - nofile\s",
    notify  => Service['wazuh-indexer'],
    require => Wazuh::Install_package['Wazuh indexer'],
  }
  file_line { "Insert line limits memlock for ${indexer_fileuser}":
    path    => '/etc/security/limits.conf',
    line    => "${indexer_fileuser} - memlock unlimited",
    match   => "^${indexer_fileuser} - memlock\s",
    notify  => Service['wazuh-indexer'],
    require => Wazuh::Install_package['Wazuh indexer'],
  }

  if $full_indexer_reinstall {
    file { $indexer_security_init_lockfile:
      ensure => absent,
      before => Exec['Initialize the Opensearch security index in Wazuh indexer'],
    }
  }
}
