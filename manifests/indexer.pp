# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Indexer
class wazuh::indexer (
  # opensearch.yml configuration
  $indexer_network_host = '0.0.0.0',
  $indexer_cluster_name = 'wazuh-cluster',
  $indexer_node_name = 'node-1',
  $indexer_node_max_local_storage_nodes = '1',
  $indexer_service = 'wazuh-indexer',
  $indexer_package = 'wazuh-indexer',
  $indexer_version = '4.12.0',
  $indexer_fileuser = 'wazuh-indexer',
  $indexer_filegroup = 'wazuh-indexer',

  $indexer_node_cert_source = "puppet:///modules/archive/indexer-${indexer_node_name}.pem",
  $indexer_node_certkey_source = "puppet:///modules/archive/indexer-${indexer_node_name}-key.pem",
  $indexer_node_rootca_source = 'puppet:///modules/archive/root-ca.pem',
  $indexer_node_admincert_source = 'puppet:///modules/archive/admin.pem',
  $indexer_node_adminkey_source = 'puppet:///modules/archive/admin-key.pem',

  $indexer_path_data = '/var/lib/wazuh-indexer',
  $indexer_path_logs = '/var/log/wazuh-indexer',
  $indexer_path_certs = '/etc/wazuh-indexer/certs',
  $indexer_security_init_lockfile = '/var/tmp/indexer-security-init.lock',
  $full_indexer_reinstall = false, # Change to true when whant a full reinstall of Wazuh indexer

  $indexer_ip = 'localhost',
  $indexer_port = '9200',
  $indexer_discovery_hosts = [], # Empty array for single-node configuration
  $indexer_cluster_initial_master_nodes = ['node-1'],
  $indexer_cluster_cn = ['node-1'],

  # JVM options
  $jvm_options_memory = '1g',
) {
  # assign version according to the package manager
  case $facts['os']['family'] {
    'Debian': {
      $indexer_version_install = "${indexer_version}-*"
    }
    'Linux', 'RedHat', default: {
      $indexer_version_install = $indexer_version
    }
  }

  # install package
  package { 'wazuh-indexer':
    ensure => $indexer_version_install,
    name   => $indexer_package,
  }

  exec { "ensure full path of ${indexer_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${indexer_path_certs}",
    creates => $indexer_path_certs,
    require => Package['wazuh-indexer'],
  }
  -> file { $indexer_path_certs:
    ensure => directory,
    owner  => $indexer_fileuser,
    group  => $indexer_filegroup,
    mode   => '0500',
  }

  file { "${indexer_path_certs}/indexer-${indexer_node_name}.pem":
    ensure  => file,
    owner   => $indexer_fileuser,
    group   => $indexer_filegroup,
    mode    => '0400',
    source  => $indexer_node_cert_source,
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file { "${indexer_path_certs}/indexer-${indexer_node_name}-key.pem":
    ensure  => file,
    owner   => $indexer_fileuser,
    group   => $indexer_filegroup,
    mode    => '0400',
    source  => $indexer_node_certkey_source,
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file { "${indexer_path_certs}/root-ca.pem":
    ensure  => file,
    owner   => $indexer_fileuser,
    group   => $indexer_filegroup,
    mode    => '0400',
    source  => $indexer_node_rootca_source,
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file { "${indexer_path_certs}/admin.pem":
    ensure  => file,
    owner   => $indexer_fileuser,
    group   => $indexer_filegroup,
    mode    => '0400',
    source  => $indexer_node_admincert_source,
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file { "${indexer_path_certs}/admin-key.pem":
    ensure  => file,
    owner   => $indexer_fileuser,
    group   => $indexer_filegroup,
    mode    => '0400',
    source  => $indexer_node_adminkey_source,
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file { 'configuration file':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    content => template('wazuh/wazuh_indexer_yml.erb'),
    group   => $indexer_filegroup,
    mode    => '0660',
    owner   => $indexer_fileuser,
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file_line { 'Insert line initial size of total heap space':
    path    => '/etc/wazuh-indexer/jvm.options',
    line    => "-Xms${jvm_options_memory}",
    match   => '^-Xms',
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file_line { 'Insert line maximum size of total heap space':
    path    => '/etc/wazuh-indexer/jvm.options',
    line    => "-Xmx${jvm_options_memory}",
    match   => '^-Xmx',
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  service { 'wazuh-indexer':
    ensure  => running,
    enable  => true,
    name    => $indexer_service,
    require => Package['wazuh-indexer'],
  }

  file_line { "Insert line limits nofile for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - nofile  65535",
    match  => "^${indexer_fileuser} - nofile\s",
    notify => Service['wazuh-indexer'],
  }
  file_line { "Insert line limits memlock for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - memlock unlimited",
    match  => "^${indexer_fileuser} - memlock\s",
    notify => Service['wazuh-indexer'],
  }

  if $full_indexer_reinstall {
    file { $indexer_security_init_lockfile:
      ensure  => absent,
      require => Package['wazuh-indexer'],
      before  => Exec['Initialize the Opensearch security index in Wazuh indexer'],
    }
  }
}
