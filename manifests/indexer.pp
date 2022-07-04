# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Indexer
class wazuh::indexer (
  # opensearch.yml configuration
  $indexer_cluster_name = 'wazuh-cluster',
  $indexer_node_name = 'node-1',
  $indexer_node_master = true,
  $indexer_node_data = true,
  $indexer_node_ingest = true,
  $indexer_node_max_local_storage_nodes = '1',
  $indexer_service = 'wazuh-indexer',
  $indexer_package = 'wazuh-indexer',
  $indexer_version = '4.3.5-1',
  $indexer_fileuser = 'wazuh-indexer',
  $indexer_filegroup = 'wazuh-indexer',

  $indexer_path_data = '/var/lib/wazuh-indexer',
  $indexer_path_logs = '/var/log/wazuh-indexer',
  $indexer_path_certs = '/etc/wazuh-indexer/certs',

  $indexer_ip = 'localhost',
  $indexer_port = '9200',
  $indexer_discovery_option = 'discovery.type: single-node',
  $indexer_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['node-1']",

  $manage_repos = false, # Change to true when manager is not present.

  # JVM options
  $jvm_options_memmory = '1g',
) {
  if $manage_repos {
    include wazuh::repo
    if $facts['os']['family'] == 'Debian' {
      Class['wazuh::repo'] -> Class['apt::update'] -> Package['wazuh-indexer']
    } else {
      Class['wazuh::repo'] -> Package['wazuh-indexer']
    }
  }

  # install package
  package { 'wazuh-indexer':
    ensure => $indexer_version,
    name   => $indexer_package,
  }

  require wazuh::certificates

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

  [
    'indexer.pem',
    'indexer-key.pem',
    'root-ca.pem',
    'admin.pem',
    'admin-key.pem',
  ].each |String $certfile| {
    file { "${indexer_path_certs}/${certfile}":
      ensure  => file,
      owner   => $indexer_fileuser,
      group   => $indexer_filegroup,
      mode    => '0400',
      replace => false,  # only copy content when file not exist
      source  => "/tmp/wazuh-certificates/${certfile}",
    }
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

  # TODO: this should be done by the package itself and not by puppet at all
  [
    '/etc/wazuh-indexer',
    '/usr/share/wazuh-indexer',
    '/var/lib/wazuh-indexer',
  ].each |String $file| {
    exec { "set ecusive ownership of ${file}":
      path        => '/usr/bin:/bin',
      command     => "chown ${indexer_fileuser}:${indexer_filegroup} -R ${file}",
      refreshonly => true,  # only run when package is installed or updated
      subscribe   => Package['wazuh-indexer'],
      notify      => Service['wazuh-indexer'],
    }
  }

  exec { 'Initialize the Opensearch security index in Wazuh indexer':
    path        => ['/usr/bin', '/bin', '/usr/sbin'],
    command     => '/usr/share/wazuh-indexer/bin/indexer-security-init.sh',
    refreshonly => true,  # only run when package is installed or updated
    subscribe   => Package['wazuh-indexer'],
    require     => Service['wazuh-indexer'],
  }
}
