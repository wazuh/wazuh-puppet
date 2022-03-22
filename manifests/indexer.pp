# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
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
  $indexer_version = '4.3.0-1',

  $indexer_path_data = '/var/lib/wazuh-indexer',
  $indexer_path_logs = '/var/log/wazuh-indexer',


  $indexer_ip = 'localhost',
  $indexer_port = '9200',
  $indexer_discovery_option = 'discovery.type: single-node',
  $indexer_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['node-1']",

  $manage_repos = false, # Change to true when manager is not present.

# JVM options
  $jvm_options_memmory = '1g',

){


  if $manage_repos {
    class { 'wazuh::repo':}
    if $::osfamily == 'Debian' {
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

  service { 'wazuh-indexer':
    ensure  => running,
    enable  => true,
    require => Package[$indexer_package],
  }

  exec { 'Insert line limits':
    path    => '/usr/bin:/bin/',
    command => "echo 'elasticsearch - nofile  65535\nelasticsearch - memlock unlimited' >> /etc/security/limits.conf",
    require => Package[$indexer_package],

  }

  exec { 'Verify wazuh-indexer folders owner':
    path    => '/usr/bin:/bin',
    command => "chown wazuh-indexer:wazuh-indexer -R /etc/wazuh-indexer\
             && chown wazuh-indexer:wazuh-indexer -R /usr/share/wazuh-indexer\
             && chown wazuh-indexer:wazuh-indexer -R /var/lib/wazuh-indexer",
    require => Package[$indexer_package],

  }

  exec { 'Launch security admin initializer':
    path    => ['/usr/bin', '/bin', '/usr/sbin'],
    command => '/usr/share/wazuh-indexer/bin/indexer-security-init.sh',
    require => Package[$indexer_package],

  }

}
