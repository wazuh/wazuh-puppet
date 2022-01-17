# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for wazuh-indexer
class wazuh::wazuh_indexer (
  # opensearch.yml configuration

  $wazuh_indexer_cluster_name = 'es-wazuh',
  $wazuh_indexer_node_name = 'node-01',
  $wazuh_indexer_node_master = true,
  $wazuh_indexer_node_data = true,
  $wazuh_indexer_node_ingest = true,
  $wazuh_indexer_node_max_local_storage_nodes = '1',
  $wazuh_indexer_service = 'wazuh-indexer',
  $wazuh_indexer_package = 'wazuh-indexer',
  $wazuh_indexer_version = '4.3.0-0.0.0.todelete',

  $wazuh_indexer_path_data = '/var/lib/wazuh-indexer',
  $wazuh_indexer_path_logs = '/var/log/wazuh-indexer',


  $wazuh_indexer_ip = 'localhost',
  $wazuh_indexer_port = '9700',
  $wazuh_indexer_discovery_option = 'discovery.type: single-node',
  $wazuh_indexer_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['node-01']",

# JVM options
  $jvm_options_memmory = '1g',

){

  class {'wazuh::repo':}


  if $::osfamily == 'Debian' {
    Class['wazuh::repo'] -> Class['apt::update'] -> Package['wazuh-indexer']
  } else {
    Class['wazuh::repo'] -> Package['wazuh-indexer']
  }

  # install package
  package { 'wazuh-indexer':
    ensure => $wazuh_indexer_version,
    name   => $wazuh_indexer_package,
  }

  service { 'wazuh-indexer':
    ensure  => running,
    enable  => true,
    require => Package[$wazuh_indexer_package],
  }

  exec { 'Insert line limits':
    path    => '/usr/bin:/bin/',
    command => "echo 'elasticsearch - nofile  65535\nelasticsearch - memlock unlimited' >> /etc/security/limits.conf",
    require => Package[$wazuh_indexer_package],

  }

  exec { 'Verify wazuh-indexer folders owner':
    path    => '/usr/bin:/bin',
    command => "chown wazuh-indexer:wazuh-indexer -R /etc/wazuh-indexer\
             && chown wazuh-indexer:wazuh-indexer -R /usr/share/wazuh-indexer\
             && chown wazuh-indexer:wazuh-indexer -R /var/lib/wazuh-indexer",
    require => Package[$wazuh_indexer_package],

  }


}
