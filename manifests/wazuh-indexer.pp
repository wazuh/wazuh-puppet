# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for wazuh-indexer
class wazuh::wazuh-indexer (
  # Elasticsearch.yml configuration

  $wazuh-indexer_cluster_name = 'es-wazuh',
  $wazuh-indexer_node_name = 'node-01',
  $wazuh-indexer_node_master = true,
  $wazuh-indexer_node_data = true,
  $wazuh-indexer_node_ingest = true,
  $wazuh-indexer_node_max_local_storage_nodes = '1',
  $wazuh-indexer_service = 'elasticsearch',
  $wazuh-indexer_package = 'wazuh-indexer',
  $wazuh-indexer_version = '1.13.2',

  $wazuh-indexer_path_data = '/var/lib/elasticsearch',
  $wazuh-indexer_path_logs = '/var/log/elasticsearch',


  $wazuh-indexer_ip = 'localhost',
  $wazuh-indexer_port = '9200',
  $wazuh-indexer_discovery_option = 'discovery.type: single-node',
  $wazuh-indexer_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['node-01']",

# JVM options
  $jvm_options_memmory = '1g',

){

  class {'wazuh::repo_wazuh-indexer':}


  if $::osfamily == 'Debian' {
    Class['wazuh::repo_wazuh-indexer'] -> Class['apt::update'] -> Package['wazuh-indexer']
  } else {
    Class['wazuh::repo_wazuh-indexer'] -> Package['wazuh-indexer']
  }

  # install package
  package { 'wazuh-indexer':
    ensure => $wazuh-indexer_version,
    name   => $wazuh-indexer_package,
  }

  file { 'Configure elasticsearch.yml':
    owner   => 'elasticsearch',
    path    => '/etc/elasticsearch/elasticsearch.yml',
    group   => 'elasticsearch',
    mode    => '0644',
    notify  => Service[$wazuh-indexer_service], ## Restarts the service
    content => template('wazuh/opendistro_yml.erb'),
    require => Package[$wazuh-indexer_package],
  }

  file { 'Configure disabledlog4j.options':
    owner   => 'root',
    path    => '/etc/elasticsearch/jvm.options.d/disabledlog4j.options',
    group   => 'elasticsearch',
    mode    => '2750',
    notify  => Service[$wazuh-indexer_service], ## Restarts the service
    content => template('wazuh/disabledlog4j_options.erb'),
    require => Package[$wazuh-indexer_package],
  }

  file { 'Configure jvm.options':
    owner   => 'elasticsearch',
    path    => '/etc/elasticsearch/jvm.options',
    group   => 'elasticsearch',
    mode    => '0660',
    notify  => Service[$wazuh-indexer_service], ## Restarts the service
    content => template('wazuh/jvm_options.erb'),
    require => Package[$wazuh-indexer_package],
  }

  service { 'elasticsearch':
    ensure  => running,
    enable  => true,
    require => Package[$wazuh-indexer_package],
  }

  exec { 'Insert line limits':
    path    => '/usr/bin:/bin/',
    command => "echo 'elasticsearch - nofile  65535\nelasticsearch - memlock unlimited' >> /etc/security/limits.conf",
    require => Package[$wazuh-indexer_package],

  }

  exec { 'Verify Elasticsearch folders owner':
    path    => '/usr/bin:/bin',
    command => "chown elasticsearch:elasticsearch -R /etc/elasticsearch\
             && chown elasticsearch:elasticsearch -R /usr/share/elasticsearch\
             && chown elasticsearch:elasticsearch -R /var/lib/elasticsearch",
    require => Package[$wazuh-indexer_package],

  }


}
