# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Setup for elasticsearch
class wazuh::elasticsearch (
  # Elasticsearch.yml configuration

  $elasticsearch_cluster_name = 'es-wazuh',
  $elasticsearch_node_name = 'es-node-01',
  $elasticsearch_node_master = true,
  $elasticsearch_node_data = true,
  $elasticsearch_node_ingest = true,
  $elasticsearch_node_max_local_storage_nodes = '1',
  $elasticsearch_service = 'elasticsearch',
  $elasticsearch_package = 'elasticsearch',
  $elasticsearch_version = '7.3.2',

  $elasticsearch_path_data = '/var/lib/elasticsearch',
  $elasticsearch_path_logs = '/var/log/elasticsearch',


  $elasticsearch_ip = '<YOUR_ELASTICSEARCH_IP>',
  $elasticsearch_port = '9200',
  $elasticsearch_discovery_option = 'discovery.type: single-node',
  $elasticsearch_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['es-node-01']",

# JVM options
  $jvm_options_memmory = '1g',

){

  # install package
  package { 'Installing elasticsearch...':
    ensure => $elasticsearch_version,
    name   => $elasticsearch_package,
  }

  file { 'Configure elasticsearch.yml':
    owner   => 'elasticsearch',
    path    => '/etc/elasticsearch/elasticsearch.yml',
    group   => 'elasticsearch',
    mode    => '0644',
    notify  => Service[$elasticsearch_service], ## Restarts the service
    content => template('wazuh/elasticsearch_yml.erb')
  }

  file { 'Configure jvm.options':
    owner   => 'elasticsearch',
    path    => '/etc/elasticsearch/jvm.options',
    group   => 'elasticsearch',
    mode    => '0660',
    notify  => Service[$elasticsearch_service], ## Restarts the service
    content => template('wazuh/jvm_options.erb')
  }

  service { 'elasticsearch':
    ensure => running,
    enable => true,
  }

  exec { 'Insert line limits':
    path    => '/usr/bin:/bin/',
    command => "echo 'elasticsearch - nofile  65535\nelasticsearch - memlock unlimited' >> /etc/security/limits.conf",

  }

  exec { 'Verify Elasticsearch folders owner':
    path    => '/usr/bin:/bin',
    command => "chown elasticsearch:elasticsearch -R /etc/elasticsearch\
             && chown elasticsearch:elasticsearch -R /usr/share/elasticsearch\
             && chown elasticsearch:elasticsearch -R /var/lib/elasticsearch",

  }


}
