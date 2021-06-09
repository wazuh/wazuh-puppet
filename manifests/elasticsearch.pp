# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
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
  $elasticsearch_version = '7.10.0',

  # user/group elasticsearch processes run as
  $elasticsearch_user = 'elasticsearch',
  $elasticsearch_group = 'elasticsearch',

  $elasticsearch_ip = 'localhost',
  $elasticsearch_port = '9200',
  $elasticsearch_discovery_option = 'discovery.type: single-node',
  $elasticsearch_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['es-node-01']",

  # elasticsearch paths
  $elasticsearch_path_config = '/etc/elasticsearch',
  $elasticsearch_path_eshome = '/usr/share/elasticsearch',
  $elasticsearch_path_data = '/var/lib/elasticsearch',
  $elasticsearch_path_logs = '/var/log/elasticsearch',

  $elasticsearch_limits_file = '/etc/security/limits.conf',

  # JVM options
  $jvm_options_memmory = '1g',

){

  # install package
  package { 'elasticsearch':
    ensure => $elasticsearch_version,
    name   => $elasticsearch_package,
  }

  file { 'Configure elasticsearch.yml':
    owner   => 'elasticsearch',
    path    => "${$elasticsearch_path_config}/elasticsearch.yml",
    group   => 'elasticsearch',
    mode    => '0644',
    notify  => Service[$elasticsearch_service], ## Restarts the service
    content => template('wazuh/elasticsearch_yml.erb'),
    require => Package[$elasticsearch_package],
  }

  file { 'Configure jvm.options':
    owner   => 'elasticsearch',
    path    => "${$elasticsearch_path_config}/jvm.options",
    group   => 'elasticsearch',
    mode    => '0660',
    notify  => Service[$elasticsearch_service], ## Restarts the service
    content => template('wazuh/jvm_options.erb'),
    require => Package[$elasticsearch_package],
  }

  file { 'Ensure limits file exists':
    ensure => present,
    path   => $elasticsearch_limits_file,
  }

  file_line { 'Ensure nofile limits':
    path    => $elasticsearch_limits_file,
    line    => 'elasticsearch - nofile  65535',
    require => Package[$elasticsearch_package],
  }

  file_line { 'Ensure memlock limits':
    path    => $elasticsearch_limits_file,
    line    => 'elasticsearch - memlock unlimited',
    require => Package[$elasticsearch_package],
  }

  file { [$elasticsearch_path_config, $elasticsearch_path_eshome, $elasticsearch_path_data]:
  recurse => true,
  owner   => $elasticsearch_user,
  group   => $elasticsearch_group,
  require => Package[$elasticsearch_package],
  }

  service { 'elasticsearch':
    ensure  => running,
    enable  => true,
    require => Package[$elasticsearch_package],
  }

}
