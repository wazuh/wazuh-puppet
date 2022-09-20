# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Indexer
class wazuh::indexer (
  # opensearch.yml configuration

  $indexer_cluster_name = 'wazuh-cluster',
  $indexer_node_name = 'node-1',
  $indexer_node_max_local_storage_nodes = '1',
  $indexer_service = 'wazuh-indexer',
  $indexer_package = 'wazuh-indexer',
  $indexer_version = '4.4.0-1',

  $indexer_path_data = '/var/lib/wazuh-indexer',
  $indexer_path_logs = '/var/log/wazuh-indexer',
  $indexer_path_certs = '/etc/wazuh-indexer/certs',
  $network_host = '0.0.0.0',

){


  class { 'wazuh::repo':}
  if $::osfamily == 'Debian' {
    Class['wazuh::repo'] -> Class['apt::update'] -> Package['wazuh-indexer']
  } else {
    Class['wazuh::repo'] -> Package['wazuh-indexer']
  }


  # install package
  package { 'wazuh-indexer':
    ensure => $indexer_version,
    name   => $indexer_package,
  }

  include wazuh::certificates

  exec { 'Copy Indexer Certificates':
    path    => '/usr/bin:/bin',
    command => "mkdir $indexer_path_certs \
             && cp /tmp/wazuh-certificates/indexer.pem  $indexer_path_certs\
             && cp /tmp/wazuh-certificates/indexer-key.pem  $indexer_path_certs\
             && cp /tmp/wazuh-certificates/root-ca.pem  $indexer_path_certs\
             && cp /tmp/wazuh-certificates/admin.pem  $indexer_path_certs\
             && cp /tmp/wazuh-certificates/admin-key.pem  $indexer_path_certs\
             && chown wazuh-indexer:wazuh-indexer -R $indexer_path_certs\
             && chmod 500 $indexer_path_certs\
             && chmod 400 $indexer_path_certs/*",
    require => Package[$indexer_package],

  }

  file_line { 'Setting cluster name for wazuh-indexer':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    line    => "cluster.name: ${indexer_cluster_name}",
    match   => "^cluster.name:\s",
    require => Package[$indexer_package],
    notify  => Service[$indexer_service],
  }
  file_line { 'Setting node name for wazuh-indexer':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    line    => "node.name: ${indexer_node_name}",
    match   => "^node.name:\s",
    require => Package[$indexer_package],
    notify  => Service[$indexer_service],
  }
  file_line { 'Setting node master for wazuh-indexer':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    line    => "- "${indexer_node_master}"",
    match   => "^- "node-1"\s",
    require => Package[$indexer_package],
    notify  => Service[$indexer_service],
  }
  file_line { 'Setting node max local storage node for wazuh-indexer':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    line    => "node.max_local_storage_nodes: ${indexer_node_max_local_storage_nodes}",
    match   => "^node.max_local_storage_nodes:\s",
    require => Package[$indexer_package],
    notify  => Service[$indexer_service],
  }
  file_line { 'Setting path data for wazuh-indexer':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    line    => "path.data: ${indexer_path_data}",
    match   => "^path.data:\s",
    require => Package[$indexer_package],
    notify  => Service[$indexer_service],
  }
  file_line { 'Setting path logs for wazuh-indexer':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    line    => "path.logs: ${indexer_path_logs}",
    match   => "^path.logs:\s",
    require => Package[$indexer_package],
    notify  => Service[$indexer_service],
  }
  file_line { 'Setting network host for wazuh-indexer':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    line    => "network.host: ${network_host}",
    match   => "^network.host:\s",
    require => Package[$indexer_package],
    notify  => Service[$indexer_service],
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
