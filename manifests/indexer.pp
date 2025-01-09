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
  $indexer_version = '4.9.2',
  $indexer_fileuser = 'wazuh-indexer',
  $indexer_filegroup = 'wazuh-indexer',

  $indexer_path_data = '/var/lib/wazuh-indexer',
  $indexer_path_logs = '/var/log/wazuh-indexer',
  $indexer_path_certs = '/etc/wazuh-indexer/certs',
  $indexer_security_init_lockfile = '/var/tmp/indexer-security-init.lock',
  $full_indexer_reinstall = false, # Change to true when whant a full reinstall of Wazuh indexer

  $indexer_ip = 'localhost',
  $indexer_port = '9200',
  $indexer_discovery_hosts = [], # Empty array for single-node configuration
  $indexer_cluster_initial_master_nodes = ['node-1'],
  $indexer_cluster_CN = ['node-1'],

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

  class { 'wazuh::install_product':
    package_name  => $indexer_package,
    wazuh_version => $indexer_version_install,
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

  [
   "indexer-$indexer_node_name.pem",
   "indexer-$indexer_node_name-key.pem",
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
    }
  }



  class { 'wazuh::modify_config_file':
    file_path => '/etc/wazuh-indexer/opensearch.yml',
    array     => ['network.host: $$indexer_network_host',
      'node.name: $indexer_node_name',
      'path.data: $indexer_path_data',
      'path.logs: $indexer_path_logs',
      'discovery.type: single-node',
      'http.port: 9200-9299',
      'transport.tcp.port: 9300-9399',
      'compatibility.override_main_response_version: true',
      'plugins.security.ssl.http.pemcert_filepath: $indexer_path_certs/wazuh.indexer.pem',
      'plugins.security.ssl.http.pemkey_filepath: $indexer_path_certs/wazuh.indexer.key',
      'plugins.security.ssl.http.pemtrustedcas_filepath: $indexer_path_certs/root-ca.pem',
      'plugins.security.ssl.transport.pemcert_filepath: $indexer_path_certs/wazuh.indexer.pem',
      'plugins.security.ssl.transport.pemkey_filepath: $indexer_path_certs/wazuh.indexer.key',
      'plugins.security.ssl.transport.pemtrustedcas_filepath: $indexer_path_certs/root-ca.pem',
      'plugins.security.ssl.http.enabled: true',
      'plugins.security.ssl.transport.enforce_hostname_verification: false',
      'plugins.security.ssl.transport.resolve_hostname: false',
      'plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"',
      'plugins.security.check_snapshot_restore_write_privileges: true',
      'plugins.security.enable_snapshot_restore_privilege: true',
      'plugins.security.nodes_dn:
      - "CN=wazuh.indexer,OU=Wazuh,O=Wazuh,L=California,C=US"',
      'plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"',
      'plugins.security.system_indices.enabled: true',
      'plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", "."opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opensearch-observability", "."opendistro-asynchronous-search-response*", ".replication-metadata-store"]',
      'plugins.security.allow_default_init_securityindex: true',
      'cluster.routing.allocation.disk.threshold_enabled: false'],
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

  # TODO: this should be done by the package itself and not by puppet at all
  [
    '/etc/wazuh-indexer',
    '/usr/share/wazuh-indexer',
    '/var/lib/wazuh-indexer',
  ].each |String $file| {
    exec { "set recusive ownership of ${file}":
      path        => '/usr/bin:/bin',
      command     => "chown ${indexer_fileuser}:${indexer_filegroup} -R ${file}",
      refreshonly => true,  # only run when package is installed or updated
      subscribe   => Package['wazuh-indexer'],
      notify      => Service['wazuh-indexer'],
    }
  }

  if $full_indexer_reinstall {
    file { $indexer_security_init_lockfile:
      ensure  => absent,
      require => Package['wazuh-indexer'],
      before  => Exec['Initialize the Opensearch security index in Wazuh indexer'],
    }
  }
}
