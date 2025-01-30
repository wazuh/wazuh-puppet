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
  wazuh::install_product { 'Wazuh indexer':
    package_name  => $indexer_package,
    wazuh_version => $indexer_version,
  }

  exec { "ensure full path of ${indexer_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${indexer_path_certs}",
    creates => $indexer_path_certs,
    require => Wazuh::Install_product['Wazuh indexer'],
  }
  -> file { $indexer_path_certs:
    ensure  => directory,
    owner   => $indexer_fileuser,
    group   => $indexer_filegroup,
    mode    => '0500',
    require => Wazuh::Install_product['Wazuh indexer'],
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
      require => Wazuh::Install_product['Wazuh indexer'],
    }
  }

  $opensearch_parameters = [
    "network.host: ${indexer_network_host}",
    "node.name: ${indexer_node_name}",
    "plugins.security.ssl.http.pemcert_filepath: ${indexer_path_certs}/indexer-${indexer_node_name}.pem",
    "plugins.security.ssl.http.pemkey_filepath: ${indexer_path_certs}/indexer-${indexer_node_name}-key.pem",
    "plugins.security.ssl.http.pemtrustedcas_filepath: ${indexer_path_certs}/root-ca.pem",
    "plugins.security.ssl.transport.pemcert_filepath: ${indexer_path_certs}/indexer-${indexer_node_name}.pem",
    "plugins.security.ssl.transport.pemkey_filepath: ${indexer_path_certs}/indexer-${indexer_node_name}-key.pem",
    "plugins.security.ssl.transport.pemtrustedcas_filepath: ${indexer_path_certs}/root-ca.pem",
  ]

  $opensearch_parameters.each |$update| {
    $parts = split($update, ': ')
    $key = $parts[0]
    $value = $parts[1]

    augeas { "yaml_config_${key}":
      lens    => 'Yaml.lns',
      incl    => '/etc/wazuh-indexer/opensearch.yml',
      changes => "set ${key} '${value}'",
      onlyif  => "get ${key} != '${value}'",
      require => [
        File['/etc/wazuh-indexer/opensearch.yml'],
        Package['wazuh-indexer']
      ],
      notify  => Service['wazuh-indexer'],
      require => Wazuh::Install_product['Wazuh indexer'],
    }
  }

  file { '/etc/wazuh-indexer/opensearch.yml':
    ensure  => file,
    require => [
      Wazuh::Install_product['Wazuh indexer']
    ],
  }

  file_line { 'Insert line initial size of total heap space':
    path    => '/etc/wazuh-indexer/jvm.options',
    line    => "-Xms${jvm_options_memory}",
    match   => '^-Xms',
    notify  => Service['wazuh-indexer'],
    require => Wazuh::Install_product['Wazuh indexer'],
  }

  file_line { 'Insert line maximum size of total heap space':
    path    => '/etc/wazuh-indexer/jvm.options',
    line    => "-Xmx${jvm_options_memory}",
    match   => '^-Xmx',
    notify  => Service['wazuh-indexer'],
    require => Wazuh::Install_product['Wazuh indexer'],
  }

  service { 'wazuh-indexer':
    ensure  => running,
    enable  => true,
    name    => $indexer_service,
    require => Wazuh::Install_product['Wazuh indexer'],
  }

  file_line { "Insert line limits nofile for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - nofile  65535",
    match  => "^${indexer_fileuser} - nofile\s",
    notify => Service['wazuh-indexer'],
    require => Wazuh::Install_product['Wazuh indexer'],
  }
  file_line { "Insert line limits memlock for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - memlock unlimited",
    match  => "^${indexer_fileuser} - memlock\s",
    notify => Service['wazuh-indexer'],
    require => Wazuh::Install_product['Wazuh indexer'],
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
      notify      => Service['wazuh-indexer'],
      require => Wazuh::Install_product['Wazuh indexer'],
    }
  }

  if $full_indexer_reinstall {
    file { $indexer_security_init_lockfile:
      ensure  => absent,
      before  => Exec['Initialize the Opensearch security index in Wazuh indexer'],
    }
  }
}
