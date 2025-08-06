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
  $indexer_version = '5.0.0',
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
  $indexer_initial_cluster_manager_nodes = ['node-1'],
  $indexer_cluster_cn = ['node-1'],
  String $cert_source_basepath = 'puppet:///modules/archive',
  Variant[Hash, Array] $certfiles = [
    "indexer-${indexer_node_name}.pem",
    "indexer-${indexer_node_name}-key.pem",
    'root-ca.pem',
    'admin.pem',
    'admin-key.pem',
  ],
  Boolean $generate_certs = false,
  Array[Pattern[/(?:indexer(.*)|admin)/]] $certs_to_generate = ['indexer', 'admin'],
  Boolean $use_puppet_ca = false,
  Boolean $use_puppet_certs = false,

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

  if $use_puppet_certs or $generate_certs {
    file { "${indexer_path_certs}/root-ca.pem":
      ensure => file,
      owner  => $indexer_fileuser,
      group  => $indexer_filegroup,
      mode   => '0400',
      source => "${settings::ssldir}/certs/ca.pem",
    }
  }
  if $use_puppet_certs {
    file { "${indexer_path_certs}/indexer.pem":
      ensure => file,
      owner  => $indexer_fileuser,
      group  => $indexer_filegroup,
      mode   => '0400',
      source => "${settings::ssldir}/indexer-${facts['networking']['fqdn']}.pem",
    }
  }
  if $generate_certs {
    $certs_to_generate.each |String $cert| {
      $_certname = "wazuh_${cert}_cert_${facts['networking']['fqdn']}"
      @@openssl::certificate::x509 { $_certname:
        ensure      => present,
        altnames    => [$facts['networking']['ip']],
        extkeyusage => ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment'],
        commonname  => $facts['networking']['fqdn'],
      }
      $_attrs = {
        ensure  => file,
        owner   => $indexer_fileuser,
        group   => $indexer_filegroup,
        mode    => '0400',
        replace => true,
      }
      file {
        "${indexer_path_certs}/${cert}.pem":
          source => "${cert_source_basepath}/${_certname}.crt",
          *      => $_attrs;

        "${indexer_path_certs}/${cert}-key.pem":
          source => "${cert_source_basepath}/${_certname}.key",
          *      => $_attrs;
      }
    }
  } else {
    # Old certificate workflow, with support for arbitrary source path
    if $certfiles =~ Hash {
      $_certfiles = $certfiles
    } else {
      $_certfiles = $certfiles.map |String $certfile| { [$certfile, $certfile] }.convert_to(Hash)
    }
    $_certfiles.each |String $certfile_source, String $certfile_target| {
      file { "${indexer_path_certs}/${certfile_target}":
        ensure  => file,
        owner   => $indexer_fileuser,
        group   => $indexer_filegroup,
        mode    => '0400',
        replace => true,
        source  => "${cert_source_basepath}/${certfile_source}",
      }
    }
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
    $_before = defined(Exec['Initialize the Opensearch security index in Wazuh indexer']) ? {
      true    => Exec['Initialize the Opensearch security index in Wazuh indexer'],
      default => undef,
    }
    file { $indexer_security_init_lockfile:
      ensure  => absent,
      require => Package['wazuh-indexer'],
      before  => $_before,
    }
  }
}
