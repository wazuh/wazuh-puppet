# Copyright (C) 2015, Wazuh Inc.
# @summary Setup for Wazuh Indexer
# @param indexer_hostname_validation
#   Whether OpenSearch requires the host to match the certificate CN
# @param cert_source_basepath
#   Prefix for the certificate file source, allowing for legacy and new filebucket workflows.
# @param generate_certs
#   Whether to generate certificates with the exported resources + Puppet CA workflow in `wazuh::certificates`
#   They will be generated using the node FQDN as the common name and IP as the alternative name.
# @param certs_to_generate
#   Array of certificate names to generate when `generate_certs` is true. On a single-node setup, this should be `['indexer', 'admin']`.
# @param admin_cn
#   The common name for the admin certificate, defaults to the indexer node name.
class wazuh::indexer (
  # opensearch.yml configuration
  $indexer_network_host = '0.0.0.0',
  $indexer_cluster_name = 'wazuh-cluster',
  $indexer_node_name = $facts['networking']['fqdn'],
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

  $indexer_discovery_hosts = [], # Empty array for single-node configuration
  $indexer_initial_cluster_manager_nodes = [$indexer_node_name],
  $indexer_cluster_cn = ["indexer-${indexer_node_name}"],
  Boolean $indexer_hostname_validation = false,
  String $cert_source_basepath = 'puppet:///modules/archive',
  Variant[Hash, Array] $certfiles = {
    "indexer-${indexer_node_name}.pem" => 'indexer.pem',
    "indexer-${indexer_node_name}-key.pem" => 'indexer-key.pem',
    'root-ca.pem' => 'root-ca.pem',
    'admin.pem' => 'admin.pem',
    'admin-key.pem' => 'admin-key.pem',
  },
  Boolean $generate_certs = false,
  Array[Pattern[/(?:indexer(.*)|admin)/]] $certs_to_generate = ['indexer', 'admin'],
  String $admin_cn = 'admin',

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

  if $generate_certs {
    # If we're generating certs, the CN will always be the node name (which should be FQDN)
    $_indexer_cluster_cn = [$indexer_node_name]
    if $admin_cn == 'admin' {
      # Presumably we're a single-node setup, so use the indexer node name as the admin CN
      $_admin_cn = $indexer_node_name
    } else {
      # We might be a multi-node setup, so use the provided admin CN
      $_admin_cn = $admin_cn
    }
    file { "${indexer_path_certs}/root-ca.pem":
      ensure => file,
      owner  => $indexer_fileuser,
      group  => $indexer_filegroup,
      mode   => '0400',
      source => "${settings::ssldir}/certs/ca.pem",
    }
    $certs_to_generate.each |String $cert| {
      $_certname = "wazuh_${cert}_cert_${facts['networking']['fqdn']}"
      @@wazuh::certificates::certificate { $_certname:
        ensure       => present,
        altnames     => [$facts['networking']['ip']],
        keyusage     => ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment'],
        commonname   => $facts['networking']['fqdn'],
        export_pkcs8 => true,
      }
      $_attrs = {
        ensure  => file,
        owner   => $indexer_fileuser,
        group   => $indexer_filegroup,
        mode    => '0400',
        replace => true,
        before  => Service['wazuh-indexer'],
      }
      file {
        "${indexer_path_certs}/${cert}.pem":
          source => "${cert_source_basepath}/${_certname}.crt",
          *      => $_attrs;

        "${indexer_path_certs}/${cert}-key.pem":
          source => "${cert_source_basepath}/${_certname}.key.pk8",
          *      => $_attrs;
      }
    }
  } else {
    # Old certificate workflow, with support for arbitrary source path
    $_indexer_cluster_cn = $indexer_cluster_cn
    $_admin_cn = $admin_cn
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
