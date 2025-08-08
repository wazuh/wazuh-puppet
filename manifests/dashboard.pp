# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Dashboard
# @param cert_filebucket_path Prefix for the certificate files, allowing for legacy and new filebucket
# usage.
class wazuh::dashboard (
  $dashboard_package = 'wazuh-dashboard',
  $dashboard_service = 'wazuh-dashboard',
  $dashboard_version = '5.0.0',
  $indexer_server_ip = 'localhost',
  $indexer_server_port = '9200',
  $manager_api_host = '127.0.0.1',
  $dashboard_path_certs = '/etc/wazuh-dashboard/certs',
  $dashboard_fileuser = 'wazuh-dashboard',
  $dashboard_filegroup = 'wazuh-dashboard',

  $dashboard_server_port = '443',
  $dashboard_server_host = '0.0.0.0',
  $dashboard_server_hosts = "https://${indexer_server_ip}:${indexer_server_port}",

  # If the keystore is used, the credentials are not managed by the module (TODO).
  # If use_keystore is false, the keystore is deleted, the dashboard use the credentials in the configuration file.
  $use_keystore = true,
  $dashboard_user = 'kibanaserver',
  $dashboard_password = 'kibanaserver',

  $dashboard_wazuh_api_credentials = [
    {
      'id'       => 'default',
      'url'      => "https://${manager_api_host}",
      'port'     => '55000',
      'user'     => 'wazuh-wui',
      'password' => 'wazuh-wui',
    },
  ],
  String $cert_source_basepath = 'puppet:///modules/archive',
  Variant[Hash, Array] $certfiles = [
    'dashboard.pem',
    'dashboard-key.pem',
    'root-ca.pem',
  ],
  Boolean $generate_certs = false,
  Array[String] $certs_to_generate = ['dashboard'],

) {
  # assign version according to the package manager
  case $facts['os']['family'] {
    'Debian': {
      $dashboard_version_install = "${dashboard_version}-*"
    }
    'Linux', 'RedHat', default: {
      $dashboard_version_install = $dashboard_version
    }
  }

  # install package
  package { 'wazuh-dashboard':
    ensure => $dashboard_version_install,
    name   => $dashboard_package,
  }

  exec { "ensure full path of ${dashboard_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${dashboard_path_certs}",
    creates => $dashboard_path_certs,
    require => Package['wazuh-dashboard'],
  }
  -> file { $dashboard_path_certs:
    ensure => directory,
    owner  => $dashboard_fileuser,
    group  => $dashboard_filegroup,
    mode   => '0500',
  }
  if $generate_certs {
    file { "${dashboard_path_certs}/root-ca.pem":
      ensure => file,
      owner  => $dashboard_fileuser,
      group  => $dashboard_filegroup,
      mode   => '0400',
      source => "${settings::ssldir}/certs/ca.pem",
    }
    $certs_to_generate.each |String $cert| {
      $_certname = "wazuh_${cert}_cert_${facts['networking']['fqdn']}"
      @@wazuh::certificate { $_certname:
        ensure       => present,
        altnames     => [$facts['networking']['ip']],
        keyusage     => ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment'],
        commonname   => $facts['networking']['fqdn'],
        export_pkcs8 => false,
      }
      $_attrs = {
        ensure  => file,
        owner   => $dashboard_fileuser,
        group   => $dashboard_filegroup,
        mode    => '0400',
        replace => true,
        before  => Service['wazuh-dashboard'],
      }
      file {
        "${dashboard_path_certs}/${cert}.pem":
          source => "${cert_source_basepath}/${_certname}.crt",
          *      => $_attrs;

        "${dashboard_path_certs}/${cert}-key.pem":
          source => "${cert_source_basepath}/${_certname}.key",
          *      => $_attrs;
      }
    }
  } else {
    if $certfiles =~ Hash {
      $_certfiles = $certfiles
    } else {
      $_certfiles = $certfiles.map |String $certfile| { [$certfile, $certfile] }.convert_to(Hash)
    }
    $_certfiles.each |String $certfile_source, String $certfile_target| {
      file { "${dashboard_path_certs}/${certfile_target}":
        ensure  => file,
        owner   => $dashboard_fileuser,
        group   => $dashboard_filegroup,
        mode    => '0400',
        replace => true,
        source  => "${cert_source_basepath}/${certfile_source}",
        notify  => Service['wazuh-dashboard'],
      }
    }
  }
  file { '/etc/wazuh-dashboard/opensearch_dashboards.yml':
    content => template('wazuh/wazuh_dashboard_yml.erb'),
    group   => $dashboard_filegroup,
    mode    => '0640',
    owner   => $dashboard_fileuser,
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }

  file { ['/usr/share/wazuh-dashboard/data/wazuh/', '/usr/share/wazuh-dashboard/data/wazuh/config']:
    ensure  => 'directory',
    group   => $dashboard_filegroup,
    mode    => '0755',
    owner   => $dashboard_fileuser,
    require => Package['wazuh-dashboard'],
  }
  -> file { '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml':
    content => template('wazuh/wazuh_yml.erb'),
    group   => $dashboard_filegroup,
    mode    => '0600',
    owner   => $dashboard_fileuser,
    notify  => Service['wazuh-dashboard'],
  }

  unless $use_keystore {
    file { '/etc/wazuh-dashboard/opensearch_dashboards.keystore':
      ensure  => absent,
      require => Package['wazuh-dashboard'],
      before  => Service['wazuh-dashboard'],
    }
  }

  service { 'wazuh-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    name       => $dashboard_service,
  }
}
