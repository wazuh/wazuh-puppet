# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Dashboard
class wazuh::dashboard (
  $dashboard_package = 'wazuh-dashboard',
  $dashboard_service = 'wazuh-dashboard',
<<<<<<< HEAD
  $dashboard_version = '4.3.10',
=======
  $dashboard_version = '4.4.0',
>>>>>>> d21823b4c950a023d9176bb13dab0c83ec6c1091
  $indexer_server_ip = 'localhost',
  $indexer_server_port = '9200',
  $dashboard_path_certs = '/etc/wazuh-dashboard/certs',
  $dashboard_fileuser = 'wazuh-dashboard',
  $dashboard_filegroup = 'wazuh-dashboard',

  $dashboard_server_port = '443',
  $dashboard_server_host = '0.0.0.0',
<<<<<<< HEAD
  $dashboard_server_hosts = "https://${indexer_server_ip}:${indexer_server_port}",

  # If the keystore is used, the credentials are not managed by the module (TODO).
  # If use_keystore is false, the keystore is deleted, the dashboard use the credentials in the configuration file.
  $use_keystore = true,
  $dashboard_user = 'kibanaserver',
  $dashboard_password = 'kibanaserver',

=======
  $indexer_server_host = "https://${indexer_server_ip}:${indexer_server_port}",
>>>>>>> d21823b4c950a023d9176bb13dab0c83ec6c1091
  $dashboard_wazuh_api_credentials = [
    {
      'id'       => 'default',
      'url'      => 'https://localhost',
      'port'     => '55000',
      'user'     => 'wazuh-wui',
      'password' => 'wazuh-wui',
    },
  ],

  $manage_repos = false, # Change to true when manager is not present.
) {

  if $manage_repos {
    include wazuh::repo

    if $::osfamily == 'Debian' {
      Class['wazuh::repo'] -> Class['apt::update'] -> Package['wazuh-dashboard']
    } else {
      Class['wazuh::repo'] -> Package['wazuh-dashboard']
    }
  }

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

  require wazuh::certificates

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

  [
    'dashboard.pem',
    'dashboard-key.pem',
    'root-ca.pem',
  ].each |String $certfile| {
    file { "${dashboard_path_certs}/${certfile}":
      ensure  => file,
      owner   => $dashboard_fileuser,
      group   => $dashboard_filegroup,
      mode    => '0400',
      replace => false,  # only copy content when file not exist
      source  => "/tmp/wazuh-certificates/${certfile}",
    }
  }

<<<<<<< HEAD
  file { '/etc/wazuh-dashboard/opensearch_dashboards.yml':
    content => template('wazuh/wazuh_dashboard_yml.erb'),
    group   => $dashboard_filegroup,
    mode    => '0640',
    owner   => $dashboard_fileuser,
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }

  file { [ '/usr/share/wazuh-dashboard/data/wazuh/', '/usr/share/wazuh-dashboard/data/wazuh/config' ]:
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
=======
  # TODO: Fully manage the opensearch_dashboards.yml and a template file resource
  file { '/etc/wazuh-dashboard/opensearch_dashboards.yml':
    owner   => 'wazuh-dashboard',
    group   => 'wazuh-dashboard',
    mode    => '0640',
    content => template('wazuh/opensearch_dashboards_yml.erb'),
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard']
>>>>>>> d21823b4c950a023d9176bb13dab0c83ec6c1091
  }

  unless $use_keystore {
    file { '/usr/share/wazuh-dashboard/config/opensearch_dashboards.keystore':
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

  file { ['/usr/share/wazuh-dashboard/data/wazuh/',
  '/usr/share/wazuh-dashboard/data/wazuh/config/']:
    ensure => 'directory',
    owner   => 'wazuh-dashboard',
    group   => 'wazuh-dashboard',
    mode    => '0600',
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }

  file { '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml':
    owner   => 'wazuh-dashboard',
    group   => 'wazuh-dashboard',
    mode    => '0600',
    content => template('wazuh/wazuh_yml.erb'),
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }
}
