# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Dashboard
class wazuh::dashboard (
  $dashboard_package = 'wazuh-dashboard',
  $dashboard_service = 'wazuh-dashboard',
  $dashboard_version = '4.3.7',
  $dashboard_user = 'admin',
  $dashboard_password = 'admin',
  $indexer_server_ip = 'localhost',
  $indexer_server_port = '9200',
  $dashboard_path_certs = '/etc/wazuh-dashboard/certs',
  $dashboard_fileuser = 'wazuh-dashboard',
  $dashboard_filegroup = 'wazuh-dashboard',

  $dashboard_server_port = '5601',
  $dashboard_server_host = '0.0.0.0',
  $dashboard_server_hosts = "https://${indexer_server_ip}:${indexer_server_port}",
  $dashboard_wazuh_api_credentials = [
    {
      'id'       => 'default',
      'url'      => 'http://localhost',
      'port'     => '55000',
      'user'     => 'foo',
      'password' => 'bar',
    },
  ],

  $manage_repos = false, # Change to true when manager is not present.
) {
  if $manage_repos {
    include wazuh::repo

    if $facts['os']['family'] == 'Debian' {
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

  # TODO: Fully manage the opensearch_dashboards.yml and a template file resource
  file_line { 'Setting host for wazuh-dashboard':
    path    => '/etc/wazuh-dashboard/opensearch_dashboards.yml',
    line    => "server.host: ${dashboard_server_host}",
    match   => "^server.host:\s",
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }
  file_line { 'Setting port for wazuh-dashboard':
    path    => '/etc/wazuh-dashboard/opensearch_dashboards.yml',
    line    => "server.port: ${dashboard_server_port}",
    match   => "^server.port:\s",
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }

  service { 'wazuh-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    name       => $dashboard_service,
  }
}
