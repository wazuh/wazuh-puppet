# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Dashboard
class wazuh::dashboard (
  $dashboard_package = 'wazuh-dashboard',
  $dashboard_service = 'wazuh-dashboard',
  $dashboard_version = '4.4.0',
  $indexer_server_ip = 'localhost',
  $indexer_server_port = '9200',
  $dashboard_path_certs = '/etc/wazuh-dashboard/certs',

  $dashboard_server_port = '443',
  $dashboard_server_host = '0.0.0.0',
  $indexer_server_host = "https://${indexer_server_ip}:$indexer_server_port}",
  $dashboard_wazuh_api_credentials_url = "http://localhost",
  $dashboard_wazuh_api_credentials_port = "55000",
  $dashboard_wazuh_api_credentials_user = "wazuh-wui",
  $dashboard_wazuh_api_credentials_password = "wazuh-wui",
) {

  # assign version according to the package manager
  case $::osfamily {
    'Debian' : {
      $dashboard_version_install = "${dashboard_version}-*"
    }
    'Linux', 'RedHat' : {
      $dashboard_version_install = "${dashboard_version}"
    }
  }

  # install package
  package { 'Installing Wazuh Dashboard...':
    ensure => $dashboard_version_install,
    name   => $dashboard_package,
  }

  include wazuh::certificates

  exec { 'Copy Dashboard Certificates':
    path    => '/usr/bin:/bin',
    command => "mkdir $dashboard_path_certs \
             && cp /tmp/wazuh-certificates/dashboard.pem  $dashboard_path_certs\
             && cp /tmp/wazuh-certificates/dashboard-key.pem  $dashboard_path_certs\
             && cp /tmp/wazuh-certificates/root-ca.pem  $dashboard_path_certs\
             && chown wazuh-dashboard:wazuh-dashboard -R $dashboard_path_certs\
             && chmod 500 $dashboard_path_certs\
             && chmod 400 $dashboard_path_certs/*",

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
  file_line { 'Setting Wazuh indexer host for wazuh-dashboard':
    path    => '/etc/wazuh-dashboard/opensearch_dashboards.yml',
    line    => "opensearch.hosts: ${indexer_server_host}",
    match   => "^opensearch.hosts:\s",
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }
  file_line { 'Setting Wazuh api url for wazuh-dashboard':
    path    => '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml',
    line    => "url: ${dashboard_wazuh_api_credentials_url}",
    match   => "^url:\s",
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }
  file_line { 'Setting Wazuh api port for wazuh-dashboard':
    path    => '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml',
    line    => "port: ${dashboard_wazuh_api_credentials_port}",
    match   => "^port:\s",
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }
  file_line { 'Setting Wazuh api username for wazuh-dashboard':
    path    => '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml',
    line    => "username: ${dashboard_wazuh_api_credentials_username}",
    match   => "^username:\s",
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }
  file_line { 'Setting Wazuh api password for wazuh-dashboard':
    path    => '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml',
    line    => "password: ${dashboard_wazuh_api_credentials_password}",
    match   => "^password:\s",
    require => Package['wazuh-dashboard'],
    notify  => Service['wazuh-dashboard'],
  }

  service { 'wazuh-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  exec {'Waiting for Wazuh indexer...':
    path      => '/usr/bin',
    command   => "curl -u ${dashboard_user}:${dashboard_password} -k -s -XGET https://${indexer_server_ip}:${indexer_server_port}",
    tries     => 100,
    try_sleep => 3,
  }

}
