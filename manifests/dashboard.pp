# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Dashboard
class wazuh::dashboard (
  $dashboard_package = 'wazuh-dashboard',
  $dashboard_service = 'wazuh-dashboard',
  $dashboard_version = '4.3.4',
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
  ]
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

  service { 'wazuh-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    name       => $dashboard_service,
  }

  exec { 'Waiting for Wazuh indexer...':
    path      => '/usr/bin',
    command   => "curl -u ${dashboard_user}:${dashboard_password} -k -s -XGET https://${indexer_server_ip}:${indexer_server_port}",
    tries     => 100,
    try_sleep => 3,
  }
}
