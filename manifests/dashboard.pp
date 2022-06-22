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

  $dashboard_server_port = '5601',
  $dashboard_server_host = '0.0.0.0',
  $dashboard_server_hosts ="https://${indexer_server_ip}:${indexer_server_port}",
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
  package { 'Installing Wazuh Dashboard...':
    ensure => $dashboard_version_install,
    name   => $dashboard_package,
  }

  include wazuh::certificates

  exec { 'Copy Dashboard Certificates':
    path    => '/usr/bin:/bin',
    command => "mkdir ${dashboard_path_certs} \
             && cp /tmp/wazuh-certificates/dashboard.pem  ${dashboard_path_certs}\
             && cp /tmp/wazuh-certificates/dashboard-key.pem  ${dashboard_path_certs}\
             && cp /tmp/wazuh-certificates/root-ca.pem  ${dashboard_path_certs}\
             && chown wazuh-dashboard:wazuh-dashboard -R ${dashboard_path_certs}\
             && chmod 500 ${dashboard_path_certs}\
             && chmod 400 ${dashboard_path_certs}/*",
  }

  service { 'wazuh-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  exec { 'Waiting for Wazuh indexer...':
    path      => '/usr/bin',
    command   => "curl -u ${dashboard_user}:${dashboard_password} -k -s -XGET https://${indexer_server_ip}:${indexer_server_port}",
    tries     => 100,
    try_sleep => 3,
  }
}
