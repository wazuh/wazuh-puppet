# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for Wazuh Dashboard
class wazuh::dashboard (
  $dashboard_package = 'wazuh-dashboard',
  $dashboard_service = 'wazuh-dashboard',
  $dashboard_version = '4.3.0-1',
  $dashboard_user = 'admin',
  $dashboard_password = 'admin',
  $dashboard_app_version = '4.3.0-1',
  $dashboard_ip = 'localhost',
  $dashboard_port = '9200',

  $dashboard_server_port = '5601',
  $dashboard_server_host = '0.0.0.0',
  $dashboard_server_hosts ="https://${dashboard_ip}:$dashboard_port}",
  $dashboard_wazuh_api_credentials = [ {
                                      'id'       => 'default',
                                      'url'      => 'http://localhost',
                                      'port'     => '55000',
                                      'user'     => 'foo',
                                      'password' => 'bar',
                                    },
                                  ]
) {

  # install package
  package { 'Installing Wazuh Dashboard...':
    ensure => $dashboard_version,
    name   => $dashboard_package,
  }

  service { 'wazuh-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  exec {'Waiting for Wazuh indexer...':
    path      => '/usr/bin',
    command   => "curl -u ${dashboard_user}:${dashboard_password} -k -s -XGET https://${dashboard_ip}:${dashboard_port}",
    tries     => 100,
    try_sleep => 3,
  }

}
