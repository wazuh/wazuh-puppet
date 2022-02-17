# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for wazuh_dashboard
class wazuh::wazuh_dashboard (
  $wazuh_dashboard_package = 'wazuh-dashboard',
  $wazuh_dashboard_service = 'wazuh-dashboard',
  $wazuh_dashboard_version = '4.3.0-1',
  $wazuh_dashboard_elastic_user = 'admin',
  $wazuh_dashboard_elastic_password = 'admin',
  $wazuh_dashboard_app_version = '4.3.0-1',
  $wazuh_dashboard_elasticsearch_ip = 'localhost',
  $wazuh_dashboard_elasticsearch_port = '9700',

  $wazuh_dashboard_server_port = '5601',
  $wazuh_dashboard_server_host = '0.0.0.0',
  $wazuh_dashboard_elasticsearch_server_hosts ="https://${wazuh_dashboard_elasticsearch_ip}:${wazuh_dashboard_elasticsearch_port}",
  $wazuh_dashboard_wazuh_api_credentials = [ {
                                      'id'       => 'default',
                                      'url'      => 'http://localhost',
                                      'port'     => '55000',
                                      'user'     => 'foo',
                                      'password' => 'bar',
                                    },
                                  ]
) {

  # install package
  package { 'Installing Wazuh-dashboard...':
    ensure => $wazuh_dashboard_version,
    name   => $wazuh_dashboard_package,
  }

  service { 'wazuh-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  exec {'Waiting for Wazuh indexer...':
    path      => '/usr/bin',
    command   => "curl -u ${wazuh_dashboard_elastic_user}:${wazuh_dashboard_elastic_password} -k -s -XGET https://${wazuh_dashboard_elasticsearch_ip}:${wazuh_dashboard_elasticsearch_port}",
    tries     => 100,
    try_sleep => 3,
  }

}
