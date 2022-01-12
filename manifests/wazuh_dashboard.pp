# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for wazuh_dashboard
class wazuh::wazuh_dashboard (
  $wazuh_dashboard_package = 'wazuh-dashboard',
  $wazuh_dashboard_service = 'wazuh-dashboard',
  $wazuh_dashboard_version = '1.13.2',
  $wazuh_dashboard_elastic_user = 'admin',
  $wazuh_dashboard_elastic_password = 'admin',
  $wazuh_dashboard_app_version = '4.3.0_7.10.2',
  $wazuh_dashboard_elasticsearch_ip = 'localhost',
  $wazuh_dashboard_elasticsearch_port = '9200',

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
  package { 'Installing OD Kibana...':
    ensure => $wazuh_dashboard_version,
    name   => $wazuh_dashboard_package,
  }

  file { 'Configure opensearch_dashboards.ym':
    owner   => 'kibana',
    path    => '/etc/wazuh-dashboard/opensearch_dashboards.ym',
    group   => 'kibana',
    mode    => '0644',
    notify  => Service[$wazuh_dashboard_service],
    content => template('wazuh/wazuh_dashboard_yml.erb'),
  }

  service { 'kibana':
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  exec {'Waiting for opendistro elasticsearch...':
    path      => '/usr/bin',
    command   => "curl -u ${wazuh_dashboard_elastic_user}:${wazuh_dashboard_elastic_password} -k -s -XGET https://${wazuh_dashboard_elasticsearch_ip}:${wazuh_dashboard_elasticsearch_port}",
    tries     => 100,
    try_sleep => 3,
  }

  file {'Removing old Wazuh Kibana Plugin...':
    ensure  => absent,
    path    => '/usr/share/wazuh-dashboard/plugins/wazuh',
    recurse => true,
    purge   => true,
    force   => true,
    notify  => Service[$wazuh_dashboard_service]
  }

  exec {'Installing Wazuh App...':
    path    => '/usr/bin',
    command => "curl -u ${wazuh_dashboard_elastic_user}:${wazuh_dashboard_elastic_password} -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-${wazuh_dashboard_app_version}.zip",
    creates => '/usr/share/kibana/plugins/wazuh/package.json',
    notify  => Service[$wazuh_dashboard_service],
  }

  exec {'Removing .wazuh index...':
    path    => '/usr/bin',
    command => "curl -u ${wazuh_dashboard_elastic_user}:${wazuh_dashboard_elastic_password} -k -s -XDELETE -sL -I 'https://${wazuh_dashboard_elasticsearch_ip}:${wazuh_dashboard_elasticsearch_port}/.wazuh' -o /dev/null",
    notify  => Service[$wazuh_dashboard_service],
  }

  file { '/usr/share/kibana/plugins/wazuh/wazuh.yml':
    owner   => 'kibana',
    group   => 'kibana',
    mode    => '0644',
    content => template('wazuh/wazuh_yml.erb'),
    notify  => Service[$wazuh_dashboard_service]
  }
  exec { 'Verify Kibana folders owner':
    path    => '/usr/bin:/bin',
    command => "chown -R kibana:kibana /usr/share/wazuh-dashboard/plugins",

  }

}
