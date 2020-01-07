# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Setup for Kibana
class wazuh::kibana (
  $kibana_package = 'kibana',
  $kibana_service = 'kibana',
  $kibana_version = '7.5.1',
  $kibana_app_version = '3.11.0_7.5.1',

  $kibana_elasticsearch_ip = 'localhost',
  $kibana_elasticsearch_port = '9200',

  $kibana_server_port = '5601',
  $kibana_server_host = '0.0.0.0',
  $kibana_elasticsearch_server_hosts ="http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",
  $kibana_wazuh_api_credentials = [ {
                                      'id'       => 'default',
                                      'url'      => 'http://localhost',
                                      'port'     => '55000',
                                      'user'     => 'foo',
                                      'password' => 'bar',
                                    },
                                  ]
) {

  # install package
  package { 'Installing Kibana...':
    ensure => $kibana_version,
    name   => $kibana_package,
  }

  file { 'Configure kibana.yml':
    owner   => 'kibana',
    path    => '/etc/kibana/kibana.yml',
    group   => 'kibana',
    mode    => '0644',
    notify  => Service[$kibana_service],
    content => template('wazuh/kibana_yml.erb'),
  }

  service { 'kibana':
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  exec {'Waiting for elasticsearch...':
    path      => '/usr/bin',
    command   => "curl -s -XGET http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",
    tries     => 100,
    try_sleep => 3,
  }

  file {'Removing old Wazuh Kibana Plugin...':
    ensure  => absent,
    path    => '/usr/share/kibana/plugins/wazuh',
    recurse => true,
    purge   => true,
    force   => true,
    notify  => Service[$kibana_service]
  }

  exec {'Installing Wazuh App...':
    path    => '/usr/bin',
    command => "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-${kibana_app_version}.zip",
    creates => '/usr/share/kibana/plugins/wazuh/package.json',
    notify  => Service[$kibana_service],
  }

  exec {'Removing .wazuh index...':
    path    => '/usr/bin',
    command => "curl -s -XDELETE -sL -I 'http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}/.wazuh' -o /dev/null",
    notify  => Service[$kibana_service],
  }

  file { '/usr/share/kibana/plugins/wazuh/wazuh.yml':
        owner   => 'kibana',
        group   => 'kibana',
        mode    => '0644',
        content => template('wazuh/wazuh_yml.erb'),
        notify  => Service[$kibana_service]
  }
  exec { 'Verify Kibana folders owner':
    path    => '/usr/bin:/bin',
    command => "chown -R kibana:kibana /usr/share/kibana/optimize\
             && chown -R kibana:kibana /usr/share/kibana/plugins",

  }

}
