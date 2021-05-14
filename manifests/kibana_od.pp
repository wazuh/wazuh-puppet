# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for Kibana_od
class wazuh::kibana_od (
  $kibana_od_package = 'opendistroforelasticsearch-kibana',
  $kibana_od_service = 'kibana',
  $kibana_od_version = '1.12.0',
  $kibana_od_elastic_user = 'admin',
  $kibana_od_elastic_password = 'admin',
  $kibana_od_app_version = '4.2.0_7.10.0',
  $kibana_od_elasticsearch_ip = 'localhost',
  $kibana_od_elasticsearch_port = '9200',

  $kibana_od_server_port = '5601',
  $kibana_od_server_host = '0.0.0.0',
  $kibana_od_elasticsearch_server_hosts ="https://${kibana_od_elasticsearch_ip}:${kibana_od_elasticsearch_port}",
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
  package { 'Installing OD Kibana...':
    ensure => $kibana_od_version,
    name   => $kibana_od_package,
  }

  file { 'Configure kibana.yml':
    owner   => 'kibana',
    path    => '/etc/kibana/kibana.yml',
    group   => 'kibana',
    mode    => '0644',
    notify  => Service[$kibana_od_service],
    content => template('wazuh/kibana_od_yml.erb'),
  }

  service { 'kibana':
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  exec {'Waiting for opendistro elasticsearch...':
    path      => '/usr/bin',
    command   => "curl -u ${kibana_od_elastic_user}:${kibana_od_elastic_password} -k -s -XGET https://${kibana_od_elasticsearch_ip}:${kibana_od_elasticsearch_port}",
    tries     => 100,
    try_sleep => 3,
  }

  file {'Removing old Wazuh Kibana Plugin...':
    ensure  => absent,
    path    => '/usr/share/kibana/plugins/wazuh',
    recurse => true,
    purge   => true,
    force   => true,
    notify  => Service[$kibana_od_service]
  }

  exec {'Installing Wazuh App...':
    path    => '/usr/bin',
    command => "sudo -u ${kibana_od_elastic_user}:${kibana_od_elastic_password} -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-${kibana_od_app_version}.zip",
    creates => '/usr/share/kibana/plugins/wazuh/package.json',
    notify  => Service[$kibana_od_service],
  }

  exec {'Removing .wazuh index...':
    path    => '/usr/bin',
    command => "curl -u ${kibana_od_elastic_user}:${kibana_od_elastic_password} -k -s -XDELETE -sL -I 'https://${kibana_od_elasticsearch_ip}:${kibana_od_elasticsearch_port}/.wazuh' -o /dev/null",
    notify  => Service[$kibana_od_service],
  }

  file { '/usr/share/kibana/plugins/wazuh/wazuh.yml':
    owner   => 'kibana',
    group   => 'kibana',
    mode    => '0644',
    content => template('wazuh/wazuh_yml.erb'),
    notify  => Service[$kibana_od_service]
  }
  exec { 'Verify Kibana folders owner':
    path    => '/usr/bin:/bin',
    command => "chown -R kibana:kibana /usr/share/kibana/optimize\
             && chown -R kibana:kibana /usr/share/kibana/plugins",

  }

}
