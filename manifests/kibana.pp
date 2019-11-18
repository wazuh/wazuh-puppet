# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Setup for Kibana
class wazuh::kibana (
  $kibana_package = 'kibana',
  $kibana_service = 'kibana',
  $kibana_version = '7.3.2',
  $kibana_app_version = '3.10.2_7.3.2',

  $kibana_elasticsearch_ip = '<YOUR_ELASTICSEARCH_IP>',
  $kibana_elasticsearch_port = '9200',

  $kibana_server_port = '5601',
  $kibana_server_host = '0.0.0.0',
  $kibana_elasticsearch_server_hosts ="http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",

){

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
    ensure => running,
    enable => true,
  }

  exec {'Waiting for elasticsearch...':
    path      => '/usr/bin',
    command   => "curl -s -XGET http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",
    tries     => 100,
    try_sleep => 3,
  }

  exec {'Installing Wazuh App...':
    path    => '/usr/bin',
    command => "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-${kibana_app_version}.zip",
    creates => '/usr/share/kibana/plugins/wazuh/package.json',
    notify  => Service[$kibana_service],

  }
    exec {'Enabling and restarting kibana...':
      path    => '/usr/bin:/bin',
      command => 'systemctl daemon-reload && systemctl enable kibana && systemctl restart kibana',

  }

  exec { 'Verify Kibana folders owner':
    path    => '/usr/bin:/bin',
    command => "chown -R kibana:kibana /usr/share/kibana/optimize\
             && chown -R kibana:kibana /usr/share/kibana/plugins",

  }

}
