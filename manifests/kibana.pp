class wazuh::kibana (
  $kibana_package = "kibana",
  $kibana_service = "kibana",
  $kibana_version = "7.1.1",
  $kibana_app_version = "3.9.1_7.1.1",

  $kibana_elasticsearch_ip = "172.17.0.101",
  $kibana_elasticsearch_port = "9200",

  $kibana_server_port = "5601",
  $kibana_server_host = "0.0.0.0",
  $kibana_elasticsearch_server_hosts ="http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",

){

  # install package
  package { 'Installing Kibana...':
    name    => $kibana_package,
    ensure  => $kibana_version,
  }

  service { "kibana":
    ensure  => running,
    enable  => true,
  }

  file { 'Configure kibana.yml':
    owner   => 'kibana',
    path    => '/etc/kibana/kibana.yml', 
    group   => 'kibana',
    mode    => '0644',
    content => template("wazuh/kibana_yml.erb"),
  }

    exec {"Waiting for elasticsearch...":
    command => "until (curl -XGET http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}); do\
                printf 'Waiting for elasticsearch....' && \
                sleep 5\
                done",
    provider => 'shell',
    returns => [0, 2, 14],
  }

  exec {"Installing Wazuh App...":
    command => "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-${kibana_app_version}.zip",
    creates => '/usr/share/kibana/plugins/wazuh/package.json',
    notify  => Service[$kibana_service],
    provider => 'shell',
  }
    exec {"Enabling and restarting kibana...":
      command => "systemctl daemon-reload && systemctl enable kibana && systemctl restart kibana",
      provider => 'shell',
  }

  exec { 'Verify Kibana folders owner':
    command => "chown -R kibana:kibana /usr/share/kibana/optimize\
             && chown -R kibana:kibana /usr/share/kibana/plugins",
    provider => 'shell',             
  }

}
