class wazuh::kibana (
  $kibana_package = "kibana",
  $kibana_service = "kibana",
  $kibana_version = "7.1.0",
  $kibana_app_version = "3.9.1_7.1.0",

  $kibana_elasticsearch_ip = "localhost",
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

  file { 'Configure kibana.yml':
    owner   => 'kibana',
    path    => '/etc/kibana/kibana.yml', 
    group   => 'kibana',
    mode    => '0644',
    notify  => Service[$kibana_service],
    content => template("wazuh/kibana_yml.erb"),
  }

  service { "kibana":
    ensure  => running,
    enable  => true,
  }

  exec {"Waiting for elasticsearch...":
    path    => "/usr/bin",
    command => "curl -XGET http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",
    timeout => 5,
    tries   => 5,
    returns => [0, 2, 14],
  }

  exec {"Installing Wazuh App...":
    path    => "/usr/bin",
    command => "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-${kibana_app_version}.zip",
    creates => '/usr/share/kibana/plugins/wazuh/package.json',
    notify  => Service[$kibana_service],
    
  }
    exec {"Enabling and restarting kibana...":
      path    => "/usr/bin",
      command => "systemctl daemon-reload && systemctl enable kibana && systemctl restart kibana",
      
  }

  exec { 'Verify Kibana folders owner':
    path    => "/usr/bin",
    command => "chown -R kibana:kibana /usr/share/kibana/optimize\
             && chown -R kibana:kibana /usr/share/kibana/plugins",
                 
  }

}
