class wazuh::filebeat (
  $filebeat_elasticsearch_ip = "172.17.0.101",
  $filebeat_elasticsearch_port = "9200",
  $elasticsearch_server_ip = "\"${filebeat_elasticsearch_ip}:${filebeat_elasticsearch_port}\"",

  $filebeat_package = "filebeat",
  $filebeat_service = "filebeat",
  $filebeat_version = "7.1.1",
  $wazuh_app_version = "3.9.1_7.1.0",
  $wazuh_extensions_version = "v3.9.1",
){

  package { 'Installing Filebeat...':
    name    => $filebeat_package,
    ensure  => $filebeat_version,
  }

  file { 'Configure filebeat.yml':
    owner   => 'root',
    path    => '/etc/filebeat/filebeat.yml', 
    group   => 'root',
    mode    => '0644',
    notify  => Service[$filebeat_service], ## Restarts the service
    content => template("wazuh/filebeat_yml.erb"),
  }

  exec { 'Installing wazuh-template.json...':
    command => "curl -so /etc/filebeat/wazuh-template.json 'https://raw.githubusercontent.com/wazuh/wazuh/$wazuh_extensions_version/extensions/elasticsearch/7.x/wazuh-template.json'",
    provider => 'shell',
    notify => Service['filebeat']
  }

  service { "filebeat":
    ensure  => running,
    enable  => true,
  }


}
