# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Setup for Filebeat
class wazuh::filebeat (
  $filebeat_elasticsearch_ip = '<YOUR_ELASTICSEARCH_IP>',
  $filebeat_elasticsearch_port = '9200',
  $elasticsearch_server_ip = "\"${filebeat_elasticsearch_ip}:${filebeat_elasticsearch_port}\"",

  $filebeat_package = 'filebeat',
  $filebeat_service = 'filebeat',
  $filebeat_version = '7.3.2',
  $wazuh_app_version = '3.10.2_7.3.2',
  $wazuh_extensions_version = 'v3.10.2',
  $wazuh_filebeat_module = 'wazuh-filebeat-0.1.tar.gz',
){

  class {'wazuh::repo_elastic':}

  package { 'Installing Filebeat...':
    ensure => $filebeat_version,
    name   => $filebeat_package,
  }

  file { 'Configure filebeat.yml':
    owner   => 'root',
    path    => '/etc/filebeat/filebeat.yml',
    group   => 'root',
    mode    => '0644',
    notify  => Service[$filebeat_service], ## Restarts the service
    content => template('wazuh/filebeat_yml.erb'),
  }

  exec { 'Installing wazuh-template.json...':
    path    => '/usr/bin',
    command => "curl -so /etc/filebeat/wazuh-template.json 'https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_extensions_version}/extensions/elasticsearch/7.x/wazuh-template.json'",
    notify  => Service['filebeat']
  }

  exec { 'Installing filebeat module ... Downloading package':
    path    => '/usr/bin',
    command => "curl -o /root/${$wazuh_filebeat_module} https://packages.wazuh.com/3.x/filebeat/${$wazuh_filebeat_module}",
  }

  exec { 'Unpackaging ...':
    command => '/bin/tar -xzvf /root/wazuh-filebeat-0.1.tar.gz -C /usr/share/filebeat/module',
    notify  => Service['filebeat']
  }

  file { '/usr/share/filebeat/module/wazuh':
    ensure => 'directory',
    mode   => '0755',
  }

  service { 'filebeat':
    ensure => running,
    enable => true,
  }
}
