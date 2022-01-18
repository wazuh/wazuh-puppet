# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for Filebeat
class wazuh::filebeat (
  $filebeat_elasticsearch_ip = 'localhost',
  $filebeat_elasticsearch_port = '9200',
  $elasticsearch_server_ip = "\"${filebeat_elasticsearch_ip}:${filebeat_elasticsearch_port}\"",

  $filebeat_package = 'filebeat',
  $filebeat_service = 'filebeat',
  $filebeat_version = '7.10.2',
  $wazuh_app_version = '4.4.0_7.10.0',
  $wazuh_extensions_version = 'v4.4.0',
  $wazuh_filebeat_module = 'wazuh-filebeat-0.1.tar.gz',
){

  class {'wazuh::repo_elastic':}

  if $::osfamily == 'Debian' {
    Class['wazuh::repo_elastic'] -> Class['apt::update'] -> Package['filebeat']
  } else {
    Class['wazuh::repo_elastic'] -> Package['filebeat']
  }

  package { 'filebeat':
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
    require => Package['filebeat']
  }

  exec { 'Installing wazuh-template.json...':
    path    => '/usr/bin',
    command => "curl -so /etc/filebeat/wazuh-template.json 'https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_extensions_version}/extensions/elasticsearch/7.x/wazuh-template.json'",
    notify  => Service['filebeat'],
    require => Package['filebeat']
  }

  exec { 'Installing filebeat module ... Downloading package':
    path    => '/usr/bin',
    command => "curl -o /root/${$wazuh_filebeat_module} https://packages.wazuh.com/4.x/filebeat/${$wazuh_filebeat_module}",
  }

  exec { 'Unpackaging ...':
    command => '/bin/tar -xzvf /root/wazuh-filebeat-0.1.tar.gz -C /usr/share/filebeat/module',
    notify  => Service['filebeat'],
    require => Package['filebeat']
  }

  file { '/usr/share/filebeat/module/wazuh':
    ensure  => 'directory',
    mode    => '0755',
    require => Package['filebeat']
  }

  service { 'filebeat':
    ensure  => running,
    enable  => true,
    require => Package['filebeat']
  }
}
