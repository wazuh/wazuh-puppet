# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for Filebeat
class wazuh::filebeat (
  String $filebeat_elasticsearch_ip = 'localhost',
  Variant[String,Integer] $filebeat_elasticsearch_port = 9200,
  Optional[String] $filebeat_elasticsearch_proto = 'https',
  String $elasticsearch_server_ip = "\"${filebeat_elasticsearch_ip}:${filebeat_elasticsearch_port}\"",

  String $filebeat_package = 'filebeat',
  String $filebeat_service = 'filebeat',
  String $filebeat_version = '7.10.0',
  Optional[String] $filebeat_elastic_user = undef,
  Optional[String] $filebeat_elastic_password = undef,
  Optional[String] $filebeat_elastic_api_key = undef,
  String $filebeat_ssl_verification = 'full',
  Integer $filebeat_elastic_worker = 1,
  Optional[Boolean] $filebeat_setup_ilm_enabled = undef,
  String $wazuh_app_version = '4.3.0_7.10.0',
  String $wazuh_extensions_version = 'v4.3.0',
  String $wazuh_filebeat_module = 'wazuh-filebeat-0.1.tar.gz',
  Optional[String] $filebeat_log_level = undef,
  Integer $filebeat_log_keep = 7,
  String $filebeat_log_interval = '1d',
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
    require => Package['filebeat'],
    creates => '/etc/filebeat/wazuh-template.json'
  } 

  exec { 'Installing filebeat module ... Downloading package':
    path    => '/usr/bin',
    command => "curl -o /root/${wazuh_filebeat_module} https://packages.wazuh.com/4.x/filebeat/${$wazuh_filebeat_module}",
    creates => "/root/${wazuh_filebeat_module}",
  }  ->

  exec { 'Unpackaging':
    command => '/bin/tar -xzvf /root/${wazuh_filebeat_module} -C /usr/share/filebeat/module',
    notify  => Service['filebeat'],
    require => Package['filebeat'],
    creates => "/usr/share/filebeat/module/wazuh/module.yml"
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
