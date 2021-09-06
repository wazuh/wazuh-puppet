# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for Filebeat_oss
class wazuh::filebeat_oss (
  String $filebeat_oss_elasticsearch_ip = 'localhost',
  Variant[String,Integer] $filebeat_oss_elasticsearch_port = 9200,
  Optional[String] $filebeat_oss_elasticsearch_proto = 'https',
  $elasticsearch_server_ip = "\"${filebeat_oss_elasticsearch_ip}:${filebeat_oss_elasticsearch_port}\"",

  String $filebeat_oss_package = 'filebeat',
  String $filebeat_oss_service = 'filebeat',
  Optional[String] $filebeat_oss_elastic_user = undef,
  Optional[String] $filebeat_oss_elastic_password = undef,
  Optional[String] $filebeat_oss_elastic_api_key = undef,
  String $filebeat_oss_ssl_verification = 'none',
  Integer $filebeat_oss_elastic_worker = 1,
  Optional[Boolean] $filebeat_oss_setup_ilm_enabled = false,

  String $filebeat_oss_version = '7.10.0',
  String $wazuh_app_version = '4.3.0_7.10.0',
  String $wazuh_extensions_version = 'v4.3.0',
  String $wazuh_filebeat_module = 'wazuh-filebeat-0.1.tar.gz',
){

  class {'wazuh::repo_elastic_oss':}

  if $::osfamily == 'Debian' {
    Class['wazuh::repo_elastic_oss'] -> Class['apt::update'] -> Package[$filebeat_oss_package]
  } else {
    Class['wazuh::repo_elastic_oss'] -> Package[$filebeat_oss_package]
  }

  package { 'filebeat':
    ensure => $filebeat_oss_version,
    name   => $filebeat_oss_package,
  }

  file { 'Configure filebeat.yml':
    owner   => 'root',
    path    => '/etc/filebeat/filebeat.yml',
    group   => 'root',
    mode    => '0644',
    notify  => Service[$filebeat_oss_service], ## Restarts the service
    content => template('wazuh/filebeat_oss_yml.erb'),
    require => Package[$filebeat_oss_package]
  }

  exec { 'Installing wazuh-template.json...':
    path    => '/usr/bin',
    command => "curl -so /etc/filebeat/wazuh-template.json 'https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_extensions_version}/extensions/elasticsearch/7.x/wazuh-template.json'",
    notify  => Service[$filebeat_oss_service],
    require => Package[$filebeat_oss_package],
    creates => '/etc/filebeat/wazuh-template.json'
  }

  exec { 'Installing filebeat module ... Downloading package':
    path    => '/usr/bin',
    command => "curl -o /root/${wazuh_filebeat_module} https://packages.wazuh.com/4.x/filebeat/${wazuh_filebeat_module}",
    creates => "/root/${wazuh_filebeat_module}",
  } ->

  exec { 'Unpackaging ...':
    command => '/bin/tar -xzvf /root/${wazuh_filebeat_module} -C /usr/share/filebeat/module',
    notify  => Service[$filebeat_oss_service],
    require => Package[$filebeat_oss_package],
    creates => "/usr/share/filebeat/module/wazuh/module.yml"
  } 

  file { '/usr/share/filebeat/module/wazuh':
    ensure  => 'directory',
    mode    => '0755',
    require => Package[$filebeat_oss_package]
  }

  service { 'filebeat':
    ensure  => running,
    enable  => true,
    require => Package[$filebeat_oss_package]
  }
}
