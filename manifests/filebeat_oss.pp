# Copyright (C) 2015, Wazuh Inc.
# Setup for Filebeat_oss
class wazuh::filebeat_oss (
  $filebeat_oss_indexer_ip = '127.0.0.1',
  $filebeat_oss_indexer_port = '9200',
  $indexer_server_ip = "\"${filebeat_oss_indexer_ip}:${filebeat_oss_indexer_port}\"",

  $filebeat_oss_package = 'filebeat',
  $filebeat_oss_service = 'filebeat',
  $filebeat_oss_elastic_user = 'admin',
  $filebeat_oss_elastic_password = 'admin',
  $filebeat_oss_version = '7.10.2',
  $wazuh_app_version = '4.3.5_7.10.2',
  $wazuh_extensions_version = 'v4.3.5',
  $wazuh_filebeat_module = 'wazuh-filebeat-0.2.tar.gz',

  $filebeat_path_certs = '/etc/filebeat/certs',
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
    require => Package[$filebeat_oss_package]
  }

  exec { 'Installing filebeat module ... Downloading package':
    path    => '/usr/bin',
    command => "curl -o /root/${$wazuh_filebeat_module} https://packages.wazuh.com/4.x/filebeat/${$wazuh_filebeat_module}",
  }

  exec { 'Unpackaging ...':
    command => '/bin/tar -xzvf /root/wazuh-filebeat-0.2.tar.gz -C /usr/share/filebeat/module',
    notify  => Service[$filebeat_oss_service],
    require => Package[$filebeat_oss_package]
  }

  file { '/usr/share/filebeat/module/wazuh':
    ensure  => 'directory',
    mode    => '0755',
    require => Package[$filebeat_oss_package]
  }

  include wazuh::certificates

  exec { 'Copy Filebeat Certificates':
    path    => '/usr/bin:/bin',
    command => "mkdir $filebeat_path_certs \
             && cp /tmp/wazuh-certificates/server.pem  $filebeat_path_certs/filebeat.pem\
             && cp /tmp/wazuh-certificates/server-key.pem  $filebeat_path_certs/filebeat-key.pem\
             && cp /tmp/wazuh-certificates/root-ca.pem  $filebeat_path_certs\
             && chown root:root -R $filebeat_path_certs\
             && chmod 500 $filebeat_path_certs\
             && chmod 400 $filebeat_path_certs/*",
    require => Package[$filebeat_oss_package],

  }

  service { 'filebeat':
    ensure  => running,
    enable  => true,
    require => Package[$filebeat_oss_package]
  }
}
