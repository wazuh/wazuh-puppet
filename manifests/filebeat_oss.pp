# Copyright (C) 2015, Wazuh Inc.
# Setup for Filebeat_oss
class wazuh::filebeat_oss (
  $filebeat_oss_indexer_ip = '127.0.0.1',
  $filebeat_oss_indexer_port = '9200',
  $indexer_server_ip = "\"${filebeat_oss_indexer_ip}:${filebeat_oss_indexer_port}\"",

  $filebeat_oss_archives = false,
  $filebeat_oss_package = 'filebeat',
  $filebeat_oss_service = 'filebeat',
  $filebeat_oss_elastic_user = 'admin',
  $filebeat_oss_elastic_password = 'admin',
  $filebeat_oss_version = '7.10.2',
  $wazuh_app_version = '4.4.4_7.10.2',
  $wazuh_extensions_version = '4.4',
  $wazuh_filebeat_module = 'wazuh-filebeat-0.2.tar.gz',

  $filebeat_fileuser = 'root',
  $filebeat_filegroup = 'root',
  $filebeat_path_certs = '/etc/filebeat/certs',
) {
  include wazuh::repo

  if $facts['os']['family'] == 'Debian' {
    Class['wazuh::repo'] -> Class['apt::update'] -> Package['filebeat']
  } else {
    Class['wazuh::repo'] -> Package['filebeat']
  }

  package { 'filebeat':
    ensure => $filebeat_oss_version,
    name   => $filebeat_oss_package,
  }

  file { '/etc/filebeat/filebeat.yml':
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    notify  => Service['filebeat'], ## Restarts the service
    content => template('wazuh/filebeat_oss_yml.erb'),
    require => Package['filebeat'],
  }

  # work around:
  #  Use cmp to compare the content of local and remote file. When they differ than rm the file to get it recreated by the file resource.
  #  Needed since GitHub can only ETAG and result in changes of the mtime everytime.
  # TODO: Include file into the wazuh/wazuh-puppet project or use file { checksum => '..' } for this instead of the exec construct.
  exec { 'cleanup /etc/filebeat/wazuh-template.json':
    command => '/bin/rm -f /etc/filebeat/wazuh-template.json',
    onlyif  => '/bin/test -f /etc/filebeat/wazuh-template.json',
    unless  => "/bin/curl -s 'https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_extensions_version}/extensions/elasticsearch/7.x/wazuh-template.json' | /bin/cmp -s '/etc/filebeat/wazuh-template.json'",
  }
  -> file { '/etc/filebeat/wazuh-template.json':
    owner   => 'root',
    group   => 'root',
    mode    => '0440',
    replace => false,  # only copy content when file not exist
    source  => "https://raw.githubusercontent.com/wazuh/wazuh/${wazuh_extensions_version}/extensions/elasticsearch/7.x/wazuh-template.json",
    notify  => Service['filebeat'],
    require => Package['filebeat'],
  }

  archive { "/tmp/${$wazuh_filebeat_module}":
    ensure       => present,
    source       => "https://packages.wazuh.com/4.x/filebeat/${$wazuh_filebeat_module}",
    extract      => true,
    extract_path => '/usr/share/filebeat/module',
    creates      => '/usr/share/filebeat/module/wazuh',
    cleanup      => true,
    notify       => Service['filebeat'],
    require      => Package['filebeat'],
  }

  file { '/usr/share/filebeat/module/wazuh':
    ensure  => 'directory',
    mode    => '0755',
    require => Package['filebeat'],
  }

  require wazuh::certificates

  exec { "ensure full path of ${filebeat_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${filebeat_path_certs}",
    creates => $filebeat_path_certs,
    require => Package['filebeat'],
  }
  -> file { $filebeat_path_certs:
    ensure => directory,
    owner  => $filebeat_fileuser,
    group  => $filebeat_filegroup,
    mode   => '0500',
  }

  $_certfiles = {
    'server.pem'     => 'filebeat.pem',
    'server-key.pem' => 'filebeat-key.pem',
    'root-ca.pem'    => 'root-ca.pem',
  }
  $_certfiles.each |String $certfile_source, String $certfile_target| {
    file { "${filebeat_path_certs}/${certfile_target}":
      ensure  => file,
      owner   => $filebeat_fileuser,
      group   => $filebeat_filegroup,
      mode    => '0400',
      replace => false,  # only copy content when file not exist
      source  => "/tmp/wazuh-certificates/${certfile_source}",
    }
  }

  service { 'filebeat':
    ensure  => running,
    enable  => true,
    name    => $filebeat_oss_service,
    require => Package['filebeat'],
  }
}
