# Copyright (C) 2015, Wazuh Inc.
# Wazuh repository installation
class wazuh::certificates_dist (
  $wazuh_repository = 'packages-dev.wazuh.com',
  $wazuh_version = '4.4',
  $indexer_certs = [],
  $manager_certs = [],
  $manager_master_certs = [],
  $manager_worker_certs = [],
  $dashboard_certs = []
) {
  file { 'Configure Wazuh Certificates config.yml':
    owner   => 'root',
    path    => '/tmp/config.yml',
    group   => 'root',
    mode    => '0640',
    content => template('wazuh/wazuh_config_dist_yml.erb'),
  }

  file { '/tmp/wazuh-certs-tool.sh':
    ensure => file,
    source => "https://${wazuh_repository}/${wazuh_version}/wazuh-certs-tool.sh",
    owner  => 'root',
    group  => 'root',
    mode   => '0740',
  }

  exec { 'Create Wazuh Certificates':
    path    => '/usr/bin:/bin',
    command => 'bash /tmp/wazuh-certs-tool.sh --all',
    creates => '/tmp/wazuh-certificates',
    require => [
      File['/tmp/wazuh-certs-tool.sh'],
      File['/tmp/config.yml'],
    ],
  }
  file { 'Copy all certificates into module':
    ensure => 'directory',
    source => '/tmp/wazuh-certificates/',
    recurse => 'remote',
    path => '/etc/puppetlabs/code/environments/production/modules/archive/files/',
    owner => 'root',
    group => 'root',
    mode  => '0755',
  }
}
