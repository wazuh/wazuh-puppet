# Copyright (C) 2015, Wazuh Inc.
# Wazuh repository installation
class wazuh::certificates (
  $indexer_certs = [],
  $server_certs = [],
  $server_master_certs = [],
  $server_worker_certs = [],
  $dashboard_certs = [],
  $cert_tool_script = 'wazuh_certs_tool_script_url',
  $cert_tool_script_name = 'wazuh-certs-tool.sh'
) {

  # Download Wazuh cert tool script
  exec { "download_${cert_tool_script}":
    command => "sh -c 'url=\$(grep -F '${cert_tool_script}:' /tmp/arrtifacts_url.txt | tr -d \"\\r\" | cut -d \" \" -f2); curl -o /tmp/${cert_tool_script_name} \"\$url\"'",
    path    => ['/usr/bin', '/bin', '/sbin', '/usr/sbin'],
    timeout => 600,
  }

  file { 'Configure Wazuh Certificates config.yml':
    owner   => 'root',
    path    => '/tmp/config.yml',
    group   => 'root',
    mode    => '0640',
    content => template('wazuh/wazuh_config_yml.erb'),
  }

  exec { 'Create Wazuh Certificates':
    path    => '/usr/bin:/bin',
    command => "bash /tmp/${cert_tool_script_name} --all",
    creates => '/tmp/wazuh-certificates',
    require => [
      Exec["download_${cert_tool_script}"],
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
