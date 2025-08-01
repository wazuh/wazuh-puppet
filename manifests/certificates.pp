# Copyright (C) 2015, Wazuh Inc.
# @summary Wazuh certificate generation
# If using legacy workflow, this generates all certificates using the
# `wazuh-certs-tool.sh` script and dumps them into Puppet server's code directory.
# (This is less than ideal.)
# If `$use_legacy_workflow` is false, it will use the openssl module and the Puppet CA 
# to generate certificates.
class wazuh::certificates (
  Boolean $use_legacy_workflow = true,
  String $puppet_code_path = '/etc/puppetlabs/code/environments/production/modules/archive/files',
  String $wazuh_repository = 'packages.wazuh.com',
  String $wazuh_version = '5.0',
  $indexer_certs = [],
  $manager_certs = [],
  $manager_master_certs = [],
  $manager_worker_certs = [],
  $dashboard_certs = [],
  Stdlib::Absolutepath $ca_cert_path = $settings::cacert,
  Stdlib::Absolutepath $ca_key_path = $settings::cakey,
  String $bucket_name = 'wazuh',
  Stdlib::Absolutepath $filebucket_path = "${settings::confdir}/filebucket",
  Stdlib::Absolutepath $fileserver_conf = "${settings::confdir}/fileserver.conf",
) {
  if $use_legacy_workflow {
    file { 'Configure Wazuh Certificates config.yml':
      owner   => 'root',
      path    => '/tmp/config.yml',
      group   => 'root',
      mode    => '0640',
      content => template('wazuh/wazuh_config_yml.erb'),
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
      ensure  => 'directory',
      source  => '/tmp/wazuh-certificates/',
      recurse => 'remote',
      path    => $puppet_code_path,
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
    }
  }
  else {
    contain wazuh::certificates::mountpoint
    Openssl::Certificate::X509 <<| tag == 'wazuh' |>> {
      ensure       => present,
      country      => 'US',
      locality     => 'California',
      organization => 'Wazuh',
      unit         => 'Wazuh',
      extkeyusage  => ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment'],
      base_dir     => "${filebucket_path}/${bucket_name}",
      ca           => $ca_cert_path,
      cakey        => $ca_key_path,
    }
  }
}
