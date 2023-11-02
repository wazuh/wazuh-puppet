# Copyright (C) 2015, Wazuh Inc.
# Wazuh repository installation
class wazuh::ism_rollover (
  $wazuh_version = '4.8',
) {

  file { '/tmp/indexerRolloverInit.sh':
    ensure => file,
    source => "https://${wazuh_repository}/${wazuh_version}/indexerRolloverInit.sh",
    owner  => 'root',
    group  => 'root',
    mode   => '0740',
  }

  exec { 'Initialize indexes Rollover':
    path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    command => "/tmp/indexerRolloverInit.sh",
    require => Service['wazuh-indexer'],
  }
}