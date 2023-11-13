# Copyright (C) 2015, Wazuh Inc.
# Wazuh repository installation
class wazuh::securityadmin (
  $indexer_init_lockfile = '/var/tmp/indexer-init.lock',
  $indexer_network_host = 'localhost',
) {
  exec { 'Initialize the Opensearch security index and ISM Polciy in Wazuh indexer':
    path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    command => "/usr/share/wazuh-indexer/bin/indexer-init.sh -i ${indexer_network_host} && touch ${indexer_init_lockfile}",
    creates => $indexer_init_lockfile,
    require => Service['wazuh-indexer'],
  }
}
