# Copyright (C) 2015, Wazuh Inc.
# Wazuh repository installation
class wazuh::securityadmin (
) {
  exec { 'Initialize the Opensearch security index in Wazuh indexer':
    path    => ['/usr/bin', '/bin', '/usr/sbin'],
    command => "/usr/share/wazuh-indexer/bin/indexer-security-init.sh && touch ${indexer_security_init_lockfile}",
    creates => $indexer_security_init_lockfile,
    require => Service['wazuh-indexer'],
  }
}