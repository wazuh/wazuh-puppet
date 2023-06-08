# Copyright (C) 2015, Wazuh Inc.
# Wazuh repository installation
class wazuh::repo_use (
) {
 include wazuh::repo
 if $facts['os']['family'] == 'Debian' {
   Class['wazuh::repo'] -> Class['apt::update'] -> Package['wazuh-indexer']
 } else {
   Class['wazuh::repo'] -> Package['wazuh-indexer']
 }
}
