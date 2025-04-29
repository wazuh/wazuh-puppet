# Copyright (C) 2015, Wazuh Inc.

# Puppet class that installs and manages the Wazuh agent
class wazuh::agent (
  $agent_package = 'wazuh_indexer',
  $agent_version = '5.0.0',
) {
  Wazuh::Install_package { 'Wazuh agent':
    package_name  => $agent_package,
    wazuh_version => $agent_version,
  }
}
