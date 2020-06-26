node 'manager_0' {
  class { "wazuh::manager":}
}
node 'agent_0' {
  class { "wazuh::agent":
        wazuh_register_endpoint => "manager_ip",
        wazuh_reporting_endpoint => "manager_ip",
  }
}
