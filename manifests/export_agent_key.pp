#Export agent key
class wazuh::export_agent_key(
  $max_clients,
  $agent_name,
  $agent_ip_address,
  $agent_seed,
  ) {
  wazuh::agentkey{ "ossec_agent_${agent_name}_client":
    agent_id         => fqdn_rand($max_clients),
    agent_name       => $agent_name,
    agent_ip_address => $agent_ip_address,
    agent_seed       => $agent_seed,
  }

  @@wazuh::agentkey{ "ossec_agent_${agent_name}_server":
    agent_id         => fqdn_rand($max_clients),
    agent_name       => $agent_name,
    agent_ip_address => $agent_ip_address,
    agent_seed       => $agent_seed,
  }
}
