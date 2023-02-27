#
# @summary Example to remove agent from manager
#
class local_profile::wazuh_remove {

  $agent_name = 'wazuh-agent.example.com'
  # $agent_name = 'my-brand-new-agent.example.com'
  
  wazuh::utils::api_remove_agent { $agent_name: 
    agent_name      => $agent_name,
    api_username    => 'wazuh',
    api_password    => 'wazuh',
    api_host        => 'wazuh.example.com',
    api_host_port   => 55000,
  }
}
