#
# @summary Example to remove agent from manager
#
class wazuh_remove {  #lint:ignore:autoloader_layout

  $agent_name = 'wazuh-agent.example.com'

  wazuh::utils::api_remove_agent { $agent_name:
    agent_name    => $agent_name,
    api_username  => 'wazuh',
    api_password  => 'wazuh',
    api_host      => 'wazuh.example.com',
    api_host_port => 55000,
  }
}
