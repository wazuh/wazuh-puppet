#
# @summary Agent name change example
#
class wazuh_nametest {  #lint:ignore:autoloader_layout

  # $agent_name = 'my-brand-new-agent.example.com'
  $agent_name = 'wazuh-agent.example.com'

  wazuh::utils::local_agent_name { $agent_name:
    auth_server_name => 'wazuh.example.com',
    auth_password    => 'changeme',
    agent_name       => $agent_name,
  }
}
