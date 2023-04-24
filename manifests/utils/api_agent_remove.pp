#
# @summary A define to remove an agent from the manager
# via API with a a custom function 
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example Basic usage
#
#   wazuh::utils::api_agent_remove { 'myagent.example.com':
#     api_username => $api_username,
#     api_password => $api_password,
#     api_host  => $api_host,
#     api_host_port => $api_host_port,
#     api_agent_name => 'myagent.example.com'
#   }
#
# @param api_username,
#   username to acces the API.
#
# @param api_password
#   password to acces the API.
#
# @param api_host
#   The API host.
# 
# @param api_host_port
#   The API port. Default 55000.
#
# @param $api_agent_name
#   Agent name to remove.
#
# @param agent_check_states
#   Limit removal to agents that have this
#   status. Default 'all'
#
define wazuh::utils::api_agent_remove(
  String $api_username,
  String $api_password,
  Stdlib::Host $api_host,
  String $api_agent_name,
  Stdlib::Port $api_host_port = 55000,
  Enum['active', 'pending', 'disconnected', 'never_connected', 'all'] $api_check_states = 'all',
) {

  $config_hash = {
    'api_agent_name'   => $api_agent_name,
    'api_check_states' => $api_check_states,
    'api_username'     => $api_username,
    'api_password'     => $api_password,
    'api_host'         => $api_host,
    'api_host_port'    => $api_host_port
  }

  wazuh::api_agent_remove($config_hash)
}
