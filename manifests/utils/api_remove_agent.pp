#
# @summary A define to remove an agent from the manager
# with API and a custom function 
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example Basic usage
#
#   wazuh::utils::api_remove_agent { 'myagent.example.com':
#     api_username => $api_username,
#     api_password => $api_password,
#     api_host  => $api_host,
#     api_host_port => $api_host_port
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
# @param $agent_name
#   Agent name to remove.
#
# @param agent_status
#   Limit removal to agents that have this
#   status. Default 'all'
#
define wazuh::utils::api_remove_agent(
  String $api_username,
  String $api_password,
  Stdlib::Host $api_host,
  Stdlib::Host $agent_name,
  Stdlib::Port $api_host_port = 55000,
  Enum['active', 'disconnected', 'never_connected', 'all'] $agent_status = 'all',
) {

  $config_hash = {
    'agent_name'    => $agent_name,
    'agent_status'  => $agent_status,
    'api_username'  => $api_username,
    'api_password'  => $api_password,
    'api_host'      => $api_host,
    'api_host_port' => $api_host_port
  }

  wazuh::api_remove_agent($config_hash)
}
