#
# @summary A define to check if and agent exists
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example Basic usage
#
#   wazuh::utils::agent_exists { 'myagent.example.com':
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
define wazuh::utils::api_agent_exists(
  String $api_username,
  String $api_password,
  Stdlib::Host $api_host,
  Stdlib::Host $agent_name,
  String $agent_status = 'all',
  Stdlib::Port $api_host_port = 55000,
) {

  $config_hash = {
    'agent_name'    => $agent_name,
    'agent_status'  => $agent_status,
    'api_username'  => $api_username,
    'api_password'  => $api_password,
    'api_host'      => $api_host,
    'api_host_port' => $api_host_port
  }

  wazuh::api_agent_exists($config_hash)
}
