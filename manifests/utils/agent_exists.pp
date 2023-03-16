#
# @summary A define to check if and agent exists
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example Basic usage
#
#   wazuh::utils::agent_exists { 'myagent.example.com':
#     api_agent_name => 'my.example.com,
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
# @param $api_agent_name
#   Agent name to look up
#
define wazuh::utils::agent_exists(
  String $api_username,
  String $api_password,
  Stdlib::Host $api_host,
  Stdlib::Host $api_agent_name,
  String $api_check_states = 'all',
  Stdlib::Port $api_host_port = 55000,
) {

  $config_hash = {
    'api_agent_name'   => $api_agent_name,
    'api_check_states' => $api_check_states,
    'api_username'     => $api_username,
    'api_password'     => $api_password,
    'api_host'         => $api_host,
    'api_host_port'    => $api_host_port
  }
}
