#
# @summary A define to reporet remote agent state
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example Basic usage
#
#   wazuh::utils::api_agent_state { 'myagent.example.com':
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
define wazuh::utils::api_agent_state(
  String $api_username,
  String $api_password,
  Stdlib::Host $api_host,
  String $agent_name,
  String $agent_status = 'all',
  Stdlib::Port $api_host_port = 55000,
) {

  if $facts.has_key('wazuh') and $facts['wazuh'].has_key('state') and $facts['wazuh']['state']['status'].length > 0 {

    # if agent name has been changed in the catalog, we cannot yet query it's state 
    if $profile::wazuh_agent::wazuh_agent_name != $facts['wazuh']['agent']['name'] {

      $config_hash = {
        'api_agent_name' => $agent_name,
        'api_status'     => $agent_status,
        'api_username'   => $api_username,
        'api_password'   => $api_password,
        'api_host'       => $api_host,
        'api_host_port'  => $api_host_port
      }

      wazuh::api_agent_state($config_hash)
    }
  }
}
