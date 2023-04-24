#
# @summary Restart agent on certain conditions
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example
# 
#   Define a hash $when to decide when
# 
#   $when = {
#      'control_last_ack_since' => 300,
#      'control_last_keepalive_since' => 300,
#      'control_status' => 'disconnected',
#   }
#
#   wazuh::utils::agent_supervisor { 'keep control':
#      when => $when,
#   }
#
# @params
#
#   $when
#   A hash with three limits:
#   control_last_ack_since, control_last_keepalive_since, control_status
#     
define wazuh::utils::agent_supervise(
  Hash $when,
  Boolean $agent_name_changed,
  Boolean $server_name_changed,
  Boolean $password_changed,
  Boolean $server_port_changed,
  Boolean $check_remote_state = false,
) {

  # do not supervise if there are changes
  unless ($agent_name_changed or $server_name_changed or $password_changed or $server_port_changed) {

    # Restart local agent if any of these conditions are true
    if ($facts['wazuh']['state']['status'] == $when['control_status'] or
      $facts['wazuh']['state']['last_keepalive_since'] > $when['last_keepalive_since'] or
    $facts['wazuh']['state']['last_ack_since'] > $when['last_ack_since']) {

      warning("WAZUH: Agent ${profile::wazuh_agent::wazuh_agent_name} has lost touch with the server, restarting...")

      wazuh::utils::agent_actions { "Agent ${profile::wazuh_agent::wazuh_agent_name} restarting...":
        action => 'restart',
      }
    }

    if $check_remote_state {

      if $facts.dig('wazuh', 'state', 'status') != undef {

        if $facts.dig('wazuh', 'agent', 'name') == $profile::wazuh_agent::wazuh_agent_name {

          $_name = $profile::wazuh_agent::wazuh_agent_name
          if ! $profile::wazuh_agent::api_hash.has_key('api_agent_name') {
            $local_api_hash = $profile::wazuh_agent::api_hash.merge({ 'api_agent_name' => $_name })
          }

          $agent_local_state = assert_type(String[1], $facts.dig('wazuh', 'state', 'status'))
          $agent_remote_state = assert_type(String[1], wazuh::api_agent_status($local_api_hash))

          if ($agent_local_state != 'connected') and ($agent_remote_state != 'active') {

            warning("WAZUH: local and remote state for ${profile::wazuh_agent::wazuh_agent_name} disagree about their state")
            # remove current name from the manager
            wazuh::utils::api_agent_remove { "${profile::wazuh_agent::wazuh_agent_name}_supervise_remove":
              * => $local_api_hash,
            }
            # reauth
            wazuh::utils::agent_name { "${profile::wazuh_agent::wazuh_agent_name}_supervise_reauth":
              *          => $profile::wazuh_agent::agent_params_hash,
              agent_name => $profile::wazuh_agent::wazuh_agent_name,
              require    => Wazuh::Utils::Api_agent_remove["${profile::wazuh_agent::wazuh_agent_name}_supervise_remove"],
            }
          }
        }
      }
    }
  }
}
