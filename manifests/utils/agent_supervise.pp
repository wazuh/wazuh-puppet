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
#      "last_ack_since" => 300,
#      'last_keepalive_since' => 300,
#      'status' => 'disconnected',
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
#   last_ack_since, last_keepalive_since, status
#     
define wazuh::utils::agent_supervise(
  Hash $when,
) {

  # Restart local agent if any of these conditions are true
  if ($facts['wazuh']['state']['status'] == $when['status'] or
      $facts['wazuh']['state']['last_keepalive_since'] > $when['last_keepalive_since'] or
      $facts['wazuh']['state']['last_ack_since'] > $when['last_ack_since']) {

        warning("Agent ${profile::wazuh::agent::wazuh_agent_name} has lost touch with the server, restarting...")

        wazuh::utils::agent_actions { "Agent ${profile::wazuh::agent::wazuh_agent_name} has lost touch with the server, restarting...":
          action => 'restart',
        }
      }

      #
      # TODO: replace this with a loop  
      #
      if $facts.dig('wazuh', 'state', 'status') != undef {

        if $facts.dig('wazuh', 'agent', 'name') == $profile::wazuh_agent::wazuh_agent_name {

          $agent_local_state = assert_type(String[1], $facts.dig('wazuh', 'state', 'status'))
          $agent_remote_state = assert_type(String[1], wazuh::api_agent_state($profile::wazuh_agent::api_hash))

          if $agent_local_state != 'connected' and $agent_remote_state != 'active' {

            warning("local and remote state for ${profile::wazuh::agent::wazuh_agent_name} disagree about their state")

            # remove current name from the manager
            wazuh::utils::api_remove_agent { "${profile::wazuh_agent::wazuh_agent_name}_supervise":
              *          => $profile::wazuh_agent::api_hash,
              agent_name => $profile::wazuh_agent::wazuh_agent_name,
            }

            # reauth
            wazuh::utils::local_agent_name { "${profile::wazuh_agent::wazuh_agent_name}_supervise":
              *          => $profile::wazuh_agent::agent_params_hash,
              agent_name => $profile::wazuh_agent::wazuh_agent_name,
              require    => Wazuh::Utils::Api_remove_agent["${profile::wazuh_agent::wazuh_agent_name}_supervise"],
            }
          }
        }
      }
}
