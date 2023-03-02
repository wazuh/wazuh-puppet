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

  notify { "got: ${when}": }
  
  if ($facts['wazuh']['state']['status'] == $when['status'] or
      $facts['wazuh']['state']['last_keepalive_since'] > $when['last_keepalive_since'] or
      $facts['wazuh']['state']['last_ack_since'] > $when['last_ack_since']) {
        
        wazuh::utils::agent_actions { 'Agent has gone too far, restarting...':
          action => 'restart',
        }
      }
}
