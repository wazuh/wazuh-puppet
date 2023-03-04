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
  
  # Restart local agent if any of these conditions are true
  if ($facts['wazuh']['state']['status'] == $when['status'] or
      $facts['wazuh']['state']['last_keepalive_since'] > $when['last_keepalive_since'] or
      $facts['wazuh']['state']['last_ack_since'] > $when['last_ack_since']) {
        
        wazuh::utils::agent_actions { 'Agent has gone too far, restarting...':
          action => 'restart',
        }
      }


      /*
      # get remote status
      # get local status 
      # if either is not connected
      # loop 10 times and give up with a warning 
      if $out_of_sync['local_status'] && $out_of_sync['remote_status'] {
        $range = range(0, 9)
        $range.each |$index| {
          warning('Still out of sync...')
          if local_status == 'connected' and remote_status == 'connected' {
            break
          }
          sleep(5)
        }
      }
      */
}

