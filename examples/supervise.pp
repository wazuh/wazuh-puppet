#
# @summary Example to Restart agent based on limits in the hash
#
class local_profile::supervise {

  $when = {
    "last_ack_since" => 300,
    'last_keepalive_since' => 300,
    'status' => 'disconnected',
  }
  
  wazuh::utils::agent_supervisor { 'keep control':
    when => $when,
  }

}
