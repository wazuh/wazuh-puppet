#
# @summary Example to Restart agent based on limits in the hash
#
class wazuh::supervise { #lint:ignore:autoloader_layout

  $when = {
    'last_ack_since' => 300,
    'last_keepalive_since' => 300,
    'status' => 'disconnected',
  }

  wazuh::utils::agent_supervise { 'keep control':
    when => $when,
  }

}
