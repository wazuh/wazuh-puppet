#
# @summary ensure local wazuh agent name
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example Basic usage
#
define wazuh::utils::local_agent_name(
  Stdlib::Host $auth_server_name,
  String $auth_password,
  Stdlib::Host $agent_name = $title,
  Stdlib::Port $enrollment_port = 1515,
) {
  local_agent_name { $agent_name:
    agent_name       => $agent_name,
    auth_password    => $auth_password,
    auth_server_name => $auth_server_name,
    enrollment_port  => $enrollment_port,
  }
}
