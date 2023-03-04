#
# @summary ensure local wazuh agent name
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example Basic usage
#
define wazuh::utils::local_agent_name(
  $wazuh_register_endpoint,
  $wazuh_reporting_endpoint,
  $wazuh_enrollment_auth_pass,
  $wazuh_enrollment_enabled,
  $wazuh_enrollment_port,
  $agent_auth_password,
  $ossec_port,
  $agent_package_version,

  #Stdlib::Host $auth_server_name,
  #String $agent_auth_password,
  Stdlib::Host $agent_name = $title,
  #Stdlib::Port $enrollment_port = 1515,
  #Stdlib::Port $communication_port = 1514,
) {

  with($agent_auth_password,
       $wazuh_register_endpoint,
       $wazuh_enrollment_port,
       $ossec_port)
  |$auth_password, $auth_server_name, $enrollment_port, $communication_port | {

    local_agent_name { $agent_name:
      agent_name         => $agent_name,
      auth_password      => $auth_password,
      auth_server_name   => $auth_server_name,
      enrollment_port    => $enrollment_port,
      communication_port => $communication_port,
    }
  }
}
