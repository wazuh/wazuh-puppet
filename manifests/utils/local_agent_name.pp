#
# @summary Ensure local wazuh agent name
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example Basic usage
#
define wazuh::utils::local_agent_name(
  Stdlib::Host $wazuh_register_endpoint,
  Optional[String] $wazuh_enrollment_auth_pass,
  Boolean $wazuh_enrollment_enabled,
  Stdlib::Port $wazuh_enrollment_port,
  String $agent_auth_password,
  Stdlib::Port $ossec_port,
  Stdlib::Host $agent_name = $agent_name,
  Optional[Stdlib::Host] $wazuh_reporting_endpoint = undef,
  Optional[String] $agent_package_version = undef,
  Optional[String] $agent_package_revision = undef,

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
