# 
# @summary Removes an agent from the API host
#
# @example Basic usage
#   class wazuh::remote_agent { 'myagent.example.com':
#     api_username => $api_username,
#     api_password => $api_password,
#     api_host  => $api_host,
#     api_host_port => $api_host_port
#   }
#
# @param agent_name
#   Agent name to remove.
#
# @param status
#   Limit removal to agents that have this
#   status. Default 'all'
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
# @param api_host
#   The API port. Default 55000.
#
define wazuh::remote_agent(
  String $api_username,
  String $api_password,
  Stdlib::Host $api_host,
  Stdlib::Port $api_host_port,
  Enum['all', 'disconnected', 'active'] $status = 'all'
) {  

  remote_agent { $title:
    ensure        => 'absent',
    status        => $status,
    api_username  => $api_username,
    api_password  => $api_password,
    api_host      => $api_host,
    api_host_port => $api_host_port
  }
}

