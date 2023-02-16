class wazuh::remote_agent(

  String $agent_name,
  String $api_username,
  String $api_password,
  Stdlib::Host $api_host,
  Stdlib::Port $api_host_port,
) {  

  notify { "agent: $agent_name": }
  notify { "api_username: $api_username": }
  notify { "api_password: $api_password": }
  notify { "api_host: $api_host": }
  notify { "api_host_port: $api_host_port": }
  
  remote_agent { $agent_name:
    ensure => 'absent',
    api_username => $api_username,
    api_password => $api_password,
    api_host  => $api_host,
    api_host_port => $api_host_port
  }
}

