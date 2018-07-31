# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# utility function to fill up /var/ossec/etc/client.keys
class wazuh::agentkey(
  String $keys_owner,
  String $keys_group,
  String $keys_mode,
  Stdlib::Absolutepath $keys_file,
  String $agent_name,
  String $agent_ip_address,
  String $ossec_server_address,
  String $agent_package_name,
  String $agent_service_name,
  Integer $max_clients = 3000,
  #Stdlib::Ip_address $agent_ip_address,
  String $agent_seed = 'xaeS7ahf',
) {
  # Generate random agent_id
  $agent_id = fqdn_rand($max_clients)

  # Generate some md5 sums
  $agentkey1 = md5("${agent_id} ${agent_seed}")
  $agentkey2 = md5("${agent_name} ${agent_ip_address} ${agent_seed}")

  # Put it all together and make sure the local keys are created since 
  #  Puppet doesn't actually DO anything with exported resources until 
  #  collected
  file { "${keys_file}":
    owner   => $keys_owner,
    group   => $keys_group,
    mode    => $keys_mode,
    content => "${agent_id} ${agent_name} ${agent_ip_address} ${agentkey1}${agentkey2}\n",
    notify  => Service[$agent_service_name],
    require => Package[$agent_package_name],
  }

  # Export keys if storeconfigs is enabled
  if ($settings::storeconfigs == true) {
    @@concat::fragment { "var_ossec_etc_client.keys_${agent_name}_${$ossec_server_address}_part":
      target  => $keys_file,
      order   => $agent_id,
      content => "${agent_id} ${agent_name} ${agent_ip_address} ${agentkey1}${agentkey2}\n",
    }
  }
}
