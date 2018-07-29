# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# utility function to fill up /var/ossec/etc/client.keys
class wazuh::agentkey(
  String $agent_name,
  String $agent_ip_address,
  Stdlib::Absolutepath $keys_file,
  Integer $max_clients = 3000,
  Boolean $export_keys = true,
  #$agent_id,
  #Stdlib::Ip_address $agent_ip_address,
  String $agent_seed = 'xaeS7ahf',
) {
  # Generate random agent_id
  $agent_id = fqdn_rand($max_clients)

  #if ! $agent_id { fail('wazuh::agentkey: $agent_id is missing')}
  #if ! $agent_seed { fail('wazuh::agentkey: $agent_seed is missing')}
  
  # Generate some md5 sums
  $agentkey1 = md5("${agent_id} ${agent_seed}")
  $agentkey2 = md5("${agent_name} ${agent_ip_address} ${agent_seed}")

  # Put it all together and make sure the local keys are created since 
  #  Puppet doesn't actually DO anything with exported resources until 
  #  collected
  concat::fragment { "var_ossec_etc_client.keys_${agent_name}_part":
    "var_ossec_etc_client.keys_${agent_name}_part":
      target  => $keys_file,
      order   => $agent_id,
      content => "${agent_id} ${agent_name} ${agent_ip_address} ${agentkey1}${agentkey2}\n",
  }

  # Export keys if storeconfigs is enabled
  if ($settings::storeconfigs == true) and ($export_keys == true) {
    @@concat::fragment { "var_ossec_etc_client.keys_${agent_name}_export":
      target  => $keys_file,
      order   => $agent_id,
      content => "${agent_id} ${agent_name} ${agent_ip_address} ${agentkey1}${agentkey2}\n",
    }
  }
}
