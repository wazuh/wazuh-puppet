# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# utility function to fill up /var/ossec/etc/client.keys
class wazuh::agentkey(
  Integer $max_clients = 3000,
  #$agent_id,
  String $agent_name,
  String $agent_ip_address,
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

  # Check if storeconfigs is enabled before attempting to export
  if $whatever == true {
    $export = '@@'
  }
  
  # Put it all together
  Resource["${export}concat::fragment"] { 
  #concat::fragment { "var_ossec_etc_client.keys_${agent_name}_part":
    "var_ossec_etc_client.keys_${agent_name}_part":
      target  => $wazuh::params::keys_file,
      order   => $agent_id,
      content => "${agent_id} ${agent_name} ${agent_ip_address} ${agentkey1}${agentkey2}\n",
  }
}
