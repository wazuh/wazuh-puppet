#
# @summary Example to change agent name
#
class local_profile::wazuh_ensure_name {

  $new_name = 'brand-new-agent.example.com'
  $current_name = $facts['wazuh']['agent']['name']

  notify { "current wazuh name fact: ${facts['wazuh']['agent']['name']}":
  }
  
  notify { "new wazuh name: ${new_name}":
    require => Notify["current wazuh name fact: ${facts['wazuh']['agent']['name']}"],
    before  => Notify["new wazuh name fact: ${facts['wazuh']['agent']['name']}"],
  }

  # does the name differ from current name? 
  if $new_name != $current_name {
    
    # prevent current agent from reconnecting in the middle
    wazuh::utils::agent_actions { "${current_name}_stop":
      action => stop,
      require => Notify["new wazuh name: ${new_name}"]
    }
    
    # remove current name from the manager
    # (custom function runs on puppet server)
    wazuh::utils::api_remove_agent { $current_name:
      api_username    => 'wazuh',
      api_password    => 'wazuh',
      api_host        => 'wazuh.example.com',
      api_host_port   => 55000,
      agent_name      => $current_name,
      require         => Wazuh::Utils::Agent_actions["${current_name}_stop"],
    }
    
    # reauth with a brand new name
    wazuh::utils::local_agent_name { $new_name:
      agent_name       => $new_name,
      auth_server_name => 'wazuh.example.com',
      auth_password    => 'changeme',
      require          => Wazuh::Utils::Api_remove_agent[$current_name],
    }
    
    # start the service again
    wazuh::utils::agent_actions { "${new_name}_start":
      action  => start,
      require => Wazuh::Utils::Local_agent_name[$new_name],
      notify  => Notify["new wazuh name fact: ${facts['wazuh']['agent']['name']}"]
    }

  }

  notify { "new wazuh name fact: ${facts['wazuh']['agent']['name']}": }
}
