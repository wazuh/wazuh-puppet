class local_profile::wazuh_actions {

  wazuh::utils::agent_actions { 'start_wazuh_service':
    action => start,
  }

  wazuh::utils::agent_actions { 'stop_wazuh_service':
    action => stop,
    require =>  Wazuh::Utils::Agent_actions['start_wazuh_service'],
  }

  wazuh::utils::agent_actions { 'disable_wazuh_service':
    action => disable,
    require =>  Wazuh::Utils::Agent_actions['start_wazuh_service'],
  }
  
  wazuh::utils::agent_actions { 'enable_wazuh_service':
    action => enable,
    require =>  Wazuh::Utils::Agent_actions['disable_wazuh_service'],
  }

  wazuh::utils::agent_actions { 'restart_wazuh_service':
    action => restart,
    require => Wazuh::Utils::Agent_actions['enable_wazuh_service'],
  }
}

