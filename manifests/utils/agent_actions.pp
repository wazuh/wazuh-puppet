#
# @summary Perform an action for the Wazuh service 
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
define wazuh::utils::agent_actions(
  Enum['start', 'stop', 'restart', 'disable', 'enable'] $action,
){

  agent_action { $title:
    action => $action,
  }
}
