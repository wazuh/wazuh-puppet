# frozen_string_literal: true

#
# @summary A Puppet provider for performing actions on the Wazuh agent
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
Puppet::Type.type(:agent_action).provide(:ruby) do
  desc 'Provider for managing agent actions'

  mk_resource_methods

  def refresh=(value)
    command = generate_command(value)
    return if command.nil?

    Puppet.debug("Executing command: #{command}")
    system(command)
  end

  def action=(value)
    command = generate_command(value)
    return if command.nil?

    Puppet.debug("Executing command: #{command}")
    system(command)
  end

  private

  def generate_command(action)
    actions = {
      start: 'systemctl is-active --quiet wazuh-agent.service || systemctl start wazuh-agent.service',
      stop: 'systemctl is-active --quiet wazuh-agent.service && systemctl stop wazuh-agent.service',
      restart: 'systemctl is-active --quiet wazuh-agent.service && systemctl restart wazuh-agent.service',
      disable: 'systemctl is-enabled --quiet wazuh-agent.service && systemctl stop wazuh-agent.service && systemctl disable wazuh-agent.service',
      enable: 'systemctl is-enabled --quiet wazuh-agent.service || systemctl enable wazuh-agent.service && systemctl start wazuh-agent.service'
    }

    command = actions[action.to_sym]
    if command.nil?
      raise Puppet::Error, "Invalid action specified: #{action}. Valid values are 'start', 'stop', 'restart', 'enable', and 'disable'."
    end

    command
  end
end
