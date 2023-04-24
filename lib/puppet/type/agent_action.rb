# frozen_string_literal: true

#
# @summary A Puppet type for performing actions on the Wazuh agent
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
Puppet::Type.newtype(:agent_action) do
  @doc = 'A custom Puppet resource type for agent actions.'

  def pre_run_check
    return if File.exist?('/var/ossec/etc/ossec.conf')

    raise Puppet::Error, 'No Wazuh, no catalog.'
  end

  newparam(:agent_name) do
    desc 'Just here for itself'
    isnamevar
  end

  newproperty(:action) do
    desc "The action to perform on the agent (service). Valid values are 'start', 'stop', 'restart', and 'clean'."
    newvalues(:start, :stop, :restart, :disable, :enable)
  end
end
