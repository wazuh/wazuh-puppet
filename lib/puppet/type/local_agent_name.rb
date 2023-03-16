# frozen_string_literal: true

#
# @summary A Puppet type for changing wazuh agent properties
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
Puppet::Type.newtype(:local_agent_name) do
  @doc = 'Custom resource change wazuh agent properties.'

  ensurable do
    desc 'Change wazuh agent properties'

    newvalue(:present) do
      provider.create
    end

    defaultto :present
  end

  def pre_run_check
    return if File.exist?('/var/ossec/etc/ossec.conf')

    raise Puppet::ResourceError, 'No ossec configuration file, no changes'
  end

  newparam(:name) do
    desc 'The name itself'
    isnamevar
  end

  newproperty(:enrollment_port) do
    desc 'The server enrollment port'
    defaultto 1515
  end

  newproperty(:communication_port) do
    desc 'The server communication port'
    defaultto 1514
  end

  newproperty(:agent_name) do
    desc 'The name of the agent'
    validate do |value|
      unless value =~ %r{^[\w.-]+$}
        raise ArgumentError, "#{agent_name} must contain only letters, digits, '_', '-', and '.'"
      end
    end
  end

  newproperty(:auth_server_name) do
    desc 'Auth server name'
    validate do |value|
      unless value =~ %r{^[\w.-]+$}
        raise ArgumentError, "#{auth_server_name} must contain only letters, digits, '_', '-', and '.'"
      end
    end
  end

  # FIXME: disallow empty string
  newproperty(:auth_password) do
    desc 'Auth password to authenticate to the server'
  end
end
