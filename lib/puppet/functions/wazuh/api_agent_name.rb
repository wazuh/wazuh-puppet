# frozen_string_literal: true

#
# @summary A custom fact to check the status of an agent on the manager side
#
# @author Kibahop <petri.lammi@puppeteers.net>
#
require_relative 'apihelper'

Puppet::Functions.create_function(:'wazuh::api_agent_name') do
  dispatch :api_agent_name do
    param 'Hash', :config
    return_type 'String'
  end

  def api_agent_name(config)
    Puppet.debug(:config)
    api_helper = ApiHelper.new(config)
    api_helper.agent_name
  end
end
