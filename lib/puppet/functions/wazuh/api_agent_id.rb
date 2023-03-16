# frozen_string_literal: true

#
# @summary A custom fact to check the status of an agent on the manager side
#
# @author Kibahop <petri.lammi@puppeteers.net>
#
require_relative 'apihelper'

Puppet::Functions.create_function(:'wazuh::api_agent_id') do
  dispatch :api_agent_id do
    param 'Hash', :config
    return_type 'String'
  end

  def api_agent_id(config)
    Puppet.debug(:config)
    api_helper = ApiHelper.new(config)
    api_helper.agent_id
  end
end
