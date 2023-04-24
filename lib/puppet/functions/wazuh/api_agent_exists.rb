# frozen_string_literal: true

#
# @summary A custom function to check the existense of an agent
#
# @author Kibahop <petri.lammi@puppeteers.net>
#
require_relative 'apihelper'

Puppet::Functions.create_function(:'wazuh::api_agent_exists') do
  dispatch :api_agent_exists? do
    param 'Hash', :config
    return_type 'Boolean'
  end

  def api_agent_exists?(config)
    api_helper = ApiHelper.new(config)
    api_helper.agent_exists?
  end
end
