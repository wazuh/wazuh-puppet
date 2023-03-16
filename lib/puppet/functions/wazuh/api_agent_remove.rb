# frozen_string_literal: true

#
# @summary A custom fact to remove a Wazuh agent via API.
#
# @author Kibahop <petri.lammi@puppeteers.net>
#
require_relative 'apihelper'

Puppet::Functions.create_function(:'wazuh::api_agent_remove') do
  dispatch :api_agent_remove do
    param 'Hash', :config
  end

  def api_agent_remove(config)
    api_helper = ApiHelper.new(config)
    api_helper.agent_remove
  end
end
