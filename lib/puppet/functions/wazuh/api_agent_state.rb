# frozen_string_literal: true
#
# @summary A custom fact to check the status of an agent on the manager side
#
# @author Kibahop <petri.lammi@puppeteers.net>
#
Puppet::Functions.create_function(:'wazuh::api_agent_state') do

  dispatch :api_agent_state do
    param 'Hash', :config
    return_type 'String'
  end

def token_uri(config)
    URI("https://#{config['api_host']}:#{config['api_host_port']}/security/user/authenticate")
  end

  def agent_id_uri(config)
    URI("https://#{config['api_host']}:#{config['api_host_port']}/agents?name=#{config['agent_name']}")
  end

  def agent_info_uri(config, id)
    URI("https://#{config['api_host']}:#{config['api_host_port']}/agents?agents_list=#{id}&status=#{config['agent_status']}&older_than=0")
  end

  def get_token(config)
    uri = token_uri(config)

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Get.new(uri)
    request.basic_auth(config['api_username'], config['api_password'])

    begin
      response = http.request(request)
      token = JSON.parse(response.body)&.dig('data','token')
    rescue StandardError => e
      error_message = "Failed to retrieve token: #{e.message}"
      Puppet.err(error_message)
      fail(error_message)
    end
  end

  def get_agent_id_by_name(config, token)
    uri = agent_id_uri(config)
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{token}" }

    begin
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
        req = Net::HTTP::Get.new(uri, headers)
        http.request(req)
      end
    rescue StandardError => e
      Puppet.err("Failed to retrieve agent id: #{e.message}")
      raise e
    end

    status = JSON.parse(res.body)&.dig('data', 'affected_items', 0, 'status')
    if res.code == '200'
      return status
    else
      return nil
    end
  end

  def api_agent_state(config)
    begin
      token = get_token(config)
      agent_state = get_agent_id_by_name(config, token)
      return agent_state
    rescue StandardError => e
      Puppet.err("Failed to get agent state: #{e.message}")
      return nil
    end
  end
end

