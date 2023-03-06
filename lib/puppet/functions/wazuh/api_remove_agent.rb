# frozen_string_literal: true
#
# @summary A custom fact to remove a Wazuh agent via API. Targeted to be run on a Puppet server.
#
# @author Kibahop <petri.lammi@puppeteers.net>
#
Puppet::Functions.create_function(:'wazuh::api_remove_agent') do

  dispatch :remove_remote_agent do
    param 'Hash', :config
  end

  def token_uri(config)
    URI("https://#{config['api_host']}:#{config['api_host_port']}/security/user/authenticate")
  end

  def agent_id_uri(config)
    URI("https://#{config['api_host']}:#{config['api_host_port']}/agents?name=#{config['agent_name']}")
  end

  def delete_agent_uri(config, id)
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
    rescue StandardError => e
      Puppet.err("Failed to retrieve token: #{e.message}")
    end
    token = JSON.parse(response.body)&.dig('data','token')
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
    end

    id = JSON.parse(res.body)&.dig('data', 'affected_items', 0, 'id')
    if res.code == '200'
      return id.nil? ? nil : id
    end
  end
  
  def remove_agent(config, id, token)
    uri = delete_agent_uri(config, id)
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{token}" }

    begin
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
        req = Net::HTTP::Delete.new(uri, headers)
        http.request(req)
      end
    rescue StandardError => e
      Puppet.err("Error: #{e.message}")
    end
    
    if res.code == '200'
      Puppet.notice("Agent #{config['agent_name']}, id #{id} successfully removed from Wazuh server.")
    else
      Puppet.err("Failed to remove agent #{config['agent_name']}, id #{id} from Wazuh server. HTTP status code: #{res.code}")
    end
  end
  
  def remove_remote_agent(config)
    token = get_token(config)
    agent_id = get_agent_id_by_name(config, token)
    unless agent_id.nil?
      remove_agent(config, agent_id, token)
    end
  end
end
