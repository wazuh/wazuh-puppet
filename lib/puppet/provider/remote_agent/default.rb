# frozen_string_literal: true

Puppet::Type.type(:remote_agent).provide(:ruby) do

  require 'open3'
  require 'net/http'

  def token_uri
    URI("https://#{@resource[:api_host]}:#{@resource[:api_host_port]}/security/user/authenticate")
  end

  def agent_id_uri(name)
    URI("https://#{@resource[:api_host]}:#{@resource[:api_host_port]}/agents?name=#{name}")
  end

  def delete_agent_uri(id)
    URI("https://#{@resource[:api_host]}:#{@resource[:api_host_port]}/agents?agents_list=#{id}&status=#{@resource[:status]}&older_than=0")
  end

  def get_token
    uri = token_uri

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Get.new(uri)
    request.basic_auth(resource[:api_username], resource[:api_password])

    response = http.request(request)
    token = JSON.parse(response.body)['data']['token']
  end
  
  def get_agent_id_by_name(name, token)
    uri = agent_id_uri(name)
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{token}" }

    res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      req = Net::HTTP::Get.new(uri, headers)
      http.request(req)
    end

    id = JSON.parse(res.body)['data']['affected_items'][0]['id']
    return id unless id.nil?
  end

  def delete_agent(id, token)
    uri = delete_agent_uri(id)
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{token}" }

    res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      req = Net::HTTP::Delete.new(uri, headers)
      http.request(req)
    end

    res
  end

  def token
    @token ||= get_token.chomp
  end

  def agent_id
    @agent_id ||= get_agent_id_by_name(@resource[:name], token)
  end

  def exists?
    !!agent_id rescue false
  end

  def create
    pass
  end

  def destroy
    delete_agent(agent_id, token)
  end
end
