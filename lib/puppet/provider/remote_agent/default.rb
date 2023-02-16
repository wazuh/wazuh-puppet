Puppet::Type.type(:remote_agent).provide(:ruby) do

  require 'base64'
  require 'open3'
  require 'net/http'

  def token_uri
    Puppet.debug("In get_token")
    URI("https://#{@resource[:api_host]}:#{@resource[:api_host_port]}/security/user/authenticate")
  end

  def agent_id_uri(name)
    URI("https://#{@resource[:api_host]}:#{@resource[:api_host_port]}/agents?name=#{name}")
  end

  def delete_agent_uri(id)
    URI("https://#{@resource[:api_host]}:#{@resource[:api_host_port]}/agents?agents_list=#{id}&status=all&older_than=0")
  end

  def execute(command)
    stdout, stderr, status = Open3.capture3(command)
    raise "Command '#{command}' failed with exit code #{status.exitstatus}\nError message: #{stderr}" unless status.success?
    stdout.chomp
  end

  def get_token
    Puppet.debug("In get_token")
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
    Puppet.debug("In get_agent_id_by_name")
    uri = agent_id_uri(name)
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{token}" }
    res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      req = Net::HTTP::Get.new(uri, headers)
      http.request(req)
    end
    id = JSON.parse(res.body)['data']['affected_items'][0]['id']
    return id
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
    Puppet.debug("In agent_id")
    @agent_id ||= get_agent_id_by_name(resource[:name], token)
  end

  def delete
    delete_agent(agent_id, token)
  end

  def exists?
    # We assume the agent doesn't exist if we can't get the ID
    Puppet.debug("In exist")
    #!!agent_id rescue false
    agent_id
  end

  def destroy
    Puppet.debug("In destroy")
    if exists?
      delete_agent(agent_id, token)
      #@property_hash[:ensure] = :absent
    end
  end
end
