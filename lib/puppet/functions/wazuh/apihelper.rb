# frozen_string_literal: true

# @summary helper class
#
# @author Kibahop <petri.lammi@puppeteers.net>
#
# TODO: DRY, shorten methods
class ApiHelper
  require 'net/http'
  require 'json'

  def initialize(config)
    @config = config
    @api_host ||=  @config['api_host']
    @api_host_port ||= @config['api_host_port']
    @api_username ||= @config['api_username']
    @api_password ||= @config['api_password']
    @api_check_states = sanitize_uri_string(@config['api_check_states'])
    @token = retrieve_token
    return unless config['api_agent_name']

    @agent_name = config['api_agent_name']
  end

  attr_reader :agent_name

  def agent_id
    @agent_id ||= retrieve_agent_id
  end

  def agent_exists?
    id = agent_id
    if !id.nil? && (id != '000')
      true
    else
      false
    end
  end

  def agent_status
    status = retrieve_agent_status if agent_exists?
  end

  def agent_remove
    api_agent_remove if agent_exists? 
  end

  private

  def sanitize_uri_string(string)
    if string == 'all'
      ['active,pending,never_connected,disconnected']
    else
      string.gsub!(/\s+/, "")
      [string]
    end
  end
  
  def retrieve_token_uri
    Puppet.debug("in retrieve_token_uri")
    URI("https://#{@api_host}:#{@api_host_port}/security/user/authenticate")
  end

  def token_uri
    @token_uri ||= retrieve_token_uri
  end

  def retrieve_token
    Puppet.debug("in retrieve_token")
    uri = token_uri

    begin
      res = Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: true,
        verify_mode: OpenSSL::SSL::VERIFY_NONE,
      ) do |http|
        req = Net::HTTP::Get.new(uri.path.to_s)
        req.basic_auth(@api_username, @api_password)
        http.request(req)
      end
    rescue StandardError => e
      Puppet.err("WAZUH: Failed to retrieve agent token: #{e.message}")
    end

    if !res.code.nil? && (res.code == '200')
      begin
        data = JSON.parse(res.body)
        token = data['data']['token']
        (!token.nil?) ? token : nil
      rescue StandardError => e
        Puppet.warning("WAZUH: Failed to extract agent token - probably ok: #{e.message}")
      end
    else
      Puppet.err('WAZUH: error communicating with the server')
    end
  end

  def build_agent_uri(params = {})
    Puppet.debug("in build_agent_uri")
    query_params = params.empty? ? { 'name' => @agent_name } : params
    
    Puppet.err("query_params: #{query_params}")
    
    uri = URI("https://#{@api_host}:#{@api_host_port}/agents")
    uri.query = URI.encode_www_form(query_params)
    Puppet.err(uri.query)
    Puppet.err("in build_agent_uri: returning: #{uri}")
    uri
  end
  
  def retrieve_agent_id
    Puppet.err("in retrieve_agent_id")
    uri = build_agent_uri
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{@token}" }
    Puppet.err("retrieve_agent_id uri: #{uri}")
    begin
      res = Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: true,
        verify_mode: OpenSSL::SSL::VERIFY_NONE,
      ) do |http|
        req = Net::HTTP::Get.new(uri.request_uri, headers)
        http.request(req)
      end
    rescue StandardError => e
      Puppet.err("Wazuh: Error connecting to Wazuh API: #{e.message}")
      return nil
    end

    if !res.nil? && (res.code == '200')
      begin
        data = JSON.parse(res.body)
        data['data']['affected_items'][0]['id']
      rescue StandardError => e
        Puppet.warning("WAZUH: #{@agent_name} doesn't exist on the server #{@api_host} - probably ok: #{e.message}")
        nil
      end
    else
      Puppet.err("WAZUH: Unspecific response error from server #{@api_host} for #{@agent_name}")
      nil
    end
  end

  def retrieve_agent_status
    Puppet.err("in retrieve_agent_status")
    status_params = {
      :agents_list => @agent_id,
      :older_than => 0
    }
    uri = build_agent_uri(params = status_params)
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{@token}" }
    Puppet.err("retrieve_agent_status uri: #{uri}")
    begin
      res = Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: true,
        verify_mode: OpenSSL::SSL::VERIFY_NONE,
      ) do |http|
        req = Net::HTTP::Get.new(uri.request_uri, headers)
        http.request(req)
      end
    rescue StandardError => e
      Puppet.err("WAZUH: Failed to retrieve agent status for #{@agent_name}/#{@agent_id}: #{e.message}")
      return 'not_found'
    end

    if res.code == '200'
      begin
        data = JSON.parse(res.body)
        status = data['data']['affected_items'][0]['status']
        return !status.nil? ? status : nil
      rescue StandardError => e
        Puppet.err("WAZUH: Failed to extract agent status from data: #{e.message}")
      end
    end
  end

  def api_agent_remove
    remove_params = {
      :agents_list =>  @agent_id,
      :status => @api_check_states,
      :older_than => 0
    }

    uri = build_agent_uri(params = remove_params)
    Puppet.err("api_agent_remove: uri: #{uri}")
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{@token}" }

    begin
      res = Net::HTTP.start(
        uri.host,
        uri.port,
        use_ssl: true,
        verify_mode: OpenSSL::SSL::VERIFY_NONE,
      ) do |http|
        req = Net::HTTP::Delete.new(uri.request_uri, headers)
        http.request(req)
      end
    rescue StandardError => e
      Puppet.err("WAZUH: Failed to remove agent #{@agent_name} from server #{@api_host}: #{e.message} #{res.body}")
    end

    case res.code
    when '200'
      Puppet.info("WAZUH: agent #{@agent_name}, id #{@agent_id} successfully removed from Wazuh server.")
    when '400'
      Puppet.err("WAZUH: Failed to remove agent #{@agent_name}, agent_id #{@agent_id} from Wazuh server. HTTP status code: #{res.code}")
    else
      Puppet.err("WAZUH: Failed to remove agent #{@agen_name}: #{res.body}")
    end
  end
end
