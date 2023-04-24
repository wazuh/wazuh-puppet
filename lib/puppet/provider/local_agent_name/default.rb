# frozen_string_literal: true

#
# @summary A Puppet provider for changing wazuh agent properties
#
# @author Kibahop petri.lammi@puppeteers.net
#
Puppet::Type.type(:local_agent_name).provide(:ruby) do
  desc 'Provider for managing agent changes'

  mk_resource_methods

  def keyfile
    @keyfile = '/var/ossec/etc/client.keys' if File.exist?('/var/ossec/etc/client.keys')
  end

  def authdfile
    @authdfile ||= '/var/ossec/etc/authd.pass'
  end

  def enrollment_port_file
    @enrollment_port_file ||= '/var/ossec/etc/.enrollment_port'
  end

  def ossec_conf_file
    @ossec_conf_file ||= '/var/ossec/etc/ossec.conf'
  end

  def current_auth_password
    @current_password ||= File.read(authdfile).chomp if File.exist?(authdfile)
  end

  def auth_password
    @auth_password ||= resource[:auth_password].chomp
    if @auth_password != current_auth_password
      File.write(authdfile, @auth_password)
    end
    @auth_password
  end

  def current_auth_password_hash
    @current_auth_password_hash ||= Digest::SHA256.hexdigest(current_auth_password)
  end

  def auth_password_hash
    @auth_password_hash ||= Digest::SHA256.hexdigest(auth_password)
  end

  def current_agent_name
    @current_name ||= File.read(keyfile).split[1].chomp if File.exist?(keyfile)
  end

  def agent_name
    @agent_name ||= resource[:agent_name].chomp
  end

  def get_ossec_conf_value(key)
    if File.exist?(ossec_conf_file)
      values = IO.readlines(ossec_conf_file).grep(%r{^.*<#{key}>}).map { |line|
        match = line.match(%r{^.*<#{key}>(.*)</#{key}>})
        match ? match.captures.first.strip : nil
      }.compact
      values.empty? ? nil : values.first
    else
      nil
    end
  end

  def current_auth_server_name
    @current_auth_server_name ||= get_ossec_conf_value('address').chomp
  end

  def auth_server_name
    @auth_server_name ||= resource[:auth_server_name].chomp
  end

  def current_enrollment_port
    port = 0
    if File.exist?(enrollment_port_file)
      port = File.read(enrollment_port_file).chomp
    end
    @enrollment_port = port
    @enrollment_port
  end

  def enrollment_port
    @enrollment_port ||= resource[:enrollment_port]
    unless File.exist?(enrollment_port_file)
      File.write(enrollment_port_file, @enrollment_port)
    end
    @enrollment_port
  end

  def current_communication_port
    @current_communication_port ||= get_ossec_conf_value('port')
  end

  def communication_port
    @communication_port ||= resource[:communication_port]
  end

  def remove_keys_file
    File.delete(keyfile)
  end

  def reauthenticate
    wazuh_agent_auth = '/var/ossec/bin/agent-auth'
    auth_password
    agent = agent_name
    server = auth_server_name
    port = enrollment_port
    cmd = "#{wazuh_agent_auth} -A #{agent} -m #{server} -p #{port}"
    system(cmd)
  end

  def exists?
    (agent_name == current_agent_name) &&
      (auth_server_name == current_auth_server_name) &&
      (auth_password == current_auth_password) &&
      (communication_port == current_communication_port) &&
      (enrollment_port == current_enrollment_port)
  end

  def create
    reauthenticate
  end

  def destroy
    pass
  end
end
