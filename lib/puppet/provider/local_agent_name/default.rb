# frozen_string_literal: true
#
# @summary A Puppet provider for changing wazuh agent properties
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
Puppet::Type.type(:local_agent_name).provide(:ruby) do
  
  desc 'Provider for managing agent name'

  mk_resource_methods

  def keyfile
    @keyfile = '/var/ossec/etc/client.keys' if File.exists?('/var/ossec/etc/client.keys')
  end

  def authdfile
    @authdfile ||= '/var/ossec/etc/authd.pass'
  end

  def ossec_conf_file
    @ossec_conf_file ||= '/var/ossec/etc/ossec.conf'
  end

  def current_auth_password
    @current_password ||= File.read(authdfile).chomp if File.exist?(authdfile) 
  end

  def current_agent_name
    @current_name ||= File.read(keyfile).split[1].chomp if File.exist?(keyfile)
  end

  def get_ossec_conf_value(key)
    if File.exist?(ossec_conf_file)
      IO.readlines(ossec_conf_file).grep(/^.*<#{key}>/).map { |line|
        line.match(/^.*<#{key}>(.*)<\/#{key}>/)&.captures&.first&.strip
      }.compact.first
    else nil
    end
  end
  
  def current_auth_server_name
    @current_auth_server_name ||= get_ossec_conf_value('address').chomp
  end
  
  def agent_name
    @agent_name ||= resource[:agent_name].chomp
  end

  def auth_server_name
    @auth_server_name ||= resource[:auth_server_name].chomp
  end

  def auth_password
    @auth_password ||= resource[:auth_password].chomp
    if @auth_password != current_auth_password
      File.write(@auth_password, authdfile)
    end
    @auth_password
  end

  def enrollment_port
    @enrollment_port ||= resource[:enrollment_port]
  end
  
  def remove_keys_file
    File.delete(keyfile)
  end
  
  def reauthenticate
    wazuh_agent_auth = '/var/ossec/bin/agent-auth'
    auth_password
    agent = agent_name
    server = auth_server_name
    cmd = "#{wazuh_agent_auth} -A #{agent} -m #{server}"
    cmd += " -p #{enrollment_port}" unless enrollment_port == 1515
    system(cmd)
  end

  def exists?
    agent_name == current_agent_name &&
      auth_server_name == current_auth_server_name &&
      auth_password == current_auth_password &&
      enrollment_port == 1515
  end
  
  def create
    reauthenticate
  end
  
  def destroy
    pass
  end
end
