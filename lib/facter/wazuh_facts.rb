#
# @summary Produces a structured wazuh fact
#
# @author Petri Lammi petri.lammi@puppeteers.net
#
# @example
#
# notify { $facts['wazuh']['state']['status']: }
#
Facter.add(:wazuh) do

  confine :kernel => 'Linux'
  confine :ossec_conf_exists => true

  setcode do
    
    @keyfile = String.new('/var/ossec/etc/client.keys')
    
    def wazuh_agent_data(index)
      if File.exist?(@keyfile)
        File.read(@keyfile).split[index]
      else
        nil
      end
    end
    
    wazuh_agent_id = wazuh_agent_data(0)
    wazuh_agent_name = wazuh_agent_data(1)
    wazuh_agent_ip = wazuh_agent_data(2)
    wazuh_agent_key = wazuh_agent_data(3)
    
    def wazuh_agent_version
      cmd = String.new
      case Facter.value('osfamily')
      when 'RedHat'
        cmd = '/bin/rpm -q wazuh-agent --queryformat "%{VERSION}"'
      when 'Debian'
        cmd = '/usr/bin/dpkg-query -W -f="\\${Version}" wazuh-agent'
      end
      Facter::Core::Execution.execute(cmd)
    end
    
    wazuh_agent_hash = {
      id: wazuh_agent_id,
      name: wazuh_agent_name,
      ip_address: wazuh_agent_ip,
      key: wazuh_agent_key,
      version: wazuh_agent_version
    }
    
    def get_ossec_conf_value(key)
      if File.exist?(@keyfile)
        IO.readlines('/var/ossec/etc/ossec.conf').grep(/^.*<#{key}>/).map { |line|
          line.match(/^.*<#{key}>(.*)<\/#{key}>/)&.captures&.first&.strip
        }.compact.first
      else nil
      end
    end
    
    def wazuh_server_name
      get_ossec_conf_value('address')
    end
  
    wazuh_server_hash = {
      name: wazuh_server_name,
    }
    
    wazuh_state_hash = {}
    state_file_path = '/var/ossec/var/run/wazuh-agentd.state'
    if File.exist?(state_file_path)
      File.foreach(state_file_path) do |line|
        key, value = line.strip.split('=')
        case key
        when 'last_keepalive'
          # calculate seconds since last keepalive
          seconds_since_keepalive = (Time.now - Time.parse(value)).to_i
          wazuh_state_hash['last_keepalive_since'] = seconds_since_keepalive
        when 'last_ack'
          # calculate seconds since last ack
          seconds_since_ack = (Time.now - Time.parse(value)).to_i
          wazuh_state_hash['last_ack_since'] = seconds_since_ack
        when 'status'
          wazuh_state_hash['status'] = value
        end
      end
    end
    
    wazuh_hash = {
      agent: wazuh_agent_hash,
      server: wazuh_server_hash,
      state: wazuh_state_hash
    }
    
    wazuh_hash
  end
end
