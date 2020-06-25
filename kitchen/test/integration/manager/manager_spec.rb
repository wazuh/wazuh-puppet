describe package('wazuh-manager') do
  it { should be_installed }
  its('version') { should eq '3.13.0-1' }
end

describe service('wazuh-manager') do
  it { should be_installed }
  it { should be_enabled }
  it { should be_running }
end

# Verifying daemons

wazuh_daemons = {
                  "ossec-authd" => "root",
                  "ossec-execd" => "root",
                  "ossec-analysisd" => "ossec",
                  "ossec-syscheckd" => "root",
                  "ossec-remoted" => "ossecr",
                  "ossec-logcollector" => "root",
                  "ossec-monitord" => "ossec",
                  "wazuh-db" => "ossec",
                  "wazuh-modulesd" => "root"
                }
wazuh_daemons.each do |key, value|

  describe processes(key) do
    its('users') { should eq [value] }
  end

end
