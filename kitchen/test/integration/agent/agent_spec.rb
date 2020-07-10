describe package('wazuh-agent') do
  it { should be_installed }
  its('version') { should eq '3.13.0-1' }
end

describe service('wazuh-agent') do
  it { should be_installed }
  it { should be_enabled }
  it { should be_running }
end

# Verifying daemons

wazuh_daemons = {
                  'ossec-agentd' => 'ossec',
                  'ossec-execd' => 'root',
                  'ossec-syscheckd' => 'root',
                  'wazuh-modulesd' => 'root',
                }
wazuh_daemons.each do |key, value|

  describe processes(key) do
    its('users') { should eq [value] }
  end

end
