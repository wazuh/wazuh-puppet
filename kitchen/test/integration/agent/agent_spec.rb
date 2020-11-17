describe package('wazuh-agent') do
  it { is_expected.to be_installed }
  its('version') { is_expected.to eq '4.0.1-1' }
end

describe service('wazuh-agent') do
  it { is_expected.to be_installed }
  it { is_expected.to be_enabled }
  it { is_expected.to be_running }
end

# Verifying daemons

wazuh_daemons = {
  'ossec-agentd' => 'ossec',
  'ossec-execd' => 'root',
  'ossec-syscheckd' => 'root',
  'wazuh-modulesd' => 'root',
  'ossec-logcollector' => 'root',
}

wazuh_daemons.each do |key, value|
  describe processes(key) do
    it { should exist }
  end
end
