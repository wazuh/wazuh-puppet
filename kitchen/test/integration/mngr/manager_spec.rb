describe package('wazuh-manager') do
  it { is_expected.to be_installed }
  its('version') { is_expected.to eq '4.0.0-1' }
end

describe service('wazuh-manager') do
  it { is_expected.to be_installed }
  it { is_expected.to be_enabled }
  it { is_expected.to be_running }
end

# Verifying daemons

wazuh_daemons = {
  'ossec-authd' => 'root',
  'ossec-execd' => 'root',
  'ossec-analysisd' => 'ossec',
  'ossec-syscheckd' => 'root',
  'ossec-remoted' => 'ossecr',
  'ossec-logcollector' => 'root',
  'ossec-monitord' => 'ossec',
  'wazuh-db' => 'ossec',
  'wazuh-modulesd' => 'root',
}

wazuh_daemons.each do |key, value|
  describe processes(key) do
    its('users') { is_expected.to eq [value] }
  end
end

