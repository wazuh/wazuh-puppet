control 'wazuh-manager' do
  title 'Wazuh manager tests'
  describe 'Checks Wazuh manager correct version, services and daemon ownership'

  describe package('wazuh-manager') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '4.0.3-1' }
  end

  # Verifying service
  describe service('wazuh-manager') do
    it { is_expected.to be_installed }
    it { is_expected.to be_enabled }
    it { is_expected.to be_running }
  end

  # Verifying daemons
  wazuh_daemons = {
    'ossec-authd' => 'root',
    'wazuh-execd' => 'root',
    'wazuh-analysisd' => 'ossec',
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
end
