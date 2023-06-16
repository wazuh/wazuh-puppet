control 'wazuh-manager' do
  title 'Wazuh manager tests'
  describe 'Checks Wazuh manager correct version, services and daemon ownership'

  describe package('wazuh-manager') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '4.4.4-1' }
  end

  # Verifying service
  describe service('wazuh-manager') do
    it { is_expected.to be_installed }
    it { is_expected.to be_enabled }
    it { is_expected.to be_running }
  end

  # Verifying daemons
  wazuh_daemons = {
    'wazuh-authd' => 'root',
    'wazuh-execd' => 'root',
    'wazuh-analysisd' => 'wazuh',
    'wazuh-syscheckd' => 'root',
    'wazuh-remoted' => 'wazuh',
    'wazuh-logcollector' => 'root',
    'wazuh-monitord' => 'wazuh',
    'wazuh-db' => 'wazuh',
    'wazuh-modulesd' => 'root',
  }

  wazuh_daemons.each do |key, value|
    describe processes(key) do
      its('users') { is_expected.to eq [value] }
    end
  end
end
