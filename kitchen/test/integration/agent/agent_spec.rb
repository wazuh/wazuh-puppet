control 'wazuh-agent' do
  title 'Wazuh agent tests'
  describe 'Checks Wazuh agent correct version, services and daemon ownership'

  describe package('wazuh-agent') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '4.0.3-1' }
  end

  describe service('wazuh-agent') do
    it { is_expected.to be_installed }
    it { is_expected.to be_enabled }
    it { is_expected.to be_running }
  end

  # Verifying daemons
  wazuh_daemons = {
    # 'wazuh-agentd' => 'ossec',
    'wazuh-execd' => 'root',
    # 'wazuh-syscheckd' => 'root',
    # 'wazuh-modulesd' => 'root',
  }

  wazuh_daemons.each do |key, value|
    describe processes(key) do
      its('users') { is_expected.to eq [value] }
    end
  end
end
