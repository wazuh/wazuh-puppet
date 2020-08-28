describe package('wazuh-manager') do
  it { is_expected.to be_installed }
  its('version') { is_expected.to eq '3.13.1-1' }
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

describe service('filebeat') do
  it { is_expected.to be_installed }
  it { is_expected.to be_enabled }
  it { is_expected.to be_running }
end

describe service('elasticsearch') do
  it { is_expected.to be_installed }
  it { is_expected.to be_enabled }
  it { is_expected.to be_running }
end

describe service('kibana') do
  it { is_expected.to be_installed }
  it { is_expected.to be_enabled }
  it { is_expected.to be_running }
end

if os.family == 'debian'
  describe package('filebeat') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '7.8.0' }
  end
  
  describe package('opendistroforelasticsearch') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '1.9.0' }
  end
  
  describe package('opendistroforelasticsearch-kibana') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '1.9.0' }
  end
elsif os.family == 'redhat'
  describe package('filebeat') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '7.8.0-1' }
  end
  
  describe package('opendistroforelasticsearch') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '1.9.0-1' }
  end
  
  describe package('opendistroforelasticsearch-kibana') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '1.9.0-1' }
  end
end

describe http('http://localhost:9200') do
  its('status') { should cmp 200 }
end