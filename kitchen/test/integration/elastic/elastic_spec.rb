describe package('elasticsearch') do
  it { is_expected.to be_installed }
  its('version') { is_expected.to eq '7.8.1' }
end

describe service('elasticsearch') do
  it { is_expected.to be_installed }
  it { is_expected.to be_enabled }
  it { is_expected.to be_running }
end

describe package('filebeat') do
  it { is_expected.to be_installed }
  its('version') { is_expected.to eq '7.8.1' }
end

describe service('filebeat') do
  it { is_expected.to be_installed }
  it { is_expected.to be_enabled }
  it { is_expected.to be_running }
end

describe package('kibana') do
  it { is_expected.to be_installed }
  its('version') { is_expected.to eq '7.8.1' }
end

describe service('kibana') do
  it { is_expected.to be_installed }
  it { is_expected.to be_enabled }
  it { is_expected.to be_running }
end

