require 'spec_helper'

describe 'wazuh::agent_config_profile' do
  {
    ['Ubuntu', '22.04']       => 'ubuntu, ubuntu22, ubuntu22.04',
    ['Ubuntu', '24.04']       => 'ubuntu, ubuntu24, ubuntu24.04',
    ['RedHat', '9.7']         => 'rhel, rhel9, rhel9.7',
    ['RedHat', '9.0']         => 'rhel, rhel9',
    ['RedHat', '9.8']         => 'rhel, rhel9, rhel9.8',
    ['AlmaLinux', '9.8']      => 'almalinux, almalinux9, almalinux9.8',
    ['Fedora', '41']          => 'fedora, fedora41',
    ['SLES', '15.5']          => 'sles, sles15, sles15.5',
    ['Ubuntu', '']            => 'ubuntu',
    ['Rocky', '9.3']          => 'rocky, rocky9, rocky9.3',
    ['OracleLinux', '9.8']    => 'ol, ol9, ol9.8',
    ['CentOS', '9']           => 'centos, centos9',
    ['Amazon', '2']           => 'amzn, amzn2',
    ['Amazon', '2023.0']      => 'amzn, amzn2023',
    ['openSUSE', '15.4']      => 'opensuse-leap, opensuse-leap15, opensuse-leap15.4',
    ['Debian', 'n/a']         => 'debian',
  }.each do |(name, full), profile|
    context "with #{name} #{full}" do
      it { is_expected.to run.with_params(name, full).and_return(profile) }
    end
  end

  context 'with Debian, which uses the major version only' do
    it { is_expected.to run.with_params('Debian', '12.9', '12').and_return('debian, debian12') }
    it { is_expected.to run.with_params('Debian', '13.0', '13').and_return('debian, debian13') }
    it { is_expected.to run.with_params('Debian', '11.11', '11').and_return('debian, debian11') }
  end

  context 'with os_name undef' do
    it { is_expected.to run.with_params(:undef).and_return(nil) }
  end

  context 'with Windows' do
    it { is_expected.to run.with_params('windows', '2022', '2022').and_return(nil) }
  end
end
