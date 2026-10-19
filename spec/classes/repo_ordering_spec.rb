require 'spec_helper'

# Wazuh component packages must be installed after wazuh::repo has configured
# the repository (and, on Debian, run apt-get update) when both are declared,
# whatever the order in which the classes are declared.
components = {
  'wazuh::agent'        => { package: 'wazuh-agent',     params: { wazuh_register_endpoint: 'manager', wazuh_reporting_endpoint: 'manager' } },
  'wazuh::manager'      => { package: 'wazuh-manager',   params: {} },
  'wazuh::indexer'      => { package: 'wazuh-indexer',   params: {} },
  'wazuh::dashboard'    => { package: 'wazuh-dashboard', params: {} },
  'wazuh::filebeat_oss' => { package: 'filebeat',        params: {} },
}

supported_os = [
  { 'operatingsystem' => 'Ubuntu', 'operatingsystemrelease' => ['20.04', '22.04', '24.04'] },
  { 'operatingsystem' => 'Debian', 'operatingsystemrelease' => ['11', '12'] },
  { 'operatingsystem' => 'RedHat', 'operatingsystemrelease' => ['8', '9'] },
  { 'operatingsystem' => 'Rocky',  'operatingsystemrelease' => ['8', '9'] },
]

# Guard: on_supported_os silently drops releases missing from facterdb, which
# would shrink the matrix without any failure.
describe 'wazuh::repo' do
  it 'finds facterdb facts for every OS release of the matrix' do
    expected = supported_os.flat_map { |os| os['operatingsystemrelease'].map { |release| [os['operatingsystem'], release] } }
    found = on_supported_os(supported_os: supported_os).values.map { |facts| [facts[:os]['name'], facts[:os]['release']['major']] }
    expect(found).to match_array(expected)
  end
end

components.each do |component, data|
  describe component do
    let(:params) { data[:params] }

    on_supported_os(supported_os: supported_os).each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts.merge(concat_basedir: '/dummy') }

        context 'with wazuh::repo declared before' do
          let(:pre_condition) { "class { 'wazuh::repo': }" }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_package(data[:package]) }

          if os_facts[:os]['family'] == 'Debian'
            it { is_expected.to contain_class('wazuh::repo').that_comes_before("Package[#{data[:package]}]") }
            it { is_expected.to contain_exec('apt-update').that_comes_before("Package[#{data[:package]}]") }
            # The packages declared by wazuh::repo itself must not be captured (dependency cycle)
            it { is_expected.to contain_package('apt-transport-https') }
          else
            it { is_expected.to contain_yumrepo('wazuh').that_comes_before("Package[#{data[:package]}]") }
            it { is_expected.not_to contain_exec('apt-update') }
          end
        end

        context 'with wazuh::repo declared after' do
          let(:post_condition) { "class { 'wazuh::repo': }" }

          it { is_expected.to compile.with_all_deps }

          if os_facts[:os]['family'] == 'Debian'
            it { is_expected.to contain_exec('apt-update').that_comes_before("Package[#{data[:package]}]") }
          else
            it { is_expected.to contain_yumrepo('wazuh').that_comes_before("Package[#{data[:package]}]") }
            it { is_expected.not_to contain_exec('apt-update') }
          end
        end

        context 'without wazuh::repo' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_package(data[:package]) }
          it { is_expected.not_to contain_exec('apt-update') }
        end
      end
    end
  end
end
