require 'spec_helper'

# The <config-profile> of ossec.conf must match the one the Wazuh agent package
# generates. The facterdb facts are fixed by hand because they lack the Ubuntu
# minor version and the real release.
describe 'wazuh::agent' do
  let(:params) { { wazuh_register_endpoint: 'manager', wazuh_reporting_endpoint: 'manager' } }

  def facts_for(base_os, base_release, name, full, major)
    base = on_supported_os(supported_os: [{ 'operatingsystem' => base_os, 'operatingsystemrelease' => [base_release] }]).values.first
    base.merge(concat_basedir: '/dummy').merge(
      os: base[:os].merge('name' => name, 'release' => { 'full' => full, 'major' => major }),
    )
  end

  context 'on Ubuntu 22.04' do
    let(:facts) { facts_for('Ubuntu', '22.04', 'Ubuntu', '22.04', '22.04') }

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>}) }

    context 'with ossec_config_ubuntu_profiles' do
      let(:params) { super().merge(ossec_config_ubuntu_profiles: 'ubuntu, custom') }

      it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>ubuntu, custom</config-profile>}) }
    end

    context 'with an empty ossec_config_ubuntu_profiles' do
      let(:params) { super().merge(ossec_config_ubuntu_profiles: '') }

      # pick_default ignores the empty string
      it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>}) }
    end

    context 'with ossec_config_centos_profiles only' do
      let(:params) { super().merge(ossec_config_centos_profiles: 'centos, custom') }

      it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>}) }
    end
  end

  context 'on RedHat 9.8' do
    let(:facts) { facts_for('RedHat', '9', 'RedHat', '9.8', '9') }

    it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>rhel, rhel9, rhel9.8</config-profile>}) }

    context 'with ossec_config_ubuntu_profiles' do
      let(:params) { super().merge(ossec_config_ubuntu_profiles: 'ubuntu, custom') }

      it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>rhel, rhel9, rhel9.8</config-profile>}) }
    end
  end

  context 'on Debian 12' do
    let(:facts) { facts_for('Debian', '12', 'Debian', '12.9', '12') }

    it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>debian, debian12</config-profile>}) }
  end

  # facterdb has no CentOS 7 facts: RedHat 8 ones renamed
  context 'on CentOS 7.9' do
    let(:facts) { facts_for('RedHat', '8', 'CentOS', '7.9', '7') }

    it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>centos, centos7, centos7.9</config-profile>}) }

    context 'with ossec_config_centos_profiles' do
      let(:params) { super().merge(ossec_config_centos_profiles: 'centos, custom') }

      it { is_expected.to contain_concat_fragment('ossec.conf_agent').with_content(%r{<config-profile>centos, custom</config-profile>}) }
    end
  end

  # wazuh::params_agent leaves variables undefined on Windows, which strict_variables rejects
  context 'on Windows' do
    before { Puppet[:strict_variables] = false }

    let(:facts) do
      on_supported_os(supported_os: [{ 'operatingsystem' => 'windows', 'operatingsystemrelease' => ['2022'] }]).values.first.merge(concat_basedir: '/dummy')
    end

    it { is_expected.to contain_concat_fragment('ossec.conf_agent').without_content(%r{config-profile}) }
  end
end
