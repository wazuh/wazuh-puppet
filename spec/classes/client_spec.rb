require 'spec_helper'
describe 'wazuh::client' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let (:facts) do
        facts.merge({ :concat_basedir => '/dummy' })
      end
      context 'with defaults for all parameters' do
        it do
          expect { is_expected.to compile.with_all_deps }.to raise_error(/must pass either/)
        end
      end

      context 'with ossec_server_ip' do
        let (:params) do
          {
            :ossec_server_ip => '127.0.0.1',
          }
        end
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('wazuh::client') }
        it { is_expected.not_to contain_Concat__Fragment('ossec.conf_10').with_content(/<server-hostname>local.test<\/server-hostname>/) }
        it { is_expected.to contain_Concat__Fragment('ossec.conf_10').with_content(/<server-ip>127.0.0.1<\/server-ip>/) }
      end

      context 'with ossec_server_hostname' do
        let (:params) do
          {
            :ossec_server_hostname => 'local.test',
          }
        end
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('wazuh::client') }
        it { is_expected.not_to contain_Concat__Fragment('ossec.conf_10').with_content(/<server-ip>127.0.0.1<\/server-ip>/) }
        it { is_expected.to contain_Concat__Fragment('ossec.conf_10').with_content(/<server-hostname>local.test<\/server-hostname>/) }
      end
    end
  end
end
