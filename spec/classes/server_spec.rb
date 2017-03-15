require 'spec_helper'
describe 'wazuh::server' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let (:facts) do
        facts.merge({ :concat_basedir => '/dummy' })
      end
      context 'with defaults for all parameters' do
        it do
          expect { is_expected.to compile.with_all_deps }.to raise_error(/Must pass smtp_server/)
        end
      end
      context 'with valid paramaters' do
        let (:params) do
          {
            :smtp_server => '127.0.0.1',
            :ossec_emailto => 'root@localhost.localdomain',
          }
        end
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('wazuh::server') }
      end
    end
  end
end
