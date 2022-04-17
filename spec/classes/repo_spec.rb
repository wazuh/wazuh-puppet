require 'spec_helper'

describe 'wazuh::repo' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      if os_facts[:os]['kernel'] == 'Linux'
        it { is_expected.to compile }

        if os_facts[:os]['family'] == 'RedHat'
          it {
            is_expected.to contain_yumrepo('wazuh').with(
              'descr'    => 'WAZUH OSSEC Repository - www.wazuh.com',
              'enabled'  => true,
              'gpgcheck' => '1',
            )
          }
        end

        describe 'Disable yumrepo' do
         let(:params) do
           {
              yumrepo_enabled: false,
           }
          end

          it {
            is_expected.to contain_yumrepo('wazuh').with(
              'descr'    => 'WAZUH OSSEC Repository - www.wazuh.com',
              'enabled'  => true,
              'gpgcheck' => '1',
            )
          }
        end
      end
    end
  end
end
