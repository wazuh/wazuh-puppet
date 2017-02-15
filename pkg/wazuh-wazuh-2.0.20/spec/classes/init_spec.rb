require 'spec_helper'
describe 'ossec' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let (:facts) { facts }
      context 'with defaults for all parameters' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('ossec') }
      end
    end
  end
end
