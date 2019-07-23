# run a test task
require 'spec_helper_acceptance'

describe 'apt tasks', if: pe_install? && puppet_version =~ %r{(5\.\d\.\d)} && fact_on(master, 'osfamily') == 'Debian' do
  describe 'update' do
    it 'updates package lists' do
      result = run_task(task_name: 'apt', params: 'action=update')
      expect_multiple_regexes(result: result, regexes: [%r{Reading package lists}, %r{Job completed. 1/1 nodes succeeded}])
    end
  end
  describe 'upgrade' do
    it 'upgrades packages' do
      result = run_task(task_name: 'apt', params: 'action=upgrade')
      expect_multiple_regexes(result: result, regexes: [%r{\d+ upgraded, \d+ newly installed, \d+ to remove and \d+ not upgraded}, %r{Job completed. 1/1 nodes succeeded}])
    end
  end
  describe 'dist-upgrade' do
    it 'dist-upgrades packages' do
      result = run_task(task_name: 'apt', params: 'action=dist-upgrade')
      expect_multiple_regexes(result: result, regexes: [%r{\d+ upgraded, \d+ newly installed, \d+ to remove and \d+ not upgraded}, %r{Job completed. 1/1 nodes succeeded}])
    end
  end
  describe 'autoremove' do
    it 'autoremoves obsolete packages' do
      result = run_task(task_name: 'apt', params: 'action=autoremove')
      expect_multiple_regexes(result: result, regexes: [%r{\d+ upgraded, \d+ newly installed, \d+ to remove and \d+ not upgraded}, %r{Job completed. 1/1 nodes succeeded}])
    end
  end
end
