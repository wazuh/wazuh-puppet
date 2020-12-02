require 'json'
require 'puppet'
require 'puppet/util/execution'


Facter.add('kibana_plugin_wazuh') do
  setcode do
    # move this to hiera
    wazuh_package_path = '/usr/share/kibana/plugins/wazuh/package.json'
    f = File.read(wazuh_package_path)
    kibana_plugin_wazuh = JSON.parse(f)
    kibana_plugin_wazuh
  end
end
