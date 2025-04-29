# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include wazuh::param_install_package
class wazuh::param_install_package {
  String $package_name = undef,
  String $wazuh_version = '5.0.0',

  # OS specific configurations
  case $facts['kernel'] {
    'Linux': {
      $download_path = '/tmp'
      $package_list_path = '/tmp/packages_url.txt',
    }
    'windows': {
      $download_path = 'C:\\Temp'
      $package_msi_key = 'wazuh_agent_url_i386_msi',
      $package_list_path = 'C:/Windows/Temp/packages_url.txt',
      $msi_download_location = 'C:/Windows/Temp/wazuh-agent-installer.msi',
      Array[String] $install_options = ['/qn'],
      Boolean $cleanup_msi = true,
    }
  }
}
