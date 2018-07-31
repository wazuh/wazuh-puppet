# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Repo installation
class wazuh::repo (
  String $apt_key_id,
  #String $apt_key_source,
  String $apt_key_server,
  Boolean $redhat_manage_epel = true,
  String $repo_base_url       = 'https://packages.wazuh.com',
  String $apt_gpgkey_name     = 'GPG-KEY-WAZUH',
  String $yum_gpgkey_name     = 'GPG-KEY-WAZUH',
  #String $yum_gpgkey_url      = 'key',
  Boolean $yum_repo_enable    = true,
  String $yum_directory_url   = '3.x/yum/',
) {
  case $facts['os']['family'] {
    'Debian' : {
      if ! defined(Package['apt-transport-https']) {
        ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
      }

      # apt-key added by issue #34
      apt::key { 'wazuh':
        id     => "${apt_key_id}",
        source => "${repo_base_url}/key/${apt_gpgkey_name}",
        # This is never used
        server => "${apt_key_server}",
      }
      apt::source { 'wazuh':
        ensure        => present,
        comment       => "This is the WAZUH ${facts['os']['name']} repository",
        location      => "${repo_base_url}/3.x/apt",
        release       => 'stable',
        repos         => 'main',
        include       => {
          'src' => false,
          'deb' => true,
        },
        notify_update => true,
      }
      # Do these need to be contained??
      #contain 'apt::key'
      #contain 'apt::source'

      # Refresh apt with new packages
      #Apt::Source['wazuh'] -> Class['apt::update']
    }
    'Linux', 'RedHat': {
      # Set up OSSEC repo
      yumrepo { 'wazuh':
        descr    => 'WAZUH OSSEC Repository',
        enabled  => $yum_repo_enable,
        gpgcheck => 1,
        gpgkey   => "${repo_base_url}/key/${yum_gpgkey_name}",
        baseurl  => "${repo_base_url}/${yum_directory_url}"
      }

      if $redhat_manage_epel {
        # Set up EPEL repo
        # NOTE: This relies on the 'epel' module referenced in metadata.json
        package { 'inotify-tools':
          ensure  => present
        }
        include epel

        Class['epel'] -> Package['inotify-tools']
      }
    }
    default: { fail('This ossec module has not been tested on your distribution') }
  }
}
