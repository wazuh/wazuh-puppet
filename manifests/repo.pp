# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Repo installation
class wazuh::repo (
  $redhat_manage_epel = true,
  $repo_base_url,
  $apt_key_id = '',
  $apt_key_source = '',
  $apt_key_server = '',
  $apt_gpgkey_name = 'GPG-KEY-WAZUH',
  $yum_gpgkey_name = 'GPG-KEY-WAZUH',
  #$yum_gpgkey_url = 'key',
  $yum_repo_enable = true,
  $yum_directory_url = '3.x/yum/',
) {

# No no no NO! Data belongs in hiera!!
  case $facts['os']['family'] {
    'Debian' : {
      if ! defined(Package['apt-transport-https']) {
        ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
      }
      if ! $facts['lsbdistcodename'] {
        fail('The lsb package does not appear to be installed or the codename fact is missing.') 
      }
        
      # apt-key added by issue #34
      apt::key { 'wazuh':
        id     => "${apt_key_id}",
        source => "${repo_base_url}/key/${apt_gpgkey_name}",
        # This is never used
        server => "${apt_key_server}",
      }
      # This list seems contradictory to params.pp, what the heck is going on??
      # Also, obscene duplication of data. The only difference is the flavor!
      # UPDATE: This definitely conflicts with params.pp, minimum versions in 
      #  params.pp are 6 for RedHat flavors. 5 is long dead and should be 
      #  dropped.
      apt::source { 'wazuh':
        ensure   => present,
        comment  => "This is the WAZUH ${facts['os']['name']} repository",
        location => "${repo_base_url}/apt",
        # This is the default so really no need to specify it
        #release  => $::lsbdistcodename,
        repos    => 'main',
        include  => {
          'src' => false,
          'deb' => true,
        },
      }
    }
    'Linux', 'RedHat': {
      # Set up OSSEC repo
      yumrepo { 'wazuh':
        descr    => 'WAZUH OSSEC Repository',
        enabled  => $yum_repo_enable,
        gpgcheck => 1,
        gpgkey   => "{repo_base_url}/key/${yum_gpgkey_name}",
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
