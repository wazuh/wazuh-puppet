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
  $yum_directory_url = '',
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
      case $::lsbdistcodename {
        /(jessie|wheezy|stretch|sid|precise|trusty|vivid|wily|xenial|yakketi)/: {

          apt::source { 'wazuh':
            ensure   => present,
            comment  => 'This is the WAZUH Ubuntu repository',
            location => 'https://packages.wazuh.com/3.x/apt',
            release  => 'stable',
            repos    => 'main',
            include  => {
              'src' => false,
              'deb' => true,
            },
          }
        }
        default: { fail('This ossec module has not been tested on your distribution (or lsb package not installed)') }
      }
    }
    'Linux', 'Redhat' : {
        case $::os[name] {
          /^(CentOS|RedHat|OracleLinux|Fedora|Amazon)$/: {
            if ( $::operatingsystemrelease =~ /^5.*/ ) {
              $baseurl  = 'https://packages.wazuh.com/3.x/yum/5/'
              $gpgkey   = 'http://packages.wazuh.com/key/GPG-KEY-WAZUH-5'
            } else {
              $baseurl  = 'https://packages.wazuh.com/3.x/yum/'
              $gpgkey   = 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
            }
          }
          default: { fail('This ossec module has not been tested on your distribution.') }
        }
      # Set up OSSEC repo
      yumrepo { 'wazuh':
        descr    => "WAZUH OSSEC Repository - www.wazuh.com",
        enabled  => true,
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
