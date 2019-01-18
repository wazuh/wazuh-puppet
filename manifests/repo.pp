# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Repo installation
class wazuh::repo (
  $redhat_manage_epel = true,
) {

  case $::osfamily {
    'Debian' : {
      if ! defined(Package['apt-transport-https']) {
        ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
      }
      # apt-key added by issue #34
      apt::key { 'wazuh':
        id     => '0DCFCA5547B19D2A6099506096B3EE5F29111145',
        source => 'https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH',
        server => 'pgp.mit.edu'
      }
      case $::lsbdistcodename {
        /(jessie|wheezy|stretch|sid|precise|trusty|vivid|wily|xenial|yakketi|bionic)/: {

          apt::source { 'wazuh':
            ensure   => present,
            comment  => 'This is the WAZUH Ubuntu repository',
            location => 'https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/apt/',
            release  => 'unstable',
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
              $baseurl  = 'http://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/yum/5/'
              $gpgkey   = 'http://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH'
            } else {
              $baseurl  = 'https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/yum/'
              $gpgkey   = 'https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH'
            }
          }
          default: { fail('This ossec module has not been tested on your distribution.') }
        }
      # Set up OSSEC repo
      yumrepo { 'wazuh':
        descr    => 'WAZUH OSSEC Repository - www.wazuh.com',
        enabled  => true,
        gpgcheck => 1,
        gpgkey   => $gpgkey,
        baseurl  => $baseurl
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
