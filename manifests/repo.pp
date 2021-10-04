# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Wazuh repository installation
class wazuh::repo (
) {

  case $::osfamily {
    'Debian' : {
      if $::lsbdistcodename =~ /(jessie|wheezy|stretch|precise|trusty|vivid|wily|xenial|yakketi|focal)/
      and ! defined(Package['apt-transport-https']) {
        ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
      }
      apt::key { 'wazuh':
        id     => '0DCFCA5547B19D2A6099506096B3EE5F29111145',
        server => 'pgp.mit.edu'
      }
      case $::lsbdistcodename {
        /(jessie|wheezy|stretch|buster|sid|precise|trusty|vivid|wily|xenial|yakketi|bionic|focal)/: {

          apt::source { 'wazuh':
            ensure   => present,
            comment  => 'This is the WAZUH Ubuntu repository',
            location => 'https://packages.wazuh.com/4.x/apt',
            release  => 'stable',
            repos    => 'main',
            key      => {
              'id'     => '0DCFCA5547B19D2A6099506096B3EE5F29111145',
              'server' => 'pgp.mit.edu',
            },
            include  => {
              'src' => false,
              'deb' => true,
            },
          }
        }
        default: { fail('This ossec module has not been tested on your distribution (or lsb package not installed)') }
      }
    }
    'Linux', 'RedHat' : {
        case $::os[name] {
          /^(CentOS|RedHat|OracleLinux|Fedora|Amazon)$/: {
            if ( $::operatingsystemrelease =~ /^5.*/ ) {
              $baseurl  = 'https://packages.wazuh.com/4.x/yum/5/'
              $gpgkey   = 'http://packages.wazuh.com/key/GPG-KEY-WAZUH-5'
            } else {
              $baseurl  = 'https://packages.wazuh.com/4.x/yum/'
              $gpgkey   = 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
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

    }
    default: { fail('This ossec module has not been tested on your distribution') }
  }
}
