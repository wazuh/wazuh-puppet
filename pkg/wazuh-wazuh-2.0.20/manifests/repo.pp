# Repo installation
class ossec::repo (
  $redhat_manage_epel = true,
) {
  file { '/usr/src/ossec':
    ensure => directory,
  }

  file { '/usr/src/ossec/RPM-GPG-KEY-OSSEC':
    ensure  => present,
    source  => 'puppet:///modules/ossec/RPM-GPG-KEY-OSSEC',
    owner   => root,
    group   => root,
    mode    => '0744',
    require => File['/usr/src/ossec']
  }

  file { '/usr/src/ossec/RPM-GPG-KEY-OSSEC-RHEL5':
    ensure  => present,
    source  => 'puppet:///modules/ossec/RPM-GPG-KEY-OSSEC-RHEL5',
    owner   => root,
    group   => root,
    mode    => '0744',
    require => File['/usr/src/ossec']
  }

  case $::osfamily {
    'Debian' : {
      # apt-key added by issue #34
      apt::key { 'puppetlabs':
        id     => '9FE55537D1713CA519DFB85114B9C8DB9A1B1C65',
        source => 'http://ossec.wazuh.com/repos/apt/conf/ossec-key.gpg.key'
      }
      case $::lsbdistcodename {
        /(precise|trusty|vivid|wily|xenial|yakketi)/: {

          apt::source { 'wazuh':
            ensure   => present,
            comment  => 'This is the WAZUH Ubuntu repository for Ossec',
            location => 'http://ossec.wazuh.com/repos/apt/ubuntu',
            release  => $::lsbdistcodename,
            repos    => 'main',
            include  => {
              'src' => false,
              'deb' => true,
            },
          }
          ~>
          exec { 'update-apt-wazuh-repo':
            command     => '/usr/bin/apt-get update',
            refreshonly => true
          }

        }
        /^(jessie|wheezy|stretch|sid)$/: {
          apt::source { 'wazuh':
            ensure   => present,
            comment  => 'This is the WAZUH Debian repository for Ossec',
            location => 'http://ossec.wazuh.com/repos/apt/debian',
            release  => $::lsbdistcodename,
            repos    => 'main',
            include  => {
              'src' => false,
              'deb' => true,
            },
          }
          ~>
          exec { 'update-apt-wazuh-repo':
            command     => '/usr/bin/apt-get update',
            refreshonly => true
          }
        }
        default: { fail('This ossec module has not been tested on your distribution (or lsb package not installed)') }
      }
    }
    'Linux', 'Redhat' : {
      if ( $::operatingsystem == 'Amazon' ) {
        $repotype = 'Amazon Linux'
        $baseurl  = 'http://ossec.wazuh.com/el/6Server/$basearch'
        $gpgkey   = 'file:///usr/src/ossec/RPM-GPG-KEY-OSSEC'
      } elsif ( $::operatingsystemrelease =~ /^5.*/ ) {
        $repotype = 'RHEL5'
        $baseurl  = 'http://ossec.wazuh.com/el/$releasever/$basearch'
        $gpgkey   = 'file:///usr/src/ossec/RPM-GPG-KEY-OSSEC-RHEL5'
      } else {
        $repotype = 'RHEL > 5'
        $baseurl  = 'http://ossec.wazuh.com/el/$releasever/$basearch'
        $gpgkey   = 'file:///usr/src/ossec/RPM-GPG-KEY-OSSEC'
      }

      # Set up OSSEC repo
      yumrepo { 'ossec':
        descr    => "WAZUH OSSEC Repository - www.wazuh.com # ${repotype}",
        enabled  => true,
        gpgcheck => 1,
        gpgkey   => $gpgkey,
        baseurl  => $baseurl,
        require  => [ File['/usr/src/ossec/RPM-GPG-KEY-OSSEC'], File['/usr/src/ossec/RPM-GPG-KEY-OSSEC-RHEL5'] ]
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
