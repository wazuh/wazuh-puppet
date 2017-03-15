# Repo installation
class wazuh::repo (
  $redhat_manage_epel = true,
) {

  case $::osfamily {
    'Debian' : {
      # apt-key added by issue #34
      apt::key { 'wazuh':
        id     => '0DCFCA5547B19D2A6099506096B3EE5F29111145',
        source => 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
      }
      case $::lsbdistcodename {
        /(precise|trusty|vivid|wily|xenial|yakketi)/: {

          apt::source { 'wazuh':
            ensure   => present,
            comment  => 'This is the WAZUH Ubuntu repository',
            location => 'https://packages.wazuh.com/apt',
            release  => $::lsbdistcodename,
            repos    => 'main',
            include  => {
              'src' => false,
              'deb' => true,
            },
          }

        }
        /^(jessie|wheezy|stretch|sid)$/: {
          apt::source { 'wazuh':
            ensure   => present,
            comment  => 'This is the WAZUH Debian repository',
            location => 'https://packages.wazuh.com/apt',
            release  => $::lsbdistcodename,
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
      if ( $::operatingsystem == 'Amazon' ) {
        $repotype = 'Amazon Linux'
        $baseurl  = 'https://packages.wazuh.com/yum/rhel/6Server/$basearch'
        $gpgkey   = 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
      }
      else {
        case $::os[name] {
          'CentOS': {
            if ( $::operatingsystemrelease =~ /^5.*/ ) {
              $repotype = 'CentOS 5'
              $baseurl  = 'https://packages.wazuh.com/yum/el/$releasever/$basearch'
              $gpgkey   = 'https://packages.wazuh.com/key/RPM-GPG-KEY-OSSEC-RHEL5'
            } else {
              $repotype = 'CentOS > 5'
              $baseurl  = 'https://packages.wazuh.com/yum/el/$releasever/$basearch'
              $gpgkey   = 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
            }
          }
          'Redhat': {
            if ( $::operatingsystemrelease =~ /^5.*/ ) {
              $repotype = 'CentOS 5'
              $baseurl  = 'https://packages.wazuh.com/yum/rhel/$releasever/$basearch'
              $gpgkey   = 'https://packages.wazuh.com/key/RPM-GPG-KEY-OSSEC-RHEL5'
            } else {
              $repotype = 'CentOS > 5'
              $baseurl  = 'https://packages.wazuh.com/yum/rhel/$releasever/$basearch'
              $gpgkey   = 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
            }
          }
          'Fedora': {
              $repotype = 'Fedora'
              $baseurl  = 'https://packages.wazuh.com/yum/fc/$releasever/$basearch'
              $gpgkey   = 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
          }
        }
      }
      # Set up OSSEC repo
      yumrepo { 'wazuh':
        descr    => "WAZUH OSSEC Repository - www.wazuh.com # ${repotype}",
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
