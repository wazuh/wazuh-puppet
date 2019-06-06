class wazuh::repo_elastic (
  $redhat_manage_epel = true,
) {
    case $::osfamily {
      'Debian' : {
        if ! defined(Package['apt-transport-https']) {
          ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
        }
        # apt-key added by issue #34
        apt::key { 'elastic':
          id     => 'D88E42B4',
          source => 'https://artifacts.elastic.co/GPG-KEY-elasticsearch',
        }
        case $::lsbdistcodename {
          /(jessie|wheezy|stretch|sid|precise|trusty|vivid|wily|xenial|yakketi|bionic)/: {

            apt::source { 'wazuh_elastic':
              ensure   => present,
              comment  => 'This is the Elastic repository',
              location => 'https://artifacts.elastic.co/packages/7.x/apt',
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
      'Redhat' : {
          case $::os[name] {
            /^(CentOS|RedHat|OracleLinux|Fedora|Amazon)$/: {
              if ( $::operatingsystemrelease =~ /^5.*/ ) {
                $baseurl  = 'https://artifacts.elastic.co/packages/7.x/apt'
                $gpgkey   = 'https://artifacts.elastic.co/GPG-KEY-elasticsearch'
              } else {
                $baseurl  = 'https://artifacts.elastic.co/packages/7.x/apt'
                $gpgkey   = 'https://artifacts.elastic.co/GPG-KEY-elasticsearch'
              }
            }
            default: { fail('This ossec module has not been tested on your distribution.') }
          }
        # Set up OSSEC repo
        yumrepo { 'elastic':
          descr    => 'Elastic',
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
