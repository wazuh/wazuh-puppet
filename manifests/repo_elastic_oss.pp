# Copyright (C) 2015, Wazuh Inc.
# Installation of Elastic-oss repository
class wazuh::repo_elastic_oss (

) {
    case $::osfamily {
      'Debian' : {
        if ! defined(Package['apt-transport-https']) {
          ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
        }
        # apt-key added by issue #34
        apt::key { 'elastic':
          id     => '46095ACC8548582C1A2699A9D27D666CD88E42B4',
          source => 'https://artifacts.elastic.co/GPG-KEY-elasticsearch',
          server => 'pgp.mit.edu'
        }
        case $::lsbdistcodename {
          /(jessie|wheezy|stretch|buster|bullseye|sid|precise|trusty|vivid|wily|xenial|yakketi|bionic|focal)/: {

            apt::source { 'wazuh_elastic_oss':
              ensure   => present,
              comment  => 'This is the OSS Elastic repository',
              location => 'https://artifacts.elastic.co/packages/oss-7.x/apt',
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
      'RedHat' : {
          case $::os[name] {
            /^(CentOS|RedHat|OracleLinux|Fedora|Amazon)$/: {
              if ( $::operatingsystemrelease =~ /^5.*/ ) {
                $baseurl  = 'https://artifacts.elastic.co/packages/oss-7.x/yum'
                $gpgkey   = 'https://artifacts.elastic.co/GPG-KEY-elasticsearch'
              } else {
                $baseurl  = 'https://artifacts.elastic.co/packages/oss-7.x/yum'
                $gpgkey   = 'https://artifacts.elastic.co/GPG-KEY-elasticsearch'
              }
            }
            default: { fail('This ossec module has not been tested on your distribution.') }
          }
        ## Set up Elasticsearch repo

        # Import GPG key

        exec { 'Install Elasticsearch GPG key':
          path    => '/usr/bin',
          command => 'rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch',
        }

        # Adding repo by Puppet yumrepo resource

        yumrepo { 'elasticsearch':
          ensure   => 'present',
          enabled  => 1,
          gpgcheck => 1,
          gpgkey   => $gpgkey,
          baseurl  => $baseurl,
          name     => 'elasticsearch',
        }
      }
      default: { fail('This ossec module has not been tested on your distribution') }
    }
  }
