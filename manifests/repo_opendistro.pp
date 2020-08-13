# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Installation of Elastic repository
class wazuh::repo_elastic (

) {
    case $::osfamily {
      'Debian' : {
        if ! defined(Package['apt-transport-https']) {
          ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
        }
        # apt-key added by issue #34
        apt::key { 'elastic':
          id     => '46095ACC8548582C1A2699A9D27D666CD88E42B4',
          source => 'https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch',
          server => 'pgp.mit.edu'
        }
        case $::lsbdistcodename {
          /(jessie|wheezy|stretch|buster|sid|precise|trusty|vivid|wily|xenial|yakketi|bionic)/: {

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
          default: { fail('This module has not been tested on your distribution (or lsb package not installed)') }
        }
      }
      'RedHat' : {
          case $::os[name] {
            /^(CentOS|RedHat|OracleLinux|Fedora|Amazon)$/: {
              if ( $::operatingsystemrelease =~ /^5.*/ ) {
                $baseurl  = 'https://d3g5vo6xdbdb9a.cloudfront.net/yum/noarch/'
                $gpgkey   = 'https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch'
              } else {
                $baseurl  = 'https://d3g5vo6xdbdb9a.cloudfront.net/yum/noarch/'
                $gpgkey   = 'https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch'
              }
            }
            default: { fail('This module has not been tested on your distribution.') }
          }
        ## Set up Elasticsearch repo

        # Import GPG key

        exec { 'Install Elasticsearch GPG key':
          path    => '/usr/bin',
          command => 'rpm --import https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch',
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
      default: { fail('This module has not been tested on your distribution') }
    }
  }
