# Wazuh App Copyright (C) 2020 Wazuh Inc. (License GPLv2)
# Installation of Open Distro for Elasticsearch repository
class wazuh::repo_opendistro (

) {
    case $::osfamily {
      'Debian' : {
        if ! defined(Package['apt-transport-https']) {
          ensure_packages(['apt-transport-https'], {'ensure' => 'present'})
        }
        # apt-key added by issue #34
        apt::key { 'opendistro':
          id     => '51209CCB28FBC2DC8CCD9A6C472CFDFCE370325E',
          source => 'https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch',
          server => 'pgp.mit.edu'
        }
        case $::lsbdistcodename {
          /(jessie|wheezy|stretch|buster|sid|precise|trusty|vivid|wily|xenial|yakketi|bionic|focal)/: {

            apt::source { 'wazuh_elastic_od':
              ensure   => present,
              comment  => 'This is the Open Distro for Elastic repository',
              location => 'https://d3g5vo6xdbdb9a.cloudfront.net/apt',
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
                $baseurl  = 'https://d3g5vo6xdbdb9a.cloudfront.net/yum/noarch/'
                $gpgkey   = 'https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch'
              } else {
                $baseurl  = 'https://d3g5vo6xdbdb9a.cloudfront.net/yum/noarch/'
                $gpgkey   = 'https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch'
              }
            }
            default: { fail('This ossec module has not been tested on your distribution.') }
          }
        ## Set up Open Distro for Elasticsearch repo

        # Import GPG key

        exec { 'Install Open Distro for Elasticsearch GPG key':
          path    => '/usr/bin',
          command => 'rpm --import https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch',
        }

        # Adding repo by Puppet yumrepo resource

        yumrepo { 'opendistro':
          ensure   => 'present',
          enabled  => 1,
          gpgcheck => 1,
          gpgkey   => $gpgkey,
          baseurl  => $baseurl,
          name     => 'opendistro',
        }
      }
      default: { fail('This ossec module has not been tested on your distribution') }
    }
  }
