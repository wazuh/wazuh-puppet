# Copyright (C) 2015, Wazuh Inc.
# @summary Wazuh repository installation
class wazuh::repo (
  String $repo_baseurl = 'packages.wazuh.com',
  String $repo_version = '5.x',
) {
  case $facts['os']['family'] {
    'Debian' : {
      $wazuh_repo_url = "https://${repo_baseurl}/${repo_version}/apt"
      $repo_release = 'stable'

      if $facts['os']['distro']['codename'] =~ /(jessie|wheezy|stretch|precise|trusty|vivid|wily|xenial|yakketi|groovy)/
      and ! defined(Package['apt-transport-https']) and ! defined(Package['gnupg']) {
        ensure_packages(['apt-transport-https', 'gnupg'], { 'ensure' => 'present' })
      }
      exec { 'import-wazuh-key':
        path    => ['/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/'],
        command => "curl -s https://${repo_baseurl}/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import",
        unless  => 'gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --list-keys | grep -q 29111145',
      }

      # Ensure permissions on the keyring
      file { '/usr/share/keyrings/wazuh.gpg':
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        require => Exec['import-wazuh-key'],
      }
      case $facts['os']['distro']['codename'] {
        /(jessie|wheezy|stretch|buster|bullseye|bookworm|sid|precise|trusty|vivid|wily|xenial|yakketi|bionic|focal|groovy|jammy)/: {
          apt::source { 'wazuh':
            ensure   => present,
            comment  => 'This is the WAZUH Ubuntu repository',
            location => $wazuh_repo_url,
            release  => $repo_release,
            repos    => 'main',
            include  => {
              'src' => false,
              'deb' => true,
            },
            require  => File['/usr/share/keyrings/wazuh.gpg'],
          }
          # Manage the APT source list file content using concat
          concat { '/etc/apt/sources.list.d/wazuh.list':
            ensure => present,
            owner  => 'root',
            group  => 'root',
            mode   => '0644',
          }

          concat::fragment { 'wazuh-source':
            target  => '/etc/apt/sources.list.d/wazuh.list',
            content => "deb [signed-by=/usr/share/keyrings/wazuh.gpg] ${wazuh_repo_url} ${repo_release} main\n",
            order   => '01',
            require => File['/usr/share/keyrings/wazuh.gpg'],
            notify  => Exec['apt-update-wazuh'],
          }
        }
        default: { fail('This ossec module has not been tested on your distribution (or lsb package not installed)') }
      }
      # Define an exec resource to run 'apt-get update', without conflicting with the apt module (if using stage workflow)
      exec { 'apt-update-wazuh':
        command     => 'apt-get update',
        refreshonly => true,
        path        => ['/bin', '/usr/bin'],
      }
    }
    'Linux', 'RedHat', 'Suse' : {
      case $facts['os'][name] {
        /^(CentOS|RedHat|OracleLinux|Fedora|Amazon|AlmaLinux|Rocky|SLES)$/: {
          if ( $facts['os']['release']['full'] =~ /^5.*/ ) {
            $baseurl  = "${repo_baseurl}/${repo_version}/yum/5/"
            $gpgkey   = "http://${repo_baseurl}/key/GPG-KEY-WAZUH"
          } else {
            $baseurl  = "https://${repo_baseurl}/${repo_version}/yum/"
            $gpgkey   = "https://${repo_baseurl}/key/GPG-KEY-WAZUH"
          }
        }
        default: { fail('This ossec module has not been tested on your distribution.') }
      }
      # Set up OSSEC repo
      case $facts['os'][name] {
        /^(CentOS|RedHat|OracleLinux|Fedora|Amazon|AlmaLinux)$/: {
          yumrepo { 'wazuh':
            descr    => 'WAZUH OSSEC Repository - www.wazuh.com',
            enabled  => true,
            gpgcheck => 1,
            gpgkey   => $gpgkey,
            baseurl  => $baseurl,
          }
        }
        /^(SLES)$/: {
          zypprepo { 'wazuh':
            ensure        => present,
            name          => 'WAZUH OSSEC Repository - www.wazuh.com',
            enabled       => 1,
            gpgcheck      => 0,
            repo_gpgcheck => 0,
            pkg_gpgcheck  => 0,
            gpgkey        => $gpgkey,
            baseurl       => $baseurl,
          }
        }
      }
    }
  }
}
