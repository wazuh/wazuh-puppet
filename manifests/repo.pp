class wazuh::repo (
  $redhat_manage_epel = true,
) {
  case $::osfamily {
    'Redhat' : {
      if $operatingsystemrelease =~ /^5.*/ {
        # Set up OSSEC repo
        yumrepo { 'wazuh':
          descr    => 'WAZUH OSSEC Repository - www.wazuh.com',
          enabled  => true,
          gpgcheck => 1,
          gpgkey   => 'http://ossec.wazuh.com/key/RPM-GPG-KEY-OSSEC-RHEL5',
          baseurl  => 'http://ossec.wazuh.com/el/$releasever/$basearch',
          priority => 1,
          protect  => false,
        }
      }
      else {
        # Set up OSSEC repo
        yumrepo { 'wazuh':
          descr    => 'WAZUH OSSEC Repository - www.wazuh.com',
          enabled  => true,
          gpgkey   => 'http://ossec.wazuh.com/key/RPM-GPG-KEY-OSSEC',
          baseurl  => 'http://ossec.wazuh.com/el/$releasever/$basearch',
          priority => 1,
          protect  => false,
        }
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
