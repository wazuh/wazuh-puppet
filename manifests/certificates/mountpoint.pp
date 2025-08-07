# @summary Creates a puppet file mountpoint for generated certificates
# on the Puppet server. If you have separate CAs and compilers, you'll
# need to implement syncing of some sort (a network share, rsync, etc)
# and include this class on all compilers as well as the CA.
# Potential improvements: 
# - Restrict access to the mountpoint with entries in auth.conf
class wazuh::certificates::mountpoint (
  Stdlib::Absolutepath $filebucket_path = $wazuh::certificates::filebucket_path,
  Stdlib::Absolutepath $fileserver_conf = $wazuh::certificates::fileserver_conf,
  Boolean $manage_fileserver_conf = true,
  Boolean $manage_bucket_dir = true,
  String $bucket_name = $wazuh::certificates::bucket_name,
  String $owner = 'puppet',
  String $group = 'puppet',
) {
  assert_private()
  $_dirs = $manage_bucket_dir ? {
    true => [
      $filebucket_path,
      "${filebucket_path}/${bucket_name}",
    ],
    default => ["${filebucket_path}/${bucket_name}"],
  }
  file { $_dirs:
    ensure => directory,
    owner  => $owner,
    group  => $group,
    mode   => '0750',
  }

  if $manage_fileserver_conf {
    file { $fileserver_conf:
      ensure => file,
      owner  => $owner,
      group  => $group,
      mode   => '0640',
    }
  }

  $_tonotify = defined(Service['puppetserver']) ? {
    true    => Service['puppetserver'],
    default => undef,
  }

  ini_setting { 'wazuh certificates mountpoint':
    ensure       => present,
    path         => $fileserver_conf,
    section      => $bucket_name,
    setting      => 'path',
    value        => "${filebucket_path}/${bucket_name}",
    indent_width => 2,
    notify       => $_tonotify,
  }
}
