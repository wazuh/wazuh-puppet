# This class downloads the package list from a specified URL to a destination file.
#
# Parameters:
#   $prod_url: The URL to download the package list from.
#   $destination: The file path where the package list will be saved.
class wazuh::package_list (
  $prod_url    = 'https://devops-wazuh-artifacts-pub.s3.us-west-1.amazonaws.com/devops-overhaul/packages_url.txt',
  $destination = undef,
) {

  $default_destination = $facts['kernel'] ? {
    'windows' => 'C:\Windows\Temp\packages_url.txt',
    default   => '/tmp/packages_url.txt',
  }

  $actual_destination = pick($destination, $default_destination)

  file { dirname($actual_destination):
    ensure => directory,
  }

  archive { $actual_destination:
    ensure  => present,
    source  => $prod_url,
    extract => false,
    cleanup => false,
    require => File[dirname($actual_destination)],
  }
}
