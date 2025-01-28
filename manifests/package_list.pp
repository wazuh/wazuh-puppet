# This class downloads the package list from a specified URL to a destination file.
#
# Parameters:
#   $prod_url: The URL to download the package list from.
#   $destination: The file path where the package list will be saved.
class wazuh::package_list (
  $prod_url = 'https://devops-wazuh-artifacts-pub.s3.us-west-1.amazonaws.com/devops-overhaul/packages_url.txt',
  $destination = '/tmp/packages_url.txt',
) {
  exec { 'download_packages_url_from_url':
    command   => "/usr/bin/curl --fail --location -o ${destination} ${prod_url}",
    path      => ['/usr/sbin', '/usr/bin', '/sbin', '/bin', '/usr/local/sbin', '/usr/local/bin'],
    creates   => $destination, # is created when the file does not exist
    unless    => "test -f ${destination}", # not executed if file exists.
    logoutput => true,
  }
}
