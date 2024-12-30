#
# Class to install Wazuh product
#
# @param package_name The name of the package to be installed.
# @param wazuh_version The version of the Wazuh package to be installed.
# @param prod_url The URL to download the package list from.
# @param source_url The Puppet URL to download the package list from.
# @param destination Destination path for the downloaded file
# @param rpm_based Regex for RPM-based OS families
# @param deb_based Regex for DEB-based OS families
# @param download_dir parameter for download directory
class wazuh::install_product (
  String $package_name = 'wazuh-manager',
  String $wazuh_version = '4.9.2',
  String $prod_url = 'https://devops-wazuh-artifacts-pub.s3.us-west-1.amazonaws.com/devops-overhaul/packages_url.txt',
  String $source_url = 'puppet:///modules/archive/packages_url.txt',
  String $destination = '/tmp/packages_url.txt',
  String $rpm_based = 'RedHat|Suse|Amazon|OracleLinux|AlmaLinux|Rocky',
  String $deb_based = 'Debian|Ubuntu|Mint|Kali|Raspbian',
  String $download_dir = '/tmp',
  String $package_url = '/tmp/package_url',

) {
  # Determine the package type (rpm or deb) based on the OS family.
  if $facts['os']['family'] =~ Regexp($rpm_based) {
    $package_type = 'rpm'
    $check_command = "/bin/rpm -q ${package_name}" # Command to check if the package is installed (RPM)
  } elsif $facts['os']['family'] =~ Regexp($deb_based) {
    $package_type = 'deb'
    $check_command = "/usr/bin/dpkg-query -l ${package_name}" # Command to check if the package is installed (DEB)
  } else {
    fail("Unsupported OS family: ${facts['os']['family']}") # Fail if the OS family is not supported
  }

  # Determine the package architecture.
  $package_arch = $facts['os']['architecture'] ? {
    'x86_64' => 'amd64',
    default  => $facts['os']['architecture'],
  }

  # Construct the package filename.
  $package_pattern = "${package_name}-${wazuh_version}-${package_arch}.${package_type}"

  # Download the file using the archive resource.
  file { $destination:
    ensure => file,
    source => $source_url,
    mode   => '0644',
  }

  exec { 'download_packages_url_from_url':
    command   => "/usr/bin/curl --fail --location -o ${destination} ${prod_url}",
    path      => ['/usr/bin', '/bin'],
    creates   => $destination, # is created when the file does not exist
    unless    => "test -f ${destination}", # not executed if file exists.
    logoutput => true,
  }

  # Find the package URL in the downloaded file.
  exec { "find_${package_pattern}_in_file":
    command   => "/bin/grep -E '^${package_pattern}:' ${destination} | cut -d':' -f2 > ${download_dir}/package_url",
    path      => ['/bin', '/usr/bin'],
    creates   => "${download_dir}/package_url",
    require   => Archive[$destination],
    logoutput => true,
  }

  if $package_url {
    $package_file = "${download_dir}/${package_pattern}"

    archive { $package_file:
      source  => $package_url,
      creates => $package_file,
      require => Exec["find_${package_pattern}_in_file"],
    }

    # Determine the install command based on the package type.
    $install_command = $package_type ? {
      'rpm' => "/bin/rpm -ivh ${package_file}",
      'deb' => "/usr/bin/dpkg -i ${package_file}",
    }

    # Install the package.
    exec { "install_${package_pattern}":
      command   => $install_command,
      path      => ['/bin', '/usr/bin'],
      require   => Archive[$package_file],
      unless    => $check_command, # Only install if the package is not already installed
      logoutput => true,
    }

    # Remove the downloaded package file.
    file { $package_file:
      ensure => absent,
      force  => true,
    }
  } else {
    warning("URL for ${package_pattern} not found in ${destination}")
  }

  # Remove the downloaded URL list file.
  file { "${download_dir}/package_url":
    ensure => absent,
    force  => true,
  }
}
