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
define wazuh::install_product (
  String $package_name = 'wazuh-manager',
  String $wazuh_version = '4.9.2',
  String $destination = '/tmp/packages_url.txt',
  String $rpm_based = 'RedHat|Suse|Amazon|OracleLinux|AlmaLinux|Rocky',
  String $deb_based = 'Debian|Ubuntu|Mint|Kali|Raspbian',
  String $download_dir = '/tmp',
) {
  # Determine the package type (rpm or deb) based on the OS family.
  if $facts['os']['family'] =~ Regexp($rpm_based) {
    $package_type = 'rpm'
    $check_command = "/bin/rpm -q ${package_name}" # Command to check if the package is installed (RPM)
  } elsif $facts['os']['family'] =~ Regexp($deb_based) {
    $package_type = 'deb'
    $check_command = "/usr/bin/dpkg-query -l ${package_name} | grep '^ii'" # Command to check if the package is installed (DEB)
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

  # Find the package URL in the downloaded file.
  exec { 'filter_and_extract_${package_name}':
    command   => "/usr/bin/sed -n '/^${package_pattern}:/p' ${destination} | /usr/bin/awk -F': ' '{print \$2}' > ${destination}.bak && mv ${destination}.bak ${destination}",
    path      => ['/usr/sbin', '/usr/bin', '/sbin', '/bin', '/usr/local/sbin', '/usr/local/bin'],
    logoutput => true,
  }

  notify { "Extracted package URL: ${destination}": }

  if $destination {
    exec { 'download_file_from_url':
      command   => "tr -d '\r' < ${destination} | xargs /usr/bin/curl -o '${download_dir}/${package_pattern}'",
      path      => ['/usr/sbin', '/usr/bin', '/sbin', '/bin', '/usr/local/sbin', '/usr/local/bin'],
      logoutput => true,
    }

    # Determine the install command based on the package type.
    $install_command = $package_type ? {
      'rpm' => "/bin/rpm -ivh ${download_dir}/${package_pattern}",
      'deb' => "dpkg -i ${download_dir}/${package_pattern} || apt-get install -f -y",
    }

    notify { "Command to install: ${install_command}": }

    # Install the package.
    exec { "install_${package_pattern}":
      command   => $install_command,
      path      => ['/usr/sbin', '/usr/bin', '/sbin', '/bin', '/usr/local/sbin', '/usr/local/bin'],
      onlyif    => "dpkg-deb --info ${download_dir}/${package_pattern}",
      unless    => $check_command, # Only install if the package is not already installed
      logoutput => true,
    }

    # Remove the downloaded package file.
    file { "${download_dir}/${package_pattern}":
      ensure => absent,
      force  => true,
    }
  } else {
    warning("URL for ${package_pattern} not found in ${destination}")
  }
}
