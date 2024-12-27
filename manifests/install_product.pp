class wazuh::install_product (
  String $package_name,
  String $wazuh_version = '5.0.0',
  String $prod_url       = 'https://devops-wazuh-artifacts-pub.s3.us-west-1.amazonaws.com/devops-overhaul/packages_url.txt',
  Optional[String] $expected_checksum = undef,
  String $download_dir    = '/tmp',
  Optional[String] $custom_url_file = undef,
) {
  String $destination = "${download_dir}/packages_url.txt"
  String $rpm_based = 'RedHat|Suse|Amazon|OracleLinux|AlmaLinux|Rocky'
  String $deb_based = 'Debian|Ubuntu|Mint|Kali|Raspbian'

  if $facts['os']['family'] =~ Regexp($rpm_based) {
    $package_type = 'rpm'
    $check_command = "/bin/rpm -q ${package_name}"
  } elsif $facts['os']['family'] =~ Regexp($deb_based) {
    $package_type = 'deb'
    $check_command = "/usr/bin/dpkg-query -l ${package_name}"
  } else {
    fail("Unsupported OS family: ${facts['os']['family']}")
  }

  $package_arch = $facts['architecture'] ? {
    'x86_64' => 'amd64',
    default  => $facts['architecture'],
  }

  $package_pattern = "${package_name}-${wazuh_version}-${package_arch}.${package_type}"

  # Determine the source of the URL file (local or remote)
  $source_url = $custom_url_file ? {
    undef   => $prod_url,
    default => $custom_url_file,
  }

  # Download/copy the URL file
  if $source_url == $prod_url {
    exec { 'fetch_packages_url':
      command  => "/usr/bin/curl --fail --location -o ${destination} ${prod_url}",
      path     => ['/usr/bin', '/bin'],
      creates  => $destination,
      logoutput => true,
    }
  } else {
    file { $destination:
      ensure => file,
      source => $source_url,
      mode   => '0644',
    }
  }

  # Find the package URL
  exec { "find_${package_pattern}_in_file":
    command  => "/bin/grep -E '^${package_pattern}:' ${destination} | cut -d':' -f2 > ${download_dir}/package_url",
    path     => ['/bin', '/usr/bin'],
    creates  => "${download_dir}/package_url",
    require  => File[$destination],
    logoutput => true,
  }

  # Read the URL from the temporary file
  $package_url = file("${download_dir}/package_url")

  if $package_url != '' {
    $package_file = "${download_dir}/${package_pattern}"

    # Download the package
    archive { $package_file:
      source          => $package_url,
      checksum        => $expected_checksum ? { undef => undef, default => 'sha256' },
      checksum_value  => $expected_checksum,
      creates         => $package_file,
      require         => Exec["find_${package_pattern}_in_file"],
    }

    # Install the package
    $install_command = $package_type ? {
      'rpm' => "/bin/rpm -ivh ${package_file}",
      'deb' => "/usr/bin/dpkg -i ${package_file}",
    }

    exec { "install_${package_pattern}":
      command  => $install_command,
      path     => ['/bin', '/usr/bin'],
      require  => Archive[$package_file],
      unless   => $check_command,
      logoutput => true,
    }

    # Clean up the downloaded package file
    file { $package_file:
      ensure => absent,
      force  => true,
    }
  } else {
    warning("URL for ${package_pattern} not found in ${destination}")
  }

  # Clean up the URL file
  file { $destination:
    ensure => absent,
    force  => true,
  }

  # Clean up the temporary package URL file
  file { "${download_dir}/package_url":
    ensure => absent,
    force  => true,
  }
}
