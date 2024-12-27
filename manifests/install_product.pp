class wazuh:install_product (
  String $package_name,
  String $wazuh_version = '5.0.0',
  String $prod_url       = 'https://devops-wazuh-artifacts-pub.s3.us-west-1.amazonaws.com/devops-overhaul/packages_url.txt',
  Optional[String] $expected_checksum = undef, # Optional checksum for package verification
  String $download_dir    = '/tmp', # Configurable download directory
  Optional[String] $custom_url_file = undef, # Optional path to a local URL file
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
    undef   => $prod_url, # Use the remote URL if no local file is provided
    default => $custom_url_file, # Use the local file if provided
  }

  # Download/copy the URL file based on the source
  if $source_url == $prod_url {
    # Download from remote URL
    exec { 'fetch_packages_url':
      command     => "/usr/bin/curl --fail --location -o ${destination} ${prod_url}",
      path         => ['/usr/bin', '/bin'],
      creates     => $destination,
      logoutput => true,
    }
  } else {
    # Copy from local file
    file { $destination:
      ensure => file,
      source => $source_url,
      mode  => '0644',
    }
  }

  # Find the package URL (only if it's not installed)
  $package_url = undef
  exec { "find_${package_pattern}_in_file":
    command     => "/bin/grep -E '^${package_pattern}:' ${destination} | cut -d':' -f2",
    path         => ['/bin', '/usr/bin'],
    returns     => [0, 1], # Allow grep to not find anything (return code 1)
    require     => $source_url == $prod_url ? { true => Exec['fetch_packages_url'], default => undef }, #Conditional requirement
    logoutput => true,
    unless => $check_command,
  }

  # Assign the URL to a variable if grep was successful
    if $?("find_${package_pattern}_in_file") == 0 {
        $package_url = $execoutput("find_${package_pattern}_in_file")
    }

  if $package_url {
    $package_file = "${download_dir}/${package_pattern}"

    # Download the package using the archive module with checksum verification
    archive { $package_file:
      source       => $package_url,
      checksum     => $expected_checksum ? { undef => undef, default => 'sha256' }, # Conditionally set checksum type
      checksum_value => $expected_checksum,
      creates      => $package_file,
      require     => Exec["find_${package_pattern}_in_file"],
    }

    # Install the package with command injection protection
    if $package_type == 'rpm' {
      $install_command = ['/bin/rpm', '-ivh', $package_file]
    } else {
      $install_command = ['/usr/bin/dpkg', '-i', $package_file]
    }

    exec { "install_${package_pattern}":
      command     => $install_command,
      path         => ['/bin', '/usr/bin'],
      require     => Archive[$package_file],
      unless     => $check_command,
      logoutput  => true,
    }

    # Clean up the downloaded package file
    file { $package_file:
      ensure => absent,
      force => true,
    }
  } else {
    warning("URL for ${package_pattern} not found in ${destination}")
  }

  # Clean up the URL file
  file { $destination:
    ensure => absent,
    force => true,
  }
}