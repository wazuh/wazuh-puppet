class install_product (
  String $package_name,
  String $desired_version = '5.0.0'
) {
  String $custom_url_file = 'puppet:///modules/archive/url_list/packages_url.txt',
  String $prod_url  = 'https://packages.wazuh.com/packages_url.txt',
  String $destination = '/tmp/packages_url.txt',
  String $rpm_based = 'RedHat|Suse|Amazon|OracleLinux|AlmaLinux|Rocky',
  String $deb_based = 'Debian|Ubuntu|Mint|Kali|Raspbian',

  # Determine the package type (rpm or deb) based on the operating system family
  # This is necessary because different Linux distributions use different package formats.
  # The correct package type must be identified to download and install the appropriate package.
  if $facts['os']['family'] =~ Regexp($rpm_based) {
    $package_type = 'rpm'
    $install_command = "/bin/rpm -ivh ${download_dir}/${package_name}-${package_version}-${package_arch}.${package_type}"
    $check_command = "/bin/rpm -q ${package_name}"
  } elsif $facts['os']['family'] =~ Regexp($deb_based) {
    $package_type = 'deb'
    $install_command = "/usr/bin/dpkg -i ${download_dir}/${package_name}-${package_version}-${package_arch}.${package_type}"
    $check_command = "/usr/bin/dpkg-query -l ${package_name}"
  } else {
    fail("Unsupported OS family: ${facts['os']['family']}")
  }

  $package_arch = $facts['architecture'] ? {
    'x86_64' => 'amd64',
    default  => $facts['architecture'],
  }

  # Check if the file exists in the remote location..
  file { $destination:
    ensure => file,
    source => $remote_path,
    mode   => '0644',
    notify => Exec['fetch_backup_file'],
  }

  # If the file cannot be copied from the module, it is downloaded from the prod URL.
  exec { 'fetch_backup_file':
    command     => "/usr/bin/curl -o ${destination} ${prod_url}",
    path        => ['/usr/bin', '/bin'],
    refreshonly => true,
    creates     => $destination,
  }

  # Build a pattern to find the package
  $package_pattern = "${package_name}-${package_version}-${package_arch}.${package_type}"

  # Read the file to obtain the package URL
  exec { "find_${package_pattern}_in_file":
    command     => "/bin/grep -E '^${package_pattern}:' ${key_value_file} | cut -d':' -f2 > $destination",
    path        => ['/bin', '/usr/bin'],
    logoutput   => true,
    returns     => [0],
  }

  # Read the URL from the temp file
  file_line { 'read_package_url':
    path    => $destination,
    require => Exec["find_${package_pattern}_in_file"],
    match   => '.*',
    line    => $package_url,
  }

  # Check that the package is installed
  exec { "check_${package_name}_installed":
    command     => $check_command,
    path        => ['/bin', '/usr/bin'],
    returns     => [0],
    unless      => $check_command,
  }

  # Install the package if it is not installed
  exec { "install_${package_pattern}":
    command     => $install_command,
    path        => ['/bin', '/usr/bin'],
    require     => Exec["download_${package_pattern}"],
    unless      => $check_command, # Idempotencia asegurada
    logoutput   => true,
  }
}







