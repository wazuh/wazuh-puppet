class install_product (
  String $package_name,
  String $desired_version = '5.0.0'
) {
  $json_file = '/tmp/package_urls.json'

  # Determine the package type (rpm or deb) based on the operating system family
  # This is necessary because different Linux distributions use different package formats.
  # The correct package type must be identified to download and install the appropriate package.
  $package_type = $facts['os']['family'] ? {
    /(RedHat|Suse|Amazon|OracleLinux|AlmaLinux|Rocky)/ => 'rpm',
    /(Debian|Ubuntu|Mint|Kali|Raspbian)/               => 'deb',
    default                                            => fail("Unsupported operating system"),
  }

  $package_arch = $facts['os']['architecture']

  # Download the JSON file
  file { $json_file:
    ensure => file,
    source => 'http://example.com/package_urls.json',
    mode   => '0644',
  }

  # Read and parse the JSON
  $packages = parsejson(file($json_file))

  # Filter the correct package
  $selected_package = $packages.filter |$pkg| {
    ($pkg['package_type'] == $package_type) and
    ($pkg['package_arch'] == $package_arch) and
    ($pkg['version'] == $desired_version) and
    ($pkg['name'] == $package_name)
  }

  # Ensure a package was found
  if empty($selected_package) {
    fail("No package found matching the criteria: type=${package_type}, architecture=${package_arch}, version=${desired_version}, name=${package_name}")
  }

  # Extract the URL of the selected package
  $package_url = $selected_package[0]['url']

  # Check if the package is already installed
  exec { "check_${package_name}_installed":
    command => "/bin/rpm -q ${package_name} || /usr/bin/dpkg-query -l ${package_name}",
    path    => ['/bin', '/usr/bin'],
    returns => [0],
    onlyif  => "/bin/true", # Always executed to verify
    logoutput => true,
  }

  # Install the package if not already installed
  exec { "install_${package_name}":
    command => "/usr/bin/curl -o /tmp/${package_name}.${package_type} ${package_url} && \
                /usr/bin/${package_type} -i /tmp/${package_name}.${package_type}",
    path    => ['/bin', '/usr/bin'],
    unless  => "/bin/rpm -q ${package_name} || /usr/bin/dpkg-query -l ${package_name}",
    require => File[$json_file],
  }
}







