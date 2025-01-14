# Class to modify configuration files (YAML or XML)
#
# @param file_path The path to the configuration file to be modified
# @param key_value_pairs An array of key-value pairs to be updated in the configuration file
class wazuh::modify_config_file (
  String $file_path,
  Array $key_value_pairs,
) {
  # Ensure the file exists before modifying it
  file { $file_path:
    ensure => 'file',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }

  # Iterate through the key-value pairs and handle each entry
  $key_value_pairs.each |$pair| {
    if $pair =~ /^([^:]+):\s*(.+)$/ {
      $key   = $1   # Extract the key
      $value = $2   # Extract the value

      # Use exec to either modify the existing line or append a new one
      exec { "set_${key}_in_${file_path}":
        command => "grep -q '^${key}:' ${file_path} && sed -i 's/^${key}:.*$/${key}: ${value}/' ${file_path} || echo '${key}: ${value}' >> ${file_path}",
        path    => ['/bin', '/usr/bin'], # Define the search path for shell commands
        unless  => "grep -q '^${key}: ${value}$' ${file_path}", # Skip if the line already matches the desired value
        require => File[$file_path],    # Ensure the file resource is applied first
      }
    } else {
      # Fail if the key-value pair does not match the expected format
      fail("The line format '${pair}' is incorrect. It should be 'key: value'")
    }
  }
}
