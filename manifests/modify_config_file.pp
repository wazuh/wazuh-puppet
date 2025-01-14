# Class to modify configuration files (YAML or XML)
#
# @param file_path The path to the configuration file to be modified
# @param key_value_pairs An array of key-value pairs to be updated in the configuration file
class wazuh::modify_config_file (
  String $file_path,
  Array $key_value_pairs,
) {

  # Define a function to check if a file exists
  file { $file_path:
    ensure  => file,
    content => "# Initial content\n",
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }

  # Read the file content
  $file_content = file($file_path, 'default' => '')

  # Iterate over the key-value pairs
  $key_value_pairs.each |$pair| {
    if ($pair =~ /^([^:]+):\s*(.+)$/) {
      $key = $1
      $value = $2

      # Escape the key to use it in a regular expression
      $escaped_key = $key.gsub(/([.*+?^${}()|\[\]\\])/, '\\\\\1')

      # Check if the key already exists in the file
      if $file_content =~ /^${escaped_key}:\s*(.+)?$/ {
        $new_content = regsubst($file_content, /^${escaped_key}:\s*(.+)?$/, "${key}: ${value}")
        file { $file_path:
          ensure  => file,
          content => $new_content,
        }
      } else {
        file { $file_path:
          ensure  => file,
          content => "${file_content}\n${key}: ${value}\n",
        }
      }
    } else {
      fail("The line format '${pair}' is incorrect. It should be 'key: value'")
    }
  }
}
