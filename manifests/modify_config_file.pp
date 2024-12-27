class wazuh::modify_config_file (
  String $config_file,                     # Path to the configuration file
  Array[String] $config_lines,             # Array of configurations to modify or add
  Enum['yaml', 'xml'] $file_type,          # File type: yaml or xml
  Boolean $replace_all = true              # Replace entire content (default true)
) {

  # Convert all configuration keys to lowercase
  $normalized_config_lines = $config_lines.map |$line| {
    regsubst($line, '^([^:]+):', '\l\1:', 'G') # Convert parameter names to lowercase
  }

  if $replace_all {
    # Replace the entire file content
    replace { "replace_all_${config_file}":
      path    => $config_file,
      pattern => '.*', # Match the entire file content
      replace => $normalized_config_lines.join("\n"), # Replace with normalized lines
    }
  } else {
    # Add configurations at the end of the file
    $normalized_config_lines.each |$line| {
      replace { "add_line_${line}":
        path             => $config_file,
        pattern          => "^${regsubst($line, '^([^:]+):.*$', '\\1', 'G')}.*$", # Match the key
        replace          => $line, # Replace the line if it exists
        append_on_no_match => true, # Add the line if it does not exist
      }
    }
  }

  # Specific handling for XML files
  if $file_type == 'xml' {
    $normalized_config_lines.each |$line| {
      $key = regsubst($line, '^<([^>]+)>.*$', '\\1', 'G') # Extract the XML tag
      replace { "modify_xml_${key}":
        path    => $config_file,
        pattern => "<${key}>.*?</${key}>", # Match the complete XML block
        replace => $line, # Replace the entire block if it exists
        append_on_no_match => true, # Add the XML block if it does not exist
      }
    }
  }
}
