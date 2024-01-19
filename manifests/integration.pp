# Copyright (C) 2015, Wazuh Inc.
#Define for a specific ossec integration
define wazuh::integration (
  String $service,
  Hash $params,
) {

#require wazuh::params_manager

notify { "integparams $service":
message => "params: $params; service: $service",
}

concat::fragment { $service:
    order   => 86,
    target  => 'manager_ossec.conf',
    content => epp('wazuh/fragments/_integration.epp', {
        servicename    => $service,
        hook_url       => $params[hook_url],
        api_key        => $params[api_key],
        rule_id        => $params[rule_id],
        level          => $params[level],
        group          => $params[group],
        event_location => $params[event_location],
        alert_format   => $params[alert_format],
        max_log        => $params[max_log],
}

)
  }
}
