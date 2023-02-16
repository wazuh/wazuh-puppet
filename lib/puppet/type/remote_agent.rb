Puppet::Type.newtype(:remote_agent) do
  ensurable do

    newvalue(:absent) do
      provider.destroy
    end

    newvalue(:present) do
      pass
    end

    defaultto :absent
  end
  
  newparam :name, :namevar => true
  newparam :api_username
  newparam :api_password
  newparam :api_host
  newparam :api_host_port
  
  validate do
    [:api_username, :api_password, :api_host, :api_host_port].each do |param|
      raise ArgumentError, "The #{param} parameter is required." unless self[param]
    end
  end
end
