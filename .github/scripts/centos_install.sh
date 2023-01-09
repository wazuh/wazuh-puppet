rpm -Uvh https://yum.puppet.com/puppet7-release-el-8.noarch.rpm
yum -y install puppetserver
ln -s /opt/puppetlabs/bin/puppet /bin
ln -s /opt/puppetlabs/server/bin/puppetserver /bin
echo "[main]" | tee -a /etc/puppetlabs/puppet/puppet.conf > /dev/null
echo "server = "$HOSTNAME | tee -a /etc/puppetlabs/puppet/puppet.conf > /dev/null
echo "dns_alt_names = "$HOSTNAME | tee -a /etc/puppetlabs/puppet/puppet.conf > /dev/null
echo "127.0.0.1 puppet" | tee -a /etc/hosts > /dev/null
cat /etc/puppetlabs/puppet/puppet.conf
service puppetserver start
puppet module install /tmp/wazuh-wazuh-$VERSION.tar.gz
hostname=$(puppetserver ca list --all | awk '{if(NR>1)print $1;}')
echo "127.0.0.1 "$hostname | tee -a /etc/hosts > /dev/null
echo "node "\"$hostname\"" {" | tee -a /etc/puppetlabs/code/environments/production/manifests/stack.pp  > /dev/null
echo "class {'wazuh::manager':} ->  class {'wazuh::indexer':} -> class {'wazuh::filebeat_oss':} -> class {'wazuh::dashboard':}" | sudo tee -a /etc/puppetlabs/code/environments/production/manifests/stack.pp > /dev/null
echo "}" | tee -a /etc/puppetlabs/code/environments/production/manifests/stack.pp > /dev/null
cat /etc/puppetlabs/code/environments/production/manifests/stack.pp
bash -c 'puppet agent -tod || test $? -eq 2'