#! /usr/bin/env bash
set -e

echo "Env var value: IMAGE "
echo $IMAGE
echo "Env var value: PLATFORM "
echo $PLATFORM
echo "Env var value: RELEASE"
echo $RELEASE

cd kitchen

mkdir -p modules/wazuh

cd .. && cp -r `ls -A | grep -v "kitchen"` kitchen/modules/wazuh/

cd kitchen

echo "Installing dependencies"
bundle install

echo "Kitchen is creating the new instances"
bundle exec kitchen create

echo "Getting Wazuh managers IPs to the agents"
manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep manager`)"

echo "getting a copy of ./manifests/site.pp.template"
cp ./manifests/site.pp.template ./manifests/site.pp

echo "wazuh-manager IP"
echo $manager_ip

echo "Assigning Wazuh managers IPs to the corresponding agents."
echo `sed -i 's/manager_ip/'${manager_ip}'/g' ./manifests/site.pp`

echo `cat ./manifests/site.pp`

if [[ $PLATFORM == *"centos"* ]] || [[ $PLATFORM == *"rhel"* ]]; then
   echo "suite is a Centos one and requires OpenSSL to be installed. .. Installing .."
   bundle exec kitchen exec $PLATFORM -c "sudo yum install -y openssl"
fi

echo "Kitchen is converging ..."
bundle exec kitchen converge

echo "Sleeping while the agent is starting"
sleep 15

echo "Kitchen is testing ..."
bundle exec kitchen verify

echo "Kitchen is destroying"
bundle exec kitchen destroy
