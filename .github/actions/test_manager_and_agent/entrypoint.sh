#! /usr/bin/env bash
set -e

echo `systemctl status`
echo `ls -lah`
echo `git status`
echo `git branch`


cd kitchen

mkdir -p modules/wazuh

cd .. && cp -r `ls -A | grep -v "kitchen"` kitchen/modules/wazuh/

cd kitchen # Access kitchen folder

echo "Kitchen is creating the new instances"
echo "Executing bundle"

bundle install
bundle exec kitchen test

echo 'cat ~/.kitchen/logs/default-ubuntu-18.log'
echo 'cat ~/.kitchen/logs/default-centos-7.log'
