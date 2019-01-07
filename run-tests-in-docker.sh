#!/usr/bin/env bash

set -euf -o pipefail

scriptDirectory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t fail2ban-ansible-modules-tests -f Dockerfile.test .
docker run --rm -it -v "${scriptDirectory}":/fail2ban-ansible-modules \
    fail2ban-ansible-modules-tests /fail2ban-ansible-modules/run-tests.sh

# Hack the paths in the coverage report (unfortunately they are absolute)
docker run --rm -it -v $PWD/:/data alpine sed -i -e "s|\"/fail2ban-ansible-modules|\"${scriptDirectory}|g" /data/.coverage
