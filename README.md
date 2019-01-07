[![Build Status](https://travis-ci.org/colin-nolan/fail2ban-ansible-modules.svg?branch=master)](https://travis-ci.org/colin-nolan/fail2ban-ansible-modules)
[![codecov](https://codecov.io/gh/colin-nolan/fail2ban-ansible-modules/branch/master/graph/badge.svg)](https://codecov.io/gh/colin-nolan/fail2ban-ansible-modules)

# Fail2ban Ansible Modules
_Ansible modules for configuring Fail2ban_

## Requirements
- Python 3.5+
- Ansible 2.5+

## Modules
### Jails
The `fail2ban_jail.py` module manages Fail2ban jails.

#### Examples
##### Add Jail
```yaml
fail2ban_jail:
  name: ssh
  enabled: true
  port: ssh
  filter: sshd
  logpath: /var/log/auth.log
  maxretry: 6
```
Note: `enabled: false` does not remove the jail's configuration file. See [Remove Jail](#remove-jail) for details on how
to do this.

##### Remove Jail
```yaml
fail2ban_jail:
  name: ssh
  present: false
  jail_directory: /etc/fail2ban/jail.d
```

## License
[MIT](LICENSE.txt).
