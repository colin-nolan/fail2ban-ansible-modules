import configparser
import os
from typing import Dict, Tuple

from ansible.module_utils.basic import AnsibleModule

ANSIBLE_MANAGED_LINE = "# Managed by Ansible"
JAIL_FILE_EXTENSION = "conf"

DEFAULT_ENABLED = True
DEFAULT_PRESENT = True
DEFAULT_JAIL_DIRECTORY = "/etc/fail2ban/jail.d"

JAIL_NAME_PARAMETER = "name"
JAIL_ENABLED_PARAMETER = "enabled"
JAIL_PORT_PARAMETER = "port"
JAIL_FILTER_PARAMETER = "filter"
JAIL_LOG_PATH_PARAMETER = "logpath"
JAIL_MAX_RETRY_PARAMETER = "maxretry"
JAIL_FIND_TIME_PARAMETER = "findtime"
JAIL_BAN_TIME_PARAMETER = "bantime"
JAIL_ACTION_PARAMETER = "action"
PRESENT_PARAMETER = "present"
JAILS_DIRECTORY_PARAMETER = "jail_directory"

FAIL2BAN_NAME_PARAMETER = "name"
FAIL2BAN_ENABLED_PARAMETER = "enabled"
FAIL2BAN_PORT_PARAMETER = "port"
FAIL2BAN_FILTER_PARAMETER = "filter"
FAIL2BAN_LOG_PATH_PARAMETER = "logpath"
FAIL2BAN_MAX_RETRY_PARAMETER = "maxretry"
FAIL2BAN_FIND_TIME_PARAMETER = "findtime"
FAIL2BAN_BAN_TIME_PARAMETER = "bantime"
FAIL2BAN_ACTION_PARAMETER = "action"

_ARGUMENT_SPEC = {
    JAIL_NAME_PARAMETER: dict(type="str", required=True),
    JAIL_ENABLED_PARAMETER: dict(type="bool", default=DEFAULT_ENABLED),
    JAIL_PORT_PARAMETER: dict(type="str"),
    JAIL_FILTER_PARAMETER: dict(type="str"),
    JAIL_LOG_PATH_PARAMETER: dict(type="str"),
    JAIL_MAX_RETRY_PARAMETER: dict(type="int"),
    JAIL_FIND_TIME_PARAMETER: dict(type="str"),
    JAIL_BAN_TIME_PARAMETER: dict(type="str"),
    JAIL_ACTION_PARAMETER: dict(type="str"),
    JAILS_DIRECTORY_PARAMETER: dict(type="str"),
    PRESENT_PARAMETER: dict(type="bool", default=DEFAULT_PRESENT)
}


def is_ansible_managed(file_path: str) -> bool:
    """
    Gets whether the fail2ban configuration file at the given path is managed by Ansible.
    :param file_path: the file to check if managed by Ansible
    :return: whether the file is managed by Ansible
    """
    with open(file_path, "r") as file:
        return file.readline() == ANSIBLE_MANAGED_LINE


def write_config_file(name: str, configuration: Dict[str, str], file_path: str):
    """
    TODO
    :param name:
    :param configuration:
    :param file_path:
    """
    config_parser = configparser.ConfigParser()
    config_parser.read_dict(configuration)
    with open(file_path, "w") as file:
        file.write("%s\n" % (ANSIBLE_MANAGED_LINE, ))
        config_parser.write(file)
    assert is_ansible_managed(file_path)


def read_config_file(file_path: str) -> Tuple[str, Dict[str, str]]:
    """
    TODO
    :param file_path:
    :return: TODO
    :raises ValueError: raised if config file is not managed by Ansible
    :raises SyntaxError: raised if the contents of the configuration file are not as expected
    """
    if not is_ansible_managed(file_path):
        raise ValueError("Config file is not managed by Ansible")

    config_parser = configparser.ConfigParser()
    config_parser.read(file_path)

    sections = config_parser.sections()
    if len(sections) == 0:
        raise SyntaxError("Config file does not contain any sections")
    name = sections[0]
    return name, dict(config_parser[name])


def main():
    """
    TODO
    :return:
    """
    module = AnsibleModule(_ARGUMENT_SPEC, supports_check_mode=True)

    present = module.params.get(PRESENT_PARAMETER)
    name = module.params.get(JAIL_NAME_PARAMETER)
    file_path = os.path.join(module.params.get(JAILS_DIRECTORY_PARAMETER), name, ".%s" % (JAIL_FILE_EXTENSION, ))
    exists = os.path.exists(file_path)

    if exists and not is_ansible_managed(file_path):
        module.fail_json(msg="Cannot work with config file as it is not managed by Ansible: %s" % (file_path,))
        exit(1)

    if not present:
        if exists and not module.check_mode:
            os.remove(file_path)
        module.exit_json(changed=exists)
    else:
        required_configuration = {
            FAIL2BAN_ENABLED_PARAMETER: "true" if module.params.get(JAIL_ENABLED_PARAMETER) else "false",
            FAIL2BAN_PORT_PARAMETER: module.params.get(JAIL_PORT_PARAMETER),
            FAIL2BAN_FILTER_PARAMETER: module.params.get(JAIL_FILTER_PARAMETER),
            FAIL2BAN_LOG_PATH_PARAMETER: module.params.get(JAIL_LOG_PATH_PARAMETER),
            FAIL2BAN_MAX_RETRY_PARAMETER: str(module.params.get(JAIL_MAX_RETRY_PARAMETER)),
            FAIL2BAN_FIND_TIME_PARAMETER: module.params.get(JAIL_FIND_TIME_PARAMETER),
            FAIL2BAN_BAN_TIME_PARAMETER: module.params.get(JAIL_BAN_TIME_PARAMETER),
            FAIL2BAN_ACTION_PARAMETER: module.params.get(JAIL_ACTION_PARAMETER)
        }
        if not exists:
            if not module.check_mode:
                write_config_file(name, required_configuration, file_path)
            module.exit_json(changed=True)
            exit(1)
        else:
            current_configuration = read_config_file(file_path)
            if current_configuration != required_configuration:
                if not module.check_mode:
                    write_config_file(name, required_configuration, file_path)
                module.exit_json(changed=True, previous=current_configuration)
            else:
                module.exit_json(changed=False)
            exit(0)


if __name__ == "__main__":
    main()
