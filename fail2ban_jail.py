import configparser
import os
from enum import unique, Enum
from typing import Dict, Tuple

from ansible.module_utils.basic import AnsibleModule

ANSIBLE_MANAGED_LINE = "# Managed by Ansible"
JAIL_FILE_EXTENSION = "conf"

DEFAULT_ENABLED = True
DEFAULT_PRESENT = True
DEFAULT_JAIL_DIRECTORY = "/etc/fail2ban/jail.d"

@unique
class AnsibleFail2BanParameter(Enum):
    """
    Mappings between Ansible and fail2ban properties.
    """
    NAME = ("name", "name")
    ENABLED = ("enabled", "enabled")
    PORT = ("port", "port")
    FILTER = ("filter", "filter")
    LOG_PATH = ("logpath", "logpath")
    MAX_RETRY = ("maxretry", "maxretry")
    FIND_TIME = ("findtime", "findtime")
    BAN_TIME = ("bantime", "bantime")
    ACTION = ("action", "action")


PRESENT_PARAMETER = "present"
JAILS_DIRECTORY_PARAMETER = "jail_directory"

ANSIBLE_ARGUMENT_SPEC = {
    AnsibleFail2BanParameter.NAME.value[0]: dict(type="str", required=True),
    AnsibleFail2BanParameter.ENABLED.value[0]: dict(type="bool", default=DEFAULT_ENABLED),
    AnsibleFail2BanParameter.PORT.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.FILTER.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.LOG_PATH.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.MAX_RETRY.value[0]: dict(type="int"),
    AnsibleFail2BanParameter.FIND_TIME.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.BAN_TIME.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.ACTION.value[0]: dict(type="str"),
    PRESENT_PARAMETER: dict(type="bool", default=DEFAULT_PRESENT),
    JAILS_DIRECTORY_PARAMETER: dict(type="str")
}


def is_ansible_managed(file_path: str) -> bool:
    """
    Gets whether the fail2ban configuration file at the given path is managed by Ansible.
    :param file_path: the file to check if managed by Ansible
    :return: whether the file is managed by Ansible
    """
    with open(file_path, "r") as file:
        return file.readline().strip() == ANSIBLE_MANAGED_LINE


def write_configuration(name: str, configuration: Dict[str, str], jails_directory: str):
    """
    TODO
    :param name:
    :param configuration:
    :param jails_directory:
    :return:
    """
    file_path = get_config_file_path(name, jails_directory)
    config_parser = configparser.ConfigParser()
    config_parser.read_dict({name: configuration})
    with open(file_path, "w") as file:
        file.write("%s\n" % (ANSIBLE_MANAGED_LINE, ))
        config_parser.write(file)
    assert is_ansible_managed(file_path)


def read_configuration(file_path: str) -> Tuple[str, Dict[str, str]]:
    """
    Reads the configuration file with the given path.
    :param file_path: path to configuration file
    :return: configuration file
    :raises ValueError: raised if config file is not managed by Ansible
    :raises SyntaxError: raised if the contents of the configuration file is not as expected
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


def get_config_file_path(name: str, jails_directory: str) -> str:
    """
    TODO
    :param name:
    :param jails_directory:
    :return:
    """
    return os.path.join(jails_directory, "%s.%s" % (name, JAIL_FILE_EXTENSION))


def run(configuration: Dict, check_mode: bool=False) -> Tuple[bool, Dict]:
    """
    TODO
    :param configuration:
    :param check_mode:
    :return:
    """
    present = configuration.get(PRESENT_PARAMETER)
    name = configuration.get(AnsibleFail2BanParameter.NAME.value[0])
    jails_directory = configuration.get(JAILS_DIRECTORY_PARAMETER)
    file_path = get_config_file_path(name, jails_directory)
    exists = os.path.exists(file_path)

    if exists and not is_ansible_managed(file_path):
        return False, dict(msg="Cannot work with config file as it is not managed by Ansible: %s" % (file_path,))

    if not present:
        if exists and not check_mode:
            os.remove(file_path)
        return True, dict(changed=exists)
    else:
        required_configuration = dict(filter(lambda x: x[1] is not None, {
            AnsibleFail2BanParameter.ENABLED.value[1]: "true" if configuration.get(AnsibleFail2BanParameter.ENABLED.value[0]) else "false",
            AnsibleFail2BanParameter.PORT.value[1]: configuration.get(AnsibleFail2BanParameter.PORT.value[0]),
            AnsibleFail2BanParameter.FILTER.value[1]: configuration.get(AnsibleFail2BanParameter.FILTER.value[0]),
            AnsibleFail2BanParameter.LOG_PATH.value[1]: configuration.get(AnsibleFail2BanParameter.LOG_PATH.value[0]),
            AnsibleFail2BanParameter.MAX_RETRY.value[1]: str(configuration.get(AnsibleFail2BanParameter.MAX_RETRY.value[0])),
            AnsibleFail2BanParameter.FIND_TIME.value[1]: configuration.get(AnsibleFail2BanParameter.FIND_TIME.value[0]),
            AnsibleFail2BanParameter.BAN_TIME.value[1]: configuration.get(AnsibleFail2BanParameter.BAN_TIME.value[0]),
            AnsibleFail2BanParameter.ACTION.value[1]: configuration.get(AnsibleFail2BanParameter.ACTION.value[0])
        }.items()))
        if not exists:
            if not check_mode:
                write_configuration(name, required_configuration, jails_directory)
            return True, dict(changed=True)
        else:
            current_name, current_configuration = read_configuration(file_path)
            if current_configuration != required_configuration or current_name != name:
                if not check_mode:
                    write_configuration(name, required_configuration, jails_directory)
                return True, dict(changed=True, previous=current_configuration)
            else:
                return True, dict(changed=False)


def main():
    """
    Main method, called by Ansible.
    """
    module = AnsibleModule(ANSIBLE_ARGUMENT_SPEC, supports_check_mode=True)
    check_mode = module.check_mode
    success, information = run(module.params, check_mode)
    if success:
        module.exit_json(**information)
    else:
        module.fail_json(**information)


if __name__ == "__main__":
    main()