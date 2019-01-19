#!/usr/bin/python

# Copyright: (c) 2019, Colin Nolan <cn580@alumni.york.ac.uk>
# MIT License

import configparser
from configparser import ParsingError
import os
from enum import unique, Enum
from typing import Dict, Tuple

from ansible.module_utils.basic import AnsibleModule

ANSIBLE_MANAGED_LINE = "# Managed by Ansible"
JAIL_FILE_EXTENSION = "conf"

DEFAULT_ENABLED_VALUE = True
DEFAULT_PRESENT_VALUE = True
DEFAULT_JAIL_DIRECTORY_VALUE = "/etc/fail2ban/jail.d"
DEFAULT_FORCE_VALUE = False


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
FORCE_PARAMETER = "force"

ANSIBLE_ARGUMENT_SPEC = {
    AnsibleFail2BanParameter.NAME.value[0]: dict(type="str", required=True),
    AnsibleFail2BanParameter.ENABLED.value[0]: dict(type="bool", default=DEFAULT_ENABLED_VALUE),
    AnsibleFail2BanParameter.PORT.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.FILTER.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.LOG_PATH.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.MAX_RETRY.value[0]: dict(type="int"),
    AnsibleFail2BanParameter.FIND_TIME.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.BAN_TIME.value[0]: dict(type="str"),
    AnsibleFail2BanParameter.ACTION.value[0]: dict(type="str"),
    PRESENT_PARAMETER: dict(type="bool", default=DEFAULT_PRESENT_VALUE),
    JAILS_DIRECTORY_PARAMETER: dict(type="str", default=DEFAULT_JAIL_DIRECTORY_VALUE),
    FORCE_PARAMETER: dict(type="bool", default=DEFAULT_FORCE_VALUE)
}


# def is_ansible_managed(file_path: str) -> bool:
def is_ansible_managed(file_path):
    """
    Gets whether the fail2ban configuration file at the given path is managed by Ansible.
    :param file_path: the file to check if managed by Ansible
    :return: whether the file is managed by Ansible
    """
    with open(file_path, "r") as file:
        return file.readline().strip() == ANSIBLE_MANAGED_LINE


# def write_configuration(name: str, configuration: Dict[str, str], jails_directory: str):
def write_configuration(name, configuration, jails_directory):
    """
    Writes the given configuration as a jail configuration file.
    :param name: the name of the jail
    :param configuration: the jail's fail2ban configuration
    :param jails_directory: the directory storing the jails
    """
    file_path = get_config_file_path(name, jails_directory)
    config_parser = configparser.ConfigParser()
    config_parser.read_dict({name: configuration})
    with open(file_path, "w") as file:
        file.write("%s\n" % (ANSIBLE_MANAGED_LINE, ))
        config_parser.write(file)
    assert is_ansible_managed(file_path)


# def read_configuration(file_path: str) -> Tuple[str, Dict[str, str]]:
def read_configuration(file_path):
    """
    Reads the configuration file with the given path.
    :param file_path: path to configuration file
    :return: tuple where the first element is the name of the jail in the file and the second is the configuration
    :raises SyntaxError: raised if the contents of the configuration file cannot be parsed
    """
    config_parser = configparser.ConfigParser()
    try:
        config_parser.read(file_path)
        sections = config_parser.sections()
    except ParsingError as e:
        raise SyntaxError() from e

    if len(sections) == 0:
        raise SyntaxError("Config file does not contain any sections")
    elif len(sections) > 1:
        raise SyntaxError("Cannot parse config with multiple sections")
    name = sections[0]
    return name, dict(config_parser[name])


# def get_config_file_path(name: str, jails_directory: str) -> str:
def get_config_file_path(name, jails_directory):
    """
    Gets the path of the configuration file with the given name in the given jails directory.
    :param name: name of the configuration file
    :param jails_directory: jails directory
    :return: configuration file path
    """
    return os.path.join(jails_directory, "%s.%s" % (name, JAIL_FILE_EXTENSION))


# def run(configuration: Dict, check_mode: bool=False) -> Tuple[bool, Dict]:
def run(configuration, check_mode=False):
    """
    Run the fail2ban jail module (not coupled to Ansible!).
    :param configuration: input configuration
    :param check_mode: whether to run in checked mode (dry mode)
    :return: tuple where the first element is `True` if the run was successful and the second is information about the
    run
    """
    present = configuration.get(PRESENT_PARAMETER)
    name = configuration.get(AnsibleFail2BanParameter.NAME.value[0])
    jails_directory = configuration.get(JAILS_DIRECTORY_PARAMETER)
    file_path = get_config_file_path(name, jails_directory)
    exists = os.path.exists(file_path)
    force = configuration.get(FORCE_PARAMETER)

    max_retries = configuration.get(AnsibleFail2BanParameter.MAX_RETRY.value[0])
    configuration = dict(filter(lambda x: x[1] is not None, {
        AnsibleFail2BanParameter.ENABLED.value[1]: "true" if configuration.get(
            AnsibleFail2BanParameter.ENABLED.value[0]) else "false",
        AnsibleFail2BanParameter.PORT.value[1]: configuration.get(AnsibleFail2BanParameter.PORT.value[0]),
        AnsibleFail2BanParameter.FILTER.value[1]: configuration.get(AnsibleFail2BanParameter.FILTER.value[0]),
        AnsibleFail2BanParameter.LOG_PATH.value[1]: configuration.get(AnsibleFail2BanParameter.LOG_PATH.value[0]),
        AnsibleFail2BanParameter.MAX_RETRY.value[1]: str(max_retries) if max_retries is not None else None,
        AnsibleFail2BanParameter.FIND_TIME.value[1]: configuration.get(AnsibleFail2BanParameter.FIND_TIME.value[0]),
        AnsibleFail2BanParameter.BAN_TIME.value[1]: configuration.get(AnsibleFail2BanParameter.BAN_TIME.value[0]),
        AnsibleFail2BanParameter.ACTION.value[1]: configuration.get(AnsibleFail2BanParameter.ACTION.value[0])
    }.items()))

    if exists and not is_ansible_managed(file_path) and not force:
        return False, dict(msg="Cannot work with config file as it is not managed by Ansible (set `force=yes` to "
                               "override): %s" % (file_path, ),
                           configuration=configuration)

    if not present:
        if exists and not check_mode:
            os.remove(file_path)
        return True, dict(changed=exists, configuration=configuration)
    else:
        if not exists:
            if not check_mode:
                write_configuration(name, configuration, jails_directory)
            return True, dict(changed=True, configuration=configuration)
        else:
            try:
                current_name, current_configuration = read_configuration(file_path)
            except SyntaxError as e:
                if not force:
                    return False, dict(msg="Cannot read configuration file (set `force=yes` to overwrite without "
                                           "reading: %s" % (file_path, ), configuration=configuration)
                current_name = None
                current_configuration = {}

            if current_configuration != configuration or current_name != name:
                if not check_mode:
                    write_configuration(name, configuration, jails_directory)
                return True, dict(changed=True, previous_configuration=current_configuration,
                                  configuration=configuration)
            else:
                return True, dict(changed=False, configuration=configuration)


def main():
    """
    Main method, called by Ansible.
    """
    module = AnsibleModule(ANSIBLE_ARGUMENT_SPEC, supports_check_mode=True)
    success, information = run(module.params, module.check_mode)
    call_method = module.exit_json if success else module.fail_json
    call_method(**information)


if __name__ == "__main__":
    main()
