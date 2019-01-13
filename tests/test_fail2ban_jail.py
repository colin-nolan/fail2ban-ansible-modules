import os
import random
import shutil
import sys
import unittest
from tempfile import mkdtemp
from typing import Dict, Tuple
from uuid import uuid4

from fail2ban_jail import ANSIBLE_ARGUMENT_SPEC, PRESENT_PARAMETER, run, JAILS_DIRECTORY_PARAMETER, \
    read_configuration, get_config_file_path, AnsibleFail2BanParameter, ANSIBLE_MANAGED_LINE

_ANSIBLE_NAME_PARAMETER = AnsibleFail2BanParameter.NAME.value[0]


class TestFail2banJailModule(unittest.TestCase):
    """
    Tests for `fail2ban_jail` Ansible module.
    """
    @staticmethod
    def _generate_ansible_arguments(jails_directory: str, present: bool=True, name: str=None) -> Tuple[str, Dict]:
        """
        Generates Ansible arguments for the fail2ban_jail module.
        :param present: whether the jail should be present
        :param jails_directory: the directory in which jails are located
        :param name: name of the jail
        :return: tuple where the first element is the name of the jail and the second is the Ansible arguments that can
        be used to create it
        """
        arguments = {}
        argument_spec = ANSIBLE_ARGUMENT_SPEC if present else dict(
            filter(lambda x: x[0] == _ANSIBLE_NAME_PARAMETER, ANSIBLE_ARGUMENT_SPEC.items()))

        for key, specification in argument_spec.items():
            value = {
                "bool": bool(random.getrandbits(1)),
                "int": random.randint(1, sys.maxsize),
                "str": str(uuid4())
            }[specification["type"]]
            arguments[key] = value

        if name:
            arguments[_ANSIBLE_NAME_PARAMETER] = name

        arguments[PRESENT_PARAMETER] = present
        arguments[JAILS_DIRECTORY_PARAMETER] = jails_directory
        return arguments[_ANSIBLE_NAME_PARAMETER], arguments

    def setUp(self):
        self.jails_directory = mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.jails_directory)

    def test_read_configuration(self):
        # Testing separately as relied upon in `_assert_matching_configuration`
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        file_path = get_config_file_path(jail_name, self.jails_directory)
        with open(file_path, "w") as file:
            print(ANSIBLE_MANAGED_LINE, file=file)
            print("[%s]" % (jail_name, ), file=file)
            for parameter in AnsibleFail2BanParameter:
                print("%s=%s" % (parameter.value[1], arguments[parameter.value[0]]), file=file)

        name, configuration = read_configuration(file_path)
        self.assertEquals(jail_name, name)
        for parameter in AnsibleFail2BanParameter:
            self.assertEquals(str(arguments[parameter.value[0]]), configuration[parameter.value[1]])

    def test_add_jail(self):
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        success, output = run(arguments)
        self.assertTrue(success)
        self.assertTrue(output["changed"])
        self._assert_matching_configuration(jail_name, arguments)

    def test_add_jail_without_max_retry_defined(self):
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        max_retry_parameter = AnsibleFail2BanParameter.MAX_RETRY.value[0]
        del arguments[max_retry_parameter]
        success, output = run(arguments)
        assert success
        self.assertNotIn(max_retry_parameter, arguments)

    def test_add_jail_checked_mode(self):
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        success, output = run(arguments, True)
        self.assertTrue(success)
        self.assertTrue(output["changed"])
        self.assertFalse(os.path.exists(get_config_file_path(jail_name, self.jails_directory)))

    def test_change_jail(self):
        jail_name, original_arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        run(original_arguments)
        _, new_arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory, name=jail_name)
        success, output = run(new_arguments)
        self.assertTrue(success)
        self.assertTrue(output["changed"])
        self._assert_matching_configuration(jail_name, new_arguments)

    def test_change_jail_checked_mode(self):
        jail_name, original_arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        run(original_arguments)
        _, new_arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory, name=jail_name)
        success, output = run(new_arguments, True)
        self.assertTrue(success)
        self.assertTrue(output["changed"])
        self._assert_matching_configuration(jail_name, original_arguments)

    def test_no_change_jail(self):
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        run(arguments)
        success, output = run(arguments)
        self.assertTrue(success)
        self.assertFalse(output["changed"])
        self._assert_matching_configuration(jail_name, arguments)

    def test_change_non_managed_jail(self):
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        self._create_non_managed_jail(jail_name)
        success, output = run(arguments)
        self.assertFalse(success)

    def test_remove_existing_jail(self):
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        run(arguments)
        assert os.path.exists(get_config_file_path(jail_name, self.jails_directory))
        arguments[PRESENT_PARAMETER] = False
        success, output = run(arguments)
        self.assertTrue(success)
        self.assertTrue(output["changed"])
        self.assertFalse(os.path.exists(get_config_file_path(jail_name, self.jails_directory)))

    def test_remove_existing_jail_checked_mode(self):
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        run(arguments)
        self.assertTrue(os.path.exists(get_config_file_path(jail_name, self.jails_directory)))
        arguments[PRESENT_PARAMETER] = False
        success, output = run(arguments, True)
        self.assertTrue(success)
        self.assertTrue(output["changed"])
        self.assertTrue(os.path.exists(get_config_file_path(jail_name, self.jails_directory)))

    def test_remove_non_managed_jail(self):
        jail_name, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory)
        self._create_non_managed_jail(jail_name)
        success, output = run(arguments)
        self.assertFalse(success)

    def test_remove_non_existing_jail(self):
        _, arguments = TestFail2banJailModule._generate_ansible_arguments(self.jails_directory, present=False)
        success, output = run(arguments)
        self.assertTrue(success)
        self.assertFalse(output["changed"])

    def _assert_matching_configuration(self, jail_name: str, ansible_arguments: Dict):
        """
        Asserts that the configuration for the jail with the given name matches that implied by the Ansible arguments.
        :param jail_name: name of the jail to examine configuration of
        :param ansible_arguments: Ansible arguments that define what the jail configuration should be
        """
        name, configuration = read_configuration(get_config_file_path(jail_name, self.jails_directory))
        self.assertEqual(jail_name, name)

        for item in AnsibleFail2BanParameter:
            if item != AnsibleFail2BanParameter.NAME:
                expected = ansible_arguments[item.value[0]]
                if type(expected) == bool:
                    expected = "true" if expected else "false"
                if type(expected) == int:
                    expected = str(expected)

                actual = configuration[item.value[1]]
                self.assertEqual(expected, actual, "Expected \"%s\" as argument for fail2ban parameter \"%s\""
                                 % (expected, item.value[1]))

    def _create_non_managed_jail(self, name: str):
        """
        Creates a non managed jail with the given name.
        :param name: the name of the jail
        """
        with open(get_config_file_path(name, self.jails_directory), "w") as file:
            file.write("Ansible does not manage this file!")


if __name__ == "__main__":
    unittest.main()
