"""Regression coverage for the nginx shipped by Ubuntu 22.04 and 24.04."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("web_supervisor", Path(__file__).with_name("supervisor.py"))
SUPERVISOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPERVISOR)


class UbuntuNginxCompatibilityTests(unittest.TestCase):
    def test_no_new_nginx_cli_flags_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            instance=SUPERVISOR.Supervisor.__new__(SUPERVISOR.Supervisor)
            instance.nginx="/usr/sbin/nginx"
            instance.directory=Path(directory)
            self.assertEqual(instance.command("nginx"),["/usr/sbin/nginx","-p",directory+"/","-c",directory+"/nginx.conf"])

    def test_error_logging_is_in_configuration_not_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            nginx,_,_,_=SUPERVISOR.render(directory,{"acme":"127.0.0.1:19080","nodes":[]})
            self.assertIn("error_log stderr warn;",nginx)
