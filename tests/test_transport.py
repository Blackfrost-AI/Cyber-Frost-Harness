import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cyber_frost_harness.transport import (
    CommandResult,
    DockerTransport,
    _validate_remote_path,
    image_for_task,
)
from cyber_frost_harness.target import TARGET_RE


class TransportTests(unittest.TestCase):
    def test_exec_spools_and_bounds_large_container_output(self):
        config = SimpleNamespace(
            transport="local-docker",
            command_timeout_seconds=60,
        )
        transport = DockerTransport(config)
        command_result = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        cleanup_result = SimpleNamespace(returncode=0, stdout=b"0\n", stderr=b"")
        stat_result = SimpleNamespace(returncode=0, stdout=str(300000).encode(), stderr=b"")
        head_result = SimpleNamespace(returncode=0, stdout=b"h" * 65536, stderr=b"")
        tail_result = SimpleNamespace(returncode=0, stdout=b"t" * 65536, stderr=b"")
        empty_stat = SimpleNamespace(returncode=0, stdout=b"0", stderr=b"")
        empty_cat = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with patch.object(
            transport,
            "_run_host",
            side_effect=[
                command_result,
                cleanup_result,
                stat_result,
                head_result,
                tail_result,
                empty_stat,
                empty_cat,
            ],
        ) as run_host:
            result = transport.exec("cfh-test", "cat /out/large", timeout=10)

        invoked = run_host.call_args_list[0].args[0]
        self.assertIn("/workspace/.cfh-command-logs", invoked)
        self.assertIn("--env", invoked)
        self.assertTrue(any(str(item).startswith("CFH_EXEC_TOKEN=") for item in invoked))
        self.assertEqual(result.stdout_bytes, 300000)
        self.assertTrue(result.stdout_truncated)
        self.assertIn("bytes omitted", result.stdout)
        self.assertGreater(len(result.stdout), 131072)
        self.assertLess(len(result.stdout), 131300)
        self.assertTrue(result.stdout.startswith("h" * 100))
        self.assertTrue(result.stdout.endswith("t" * 100))
        self.assertEqual(result.stderr_bytes, 0)
        self.assertEqual(result.cleaned_processes, 0)

    def test_create_uses_init_and_pid_ceiling(self):
        config = SimpleNamespace(
            transport="local-docker",
            container_prefix="cfh",
            network="none",
            cpus=24,
            memory="96g",
            pids_limit=256,
            sanitizer_compat=False,
            command_timeout_seconds=60,
        )
        transport = DockerTransport(config)
        ok = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        clean = CommandResult("sanitize", 0, "", "", 0.1)
        with patch.object(transport, "image_exists", return_value=True), patch.object(
            transport, "_run_host", side_effect=[ok, ok]
        ) as run_host, patch.object(transport, "exec", return_value=clean):
            transport.create("arvo:8696", run_label="test")

        create = run_host.call_args_list[0].args[0]
        self.assertIn("--init", create)
        self.assertEqual(create[create.index("--pids-limit") + 1], "256")

    def test_wrapper_target_regex_preserves_fuzztest_name(self):
        wrapper = "/out/enc_fuzzer@Enc.EncTest /tmp/poc"
        self.assertEqual(TARGET_RE.findall(wrapper), ["enc_fuzzer@Enc.EncTest"])

    def test_maps_only_vulnerable_images(self):
        self.assertEqual(image_for_task("arvo:8696"), "n132/arvo:8696-vul")
        self.assertEqual(
            image_for_task("oss-fuzz:42537493"),
            "cybergym/oss-fuzz:42537493-vul",
        )

    def test_rejects_unknown_task_family(self):
        with self.assertRaises(ValueError):
            image_for_task("other:123")

    def test_container_path_boundaries(self):
        self.assertEqual(_validate_remote_path("/workspace/a.bin"), "/workspace/a.bin")
        with self.assertRaises(ValueError):
            _validate_remote_path("/etc/shadow")
        with self.assertRaises(ValueError):
            _validate_remote_path("/workspace/../etc/shadow")
        with self.assertRaises(ValueError):
            _validate_remote_path("/src/file", writable=True)


if __name__ == "__main__":
    unittest.main()
