"""Exercise the built distribution outside the source checkout."""

from email.parser import Parser
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import venv
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAMES = ("client", "core", "server", "utils", "benchmark", "data")
PRIVATE_SUFFIXES = (
    ".joblib", ".key", ".vault", ".vault.lock", ".pem", ".p12", ".pfx",
    ".sqlite", ".sqlite-wal", ".sqlite-shm",
)
INERT_ARTIFACTS = tuple("data/packaging-sentinel" + suffix for suffix in PRIVATE_SUFFIXES)
INERT_CONTENT = b"INERT packaging test sentinel; not a model, key, vault or database.\n"


def run_checked(command, cwd):
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True,
        encoding="utf-8", timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory):
    workspace = tmp_path_factory.mktemp("distribution")
    source = workspace / "source"
    source.mkdir()
    for name in ("setup.py", "pyproject.toml", "MANIFEST.in", "README.md", "LICENSE", "train_model.py"):
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, source / name)
    for requirements in ROOT.glob("requirements*.txt"):
        shutil.copy2(requirements, source / requirements.name)
    for package in PACKAGE_NAMES:
        (source / package).mkdir()
        for module in (ROOT / package).glob("*.py"):
            shutil.copy2(module, source / package / module.name)
    # Exercise distribution of generated public assets without requiring Node
    # in the Python-only suite. The release pipeline tests the real web build.
    static = source / "server" / "web_static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>Build fixture</title>", encoding="utf-8")
    (static / "assets" / "app.js").write_text("export const fixture = true;", encoding="utf-8")
    (static / "assets" / "crypto.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
    # These are plain inert bytes, created only in the temporary source copy.
    # Never copy or deserialize the repository's persisted private state.
    for relative_name in INERT_ARTIFACTS:
        (source / relative_name).write_bytes(INERT_CONTENT)
    # Make the inert files eligible for the sdist before the real exclusion rules.
    # This tests that global-exclude is effective, not merely that setuptools
    # happened to ignore non-Python files by default.
    manifest = source / "MANIFEST.in"
    manifest.write_text(
        "include " + " ".join(INERT_ARTIFACTS) + "\n" + manifest.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    output = workspace / "dist"
    run_checked(
        # The default builds an sdist, then builds the wheel from that archive.
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output), str(source)],
        cwd=workspace,
    )
    return next(output.glob("*.whl"))


def test_wheel_contains_application_packages(built_wheel):
    with zipfile.ZipFile(built_wheel) as archive:
        files = set(archive.namelist())
    expected = {
        "client/client.py", "core/auth.py", "core/crypto.py", "core/comm.py",
        "core/anomaly.py", "server/server.py", "server/session_manager.py",
        "utils/logger.py", "benchmark/performance_test.py", "data/training_data_generator.py",
        "client/app.py", "core/identity.py", "core/e2ee.py", "core/protocol.py",
        "core/transport.py", "core/relay_client.py", "server/relay.py",
    }
    assert expected <= files, f"Missing packaged modules: {sorted(expected - files)}"


def test_distributions_exclude_models_keys_and_local_state(built_wheel):
    source = built_wheel.parent.parent / "source"
    for relative_name in INERT_ARTIFACTS:
        sentinel = source / relative_name
        assert sentinel.is_file(), f"Missing input sentinel: {relative_name}"
        assert sentinel.read_bytes() == INERT_CONTENT

    with zipfile.ZipFile(built_wheel) as archive:
        wheel_files = archive.namelist()
    with tarfile.open(next(built_wheel.parent.glob("*.tar.gz")), "r:gz") as archive:
        sdist_files = archive.getnames()
    for format_name, files in (("wheel", wheel_files), ("sdist", sdist_files)):
        forbidden = [name for name in files if name.endswith(PRIVATE_SUFFIXES)]
        assert not forbidden, f"Unexpected artifacts in {format_name}: {forbidden}"


def test_runtime_dependencies_are_only_the_e2ee_and_http_stack(built_wheel):
    with zipfile.ZipFile(built_wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
    runtime = [item for item in metadata.get_all("Requires-Dist", []) if "extra ==" not in item]
    assert {item.split("<", 1)[0].split(">", 1)[0].split("=", 1)[0] for item in runtime} == {
        "cryptography", "vodozemac", "filelock", "aiohttp",
    }
    assert "vodozemac==0.10.0" in runtime
    assert "aiohttp==3.14.3" in runtime
    assert metadata["Requires-Python"] == ">=3.10"
    optional = metadata.get_all("Requires-Dist", [])
    assert any(item.startswith("scikit-learn") and 'extra == "legacy"' in item for item in optional)
    assert any(item.startswith("matplotlib") and 'extra == "training"' in item for item in optional)
    assert any(item.startswith("scikit-learn") and 'extra == "dev"' in item for item in optional)


def test_web_distribution_contains_bundled_assets_and_entrypoint(built_wheel):
    with zipfile.ZipFile(built_wheel) as archive:
        files = set(archive.namelist())
        assert {
            "server/web_static/index.html", "server/web_static/assets/app.js",
            "server/web_static/assets/crypto.wasm",
        } <= files
        entries = next(name for name in files if name.endswith(".dist-info/entry_points.txt"))
        assert "securecomm-web = server.web_server:main" in archive.read(entries).decode()


@pytest.fixture(scope="module")
def installed_scripts(built_wheel, tmp_path_factory):
    workspace = tmp_path_factory.mktemp("installed")
    environment = workspace / "env"
    # Install the app wheel into a fresh environment without inherited editable hooks.
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(environment)
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    run_checked(
        [str(python), "-m", "pip", "--isolated", "install", "--no-deps", "--no-index", str(built_wheel)],
        cwd=workspace,
    )
    # Reuse dependency directories without processing the development environment's
    # .pth files. Its editable checkout must not stand in for wheel modules.
    dependency_paths = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    installed_site = run_checked(
        [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        cwd=workspace,
    ).stdout.strip()
    (Path(installed_site) / "test_dependencies.pth").write_text(
        "\n".join(dependency_paths) + "\n", encoding="utf-8",
    )
    return workspace, scripts


@pytest.mark.parametrize("command", ["securecomm-client", "securecomm-server"])
def test_installed_console_scripts_display_help_outside_checkout(installed_scripts, command):
    workspace, scripts = installed_scripts
    executable = scripts / (command + (".exe" if os.name == "nt" else ""))
    before = {path.name for path in workspace.iterdir()}
    result = run_checked([str(executable), "--help"], cwd=workspace)
    assert "--port" in result.stdout
    assert "--host" in result.stdout
    assert {path.name for path in workspace.iterdir()} == before, "--help wrote local state"


def test_installed_entrypoints_use_wheel_modules_without_legacy_ml(installed_scripts):
    workspace, scripts = installed_scripts
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    result = run_checked(
        [str(python), "-I", "-c", "\n".join([
            "from pathlib import Path",
            "import sys",
            "import client.client, client.app, server.server, server.relay",
            "import core.identity, core.e2ee, core.protocol, core.transport, core.relay_client",
            "for name, module in list(sys.modules.items()):",
            "    if name.split('.')[0] in {'client', 'core', 'server'}:",
            "        assert Path(module.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()), name",
            "assert not any(name.split('.')[0] in {'sklearn', 'joblib', 'pandas', 'numpy'} for name in sys.modules)",
            "print('wheel-source-ok; no-legacy-ml-imports')",
        ])],
        cwd=workspace,
    )
    assert "wheel-source-ok; no-legacy-ml-imports" in result.stdout
