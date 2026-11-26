"""scripts/set_llm_default.py, behind `make llm-default PROFILE=NAME` (ADR-038).

Run against temporary role-defaults and vars files: it must refuse an undefined name,
change only its one line, and never write into a file it cannot edit safely.
"""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("set_llm_default", ROOT / "scripts/set_llm_default.py")
sld = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sld)

DEFAULTS = """pipeline_default_llm_profile: local
pipeline_llm_profiles_builtin:
  stub: {cloud: false, model: stub}
"""
VARS = """# operator vars
cape_api_url: http://keep.me
pipeline_llm_profiles:
  haiku: {cloud: true, model: eval-haiku55}
"""


@pytest.fixture
def files(tmp_path):
    d, v = tmp_path / "defaults.yml", tmp_path / "vars.yml"
    d.write_text(DEFAULTS)
    v.write_text(VARS)
    return d, v


def test_it_appends_the_setting_and_changes_nothing_else(files):
    d, v = files
    assert sld.set_default("haiku", d, v) == "local"
    text = v.read_text()
    assert text.startswith(VARS) and text.rstrip().endswith("pipeline_default_llm_profile: haiku")


def test_a_second_change_replaces_the_line_in_place(files):
    d, v = files
    sld.set_default("haiku", d, v)
    assert sld.set_default("stub", d, v) == "haiku"
    text = v.read_text()
    assert text.count("pipeline_default_llm_profile:") == 1 and "pipeline_default_llm_profile: stub" in text
    assert "cape_api_url: http://keep.me" in text


@pytest.mark.parametrize("name", ["local", "stub", "haiku"])
def test_built_in_operator_and_local_profiles_are_accepted(files, name):
    d, v = files
    sld.set_default(name, d, v)
    assert f"pipeline_default_llm_profile: {name}" in v.read_text()


def test_an_undefined_profile_is_refused_and_nothing_is_written(files, capsys):
    d, v = files
    with pytest.raises(SystemExit) as e:
        sld.set_default("opus", d, v)
    assert e.value.code == 2
    assert "defined: local, stub, haiku" in capsys.readouterr().err
    assert v.read_text() == VARS


def test_a_vault_encrypted_vars_file_is_left_alone(files):
    d, v = files
    v.write_text("$ANSIBLE_VAULT;1.1;AES256\n6162\n")
    with pytest.raises(SystemExit, match="vault-encrypted"):
        sld.set_default("stub", d, v)
    assert v.read_text().startswith("$ANSIBLE_VAULT")


def test_the_real_role_defaults_ship_local():
    import yaml
    defaults = yaml.safe_load((ROOT / "ansible/roles/pipeline/defaults/main.yml").read_text())
    assert defaults["pipeline_default_llm_profile"] == "local"
