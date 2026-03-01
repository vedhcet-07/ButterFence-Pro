"""Tests for rule pack manager."""
import pytest
import yaml
from pathlib import Path
from butterfence.packs import list_packs, get_pack_info, install_pack, PackInfo
from butterfence.config import DEFAULT_CONFIG, save_config, load_config

class TestListPacks:
    def test_list_builtin_packs(self):
        packs = list_packs()
        assert len(packs) >= 7
        names = {p.name for p in packs}
        assert "owasp" in names
        assert "aws" in names

    def test_list_empty_directory(self, tmp_path):
        packs = list_packs(tmp_path)
        assert len(packs) == 0

    def test_pack_info_fields(self):
        packs = list_packs()
        for p in packs:
            assert isinstance(p, PackInfo)
            assert p.name
            assert p.version
            assert p.author

class TestGetPackInfo:
    def test_existing_pack(self):
        info = get_pack_info("aws")
        assert info is not None
        assert info.name == "aws"
        assert len(info.categories) > 0

    def test_nonexistent_pack(self):
        info = get_pack_info("nonexistent_pack_xyz")
        assert info is None

class TestInstallPack:
    def _setup_project(self, tmp_path):
        bf_dir = tmp_path / ".butterfence"
        bf_dir.mkdir()
        save_config(DEFAULT_CONFIG, tmp_path)
        return tmp_path

    def test_install_pack(self, tmp_path):
        project = self._setup_project(tmp_path)
        success = install_pack("aws", project)
        assert success is True
        config = load_config(project)
        assert "aws" in config.get("installed_packs", [])

    def test_install_nonexistent(self, tmp_path):
        project = self._setup_project(tmp_path)
        success = install_pack("nonexistent_xyz", project)
        assert success is False

    def test_idempotent_install(self, tmp_path):
        project = self._setup_project(tmp_path)
        install_pack("aws", project)
        config1 = load_config(project)

        install_pack("aws", project)
        config2 = load_config(project)

        # Pack should only appear once
        assert config2["installed_packs"].count("aws") == 1

    def test_install_adds_categories(self, tmp_path):
        project = self._setup_project(tmp_path)
        install_pack("aws", project)
        config = load_config(project)
        # AWS pack should add aws-related categories
        categories = config.get("categories", {})
        aws_cats = [c for c in categories if "aws" in c.lower()]
        assert len(aws_cats) >= 1

    def test_custom_packs_dir(self, tmp_path):
        project = self._setup_project(tmp_path)
        packs_dir = tmp_path / "custom_packs"
        packs_dir.mkdir()
        pack_file = packs_dir / "test.yaml"
        pack_file.write_text(yaml.dump({
            "name": "test",
            "version": "1.0.0",
            "author": "test",
            "description": "Test pack",
            "categories": {
                "test_cat": {
                    "enabled": True,
                    "severity": "high",
                    "action": "block",
                    "patterns": ["test_pattern"],
                    "safe_list": [],
                }
            }
        }))
        success = install_pack("test", project, packs_dir)
        assert success is True
        config = load_config(project)
        assert "test_cat" in config["categories"]
