import zipfile

import build


def test_build_packages_handler_and_common_without_tests(tmp_path):
    [archive] = build.build(["account_collector"], tmp_path, skip_deps=True)
    names = zipfile.ZipFile(archive).namelist()
    assert "account_collector/handler.py" in names and "common/db.py" in names
    assert not any("__pycache__" in n or n.endswith(".pyc") or "/tests/" in n for n in names)
    assert not any(n.startswith("s3_log_ingestor/") for n in names)  # one function per zip
    assert (tmp_path / "step_functions.asl.json").exists()


def test_build_list_matches_lambda_packages():
    from tests.test_infra import LAMBDA_PACKAGES
    assert sorted(build.FUNCTIONS) == LAMBDA_PACKAGES
