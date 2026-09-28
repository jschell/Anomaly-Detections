import siem_anomaly as sa


def test_package_imports() -> None:
    assert sa.__version__ == "0.1.0"
    assert callable(sa.open_engagement)
