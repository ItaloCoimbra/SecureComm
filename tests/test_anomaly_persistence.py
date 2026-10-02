"""Persistence tests use only artifacts trained inside each temporary directory."""

from pathlib import Path
import runpy
import tempfile

import joblib
import pandas as pd
import pytest

from core import anomaly


@pytest.fixture
def isolated_artifacts(tmp_path, monkeypatch):
    """Fail before joblib can touch an artifact outside this test's directory."""
    original_dump = joblib.dump
    original_load = joblib.load
    original_temporary_directory = tempfile.TemporaryDirectory
    written_paths = []

    def checked_path(filename):
        path = Path(filename).resolve()
        if not path.is_relative_to(tmp_path.resolve()):
            pytest.fail(f"Artifact access escaped the temporary directory: {path}")
        return path

    def guarded_dump(value, filename, *args, **kwargs):
        path = checked_path(filename)
        written_paths.append(path)
        return original_dump(value, filename, *args, **kwargs)

    def guarded_load(filename, *args, **kwargs):
        checked_path(filename)
        return original_load(filename, *args, **kwargs)

    def temporary_directory(*args, **kwargs):
        return original_temporary_directory(*args, dir=tmp_path, **kwargs)

    monkeypatch.setattr(joblib, "dump", guarded_dump)
    monkeypatch.setattr(joblib, "load", guarded_load)
    monkeypatch.setattr(tempfile, "TemporaryDirectory", temporary_directory)
    return written_paths


@pytest.fixture
def training_features():
    return pd.DataFrame({
        "message_length": [100 + index * 10 for index in range(24)],
        "time_interval": [0.5 + (index % 4) * 0.1 for index in range(24)],
        "message_count_window": [1 + index % 5 for index in range(24)],
    })


def test_training_and_automatic_loading_use_instance_paths(
    tmp_path, isolated_artifacts, training_features
):
    model_path = tmp_path / "models" / "model.joblib"
    scaler_path = tmp_path / "scalers" / "scaler.joblib"
    detector = anomaly.AnomalyDetector(
        model_path=model_path, scaler_path=scaler_path
    )

    detector.train(training_features)

    assert detector.is_trained
    assert model_path.is_file()
    assert scaler_path.is_file()
    event = training_features.iloc[10].to_dict()
    expected_prediction = detector.predict(event)
    expected_score = detector.get_anomaly_score(event)

    restored = anomaly.AnomalyDetector(
        model_path=model_path, scaler_path=scaler_path
    )
    assert not restored.is_trained
    assert restored.predict(event) == expected_prediction
    assert restored.is_trained
    assert restored.get_anomaly_score(event) == pytest.approx(expected_score)
    assert restored.supported_features == list(training_features.columns)


def test_module_demo_cleans_up_all_artifacts(isolated_artifacts):
    runpy.run_path(anomaly.__file__, run_name="__main__")

    assert isolated_artifacts, "The demo should exercise real persistence."
    assert all(not path.exists() for path in isolated_artifacts)
    assert all(not path.parent.exists() for path in isolated_artifacts)


def test_explicit_save_and_load_paths_remain_compatible(
    tmp_path, isolated_artifacts, training_features
):
    model_path = tmp_path / "source-model.joblib"
    scaler_path = tmp_path / "source-scaler.joblib"
    source = anomaly.AnomalyDetector(model_path=model_path, scaler_path=scaler_path)
    source.train(training_features)
    event = training_features.iloc[10].to_dict()

    restored = anomaly.AnomalyDetector()
    assert restored.load_model(model_path, scaler_path)
    assert restored.predict(event) == source.predict(event)

    copied_model = tmp_path / "copies" / "model.joblib"
    copied_scaler = tmp_path / "copies" / "scaler.joblib"
    restored.save_model(copied_model, copied_scaler)
    copied = anomaly.AnomalyDetector()
    assert copied.load_model(copied_model, copied_scaler)
    assert copied.get_anomaly_score(event) == pytest.approx(source.get_anomaly_score(event))
