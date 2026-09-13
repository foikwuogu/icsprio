import pandas as pd
from click.testing import CliRunner

from icsprio import pipeline
from icsprio.cli import main


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "icsprio" in result.output


def test_run_command_invokes_pipeline_and_reports_row_count(monkeypatch):
    fake_df = pd.DataFrame([{"a": 1}])

    def fake_run_pipeline(**kwargs):
        return {"df": fake_df, "stats": {}, "report_text": "ok", "parquet_written": True}

    monkeypatch.setattr(pipeline, "run_pipeline", fake_run_pipeline)

    runner = CliRunner()
    result = runner.invoke(main, ["run"])
    assert result.exit_code == 0
    assert "Wrote 1 rows" in result.output


def test_report_command_errors_when_no_report(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["report", "--processed-dir", str(tmp_path)])
    assert result.exit_code != 0


def test_report_command_prints_existing_report(tmp_path):
    (tmp_path / "qa_report.txt").write_text("hello from qa report")
    runner = CliRunner()
    result = runner.invoke(main, ["report", "--processed-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "hello from qa report" in result.output


def test_build_command_errors_without_manifest(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["build", "--raw-dir", str(tmp_path)])
    assert result.exit_code != 0
