from icsprio import attack_mapping
from icsprio.config import CWE_ATTACK_CROSSWALK


def test_crosswalk_loads_from_repo_reference_file():
    crosswalk = attack_mapping.load_crosswalk(CWE_ATTACK_CROSSWALK)
    assert "CWE-798" in crosswalk
    ids = {m["attack_technique_id"] for m in crosswalk["CWE-798"]}
    assert "T0859" in ids


def test_map_cwes_to_techniques_dedupes_and_keeps_highest_confidence():
    crosswalk = {
        "CWE-1": [
            {"attack_technique_id": "T1", "attack_technique_name": "A", "confidence": "low", "rationale": "r1"}
        ],
        "CWE-2": [
            {"attack_technique_id": "T1", "attack_technique_name": "A", "confidence": "high", "rationale": "r2"}
        ],
    }
    out = attack_mapping.map_cwes_to_techniques(["CWE-1", "CWE-2"], crosswalk)
    assert len(out) == 1
    assert out[0]["confidence"] == "high"


def test_map_cwes_to_techniques_handles_unmapped_cwe():
    assert attack_mapping.map_cwes_to_techniques(["CWE-99999"], {}) == []


def test_map_cwes_to_techniques_handles_empty_input():
    assert attack_mapping.map_cwes_to_techniques([], {"CWE-1": []}) == []
    assert attack_mapping.map_cwes_to_techniques(None, {"CWE-1": []}) == []
