from icsprio.sources.attack_ics import list_technique_ids, parse_attack_bundle


def test_parse_attack_bundle_indexes_by_technique_id(attack_ics_fixture):
    out = parse_attack_bundle(attack_ics_fixture)
    assert set(out.keys()) == {"T0859", "T0819"}
    assert out["T0859"]["attack_technique_name"] == "Valid Accounts"
    assert out["T0859"]["attack_tactics"] == ["initial-access"]


def test_parse_attack_bundle_skips_revoked(attack_ics_fixture):
    out = parse_attack_bundle(attack_ics_fixture)
    assert "T9999" not in out


def test_list_technique_ids_sorted(attack_ics_fixture):
    out = parse_attack_bundle(attack_ics_fixture)
    assert list_technique_ids(out) == ["T0819", "T0859"]
