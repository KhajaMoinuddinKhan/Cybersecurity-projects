from src.aggregator import import_iocs, search_iocs

def test_import_deduplicates_iocs(tmp_path):
    db=tmp_path/"intel.db"
    rows=[("ip","198.51.100.23","lab"),("domain","bad.example","lab"),("ip","198.51.100.23","lab")]
    assert import_iocs(db,rows)==2
    assert search_iocs(db,"198.51.100.23")==[("ip","198.51.100.23","lab")]
