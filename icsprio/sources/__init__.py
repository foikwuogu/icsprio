"""Source fetchers: one module per upstream data source.

Each module exposes a `fetch_*` function that returns plain Python
data structures (lists of dicts) and writes its raw payload to
data/raw/, logging provenance via icsprio.provenance.log_fetch. Keeping
network I/O isolated here is what lets icsprio.join and icsprio.scoring be
tested purely offline against fixtures.
"""
