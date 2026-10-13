"""compute_kappa.py on small synthetic tables with known values (no real labels)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("compute_kappa", ROOT / "evaluation/v3/in_the_wild/compute_kappa.py")
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)


def test_textbook_two_by_two():
    # 50 items: 20 yes/yes, 5 yes/no, 10 no/yes, 15 no/no -> po = 0.7, pe = 0.5, kappa = 0.4
    r = K.kappa_from_matrix(["no", "yes"], [[15, 10], [5, 20]])
    assert (r["n"], r["agree"]) == (50, 35)
    assert abs(r["po"] - 0.7) < 1e-12 and abs(r["pe"] - 0.5) < 1e-12 and abs(r["kappa"] - 0.4) < 1e-12


def test_ratings_and_matrix_agree(tmp_path):
    pairs = [("a", "a")] * 4 + [("a", "b")] + [("b", "b")] * 3 + [("b", "a")] * 2 + [("c", "c")]
    r1 = K.from_ratings(pairs)
    p = tmp_path / "ratings.csv"
    p.write_text("dossier_id,rater_a,rater_b\n" + "\n".join(f"L-{i:03d},{a},{b}" for i, (a, b) in enumerate(pairs)), encoding="utf-8")
    assert K.from_ratings(K.read_ratings(p)) == r1
    q = tmp_path / "m.csv"
    q.write_text(",a,b,c\n" + "\n".join(f"{l}," + ",".join(str(x) for x in row) for l, row in zip(r1["labels"], r1["matrix"])), encoding="utf-8")
    assert abs(K.kappa_from_matrix(*K.read_matrix(q))["kappa"] - r1["kappa"]) < 1e-12


def test_perfect_agreement_and_label_order():
    r = K.from_ratings([("x", "x"), ("y", "y"), ("y", "y")])
    assert r["kappa"] == 1.0 and r["agree"] == 3
