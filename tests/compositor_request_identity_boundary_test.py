"""Keep public compositor request IDs away from zero and UINT32_MAX."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = (ROOT / "src/compositor_gui.c").read_text(encoding="utf-8")
    assert "static int runtime_request_id_valid" in source
    assert "request_id != UINT32_MAX" in source
    assert source.count(
        "if (!runtime_request_id_valid(g_next_request_id)) g_next_request_id = 1u;"
    ) == 4
    print("compositor_request_identity_boundary_test: PASS")


if __name__ == "__main__":
    main()
