"""Keep the public crashd client request allocator terminal-safe."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = (ROOT / "src/crash_service_client.c").read_text(encoding="utf-8")
    assert "static int crash_service_request_id_valid" in source
    assert "request_id != UINT64_MAX" in source
    assert "for (unsigned attempt = 0u; attempt < 3u; ++attempt)" in source
    assert "request_id = crash_service_next_request_id();" in source
    assert "if (!crash_service_request_id_valid(request_id))" in source
    print("crash_service_request_identity_boundary_test: PASS")


if __name__ == "__main__":
    main()
