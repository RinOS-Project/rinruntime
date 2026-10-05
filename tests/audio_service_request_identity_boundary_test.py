"""Keep the public audio service request counter terminal-safe."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = (ROOT / "src/audio/rin_audio_service_client.c").read_text(
        encoding="utf-8"
    )
    assert "static int audio_request_id_valid" in source
    assert "request_id != UINT64_MAX" in source
    assert source.count(
        "if (!audio_request_id_valid(g_client.next_request_id))"
    ) == 2
    print("audio_service_request_identity_boundary_test: PASS")


if __name__ == "__main__":
    main()
