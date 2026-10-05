"""Keep the public accessibility service client request counter terminal-safe."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = (ROOT / "src/accessibility_service_client.c").read_text(
        encoding="utf-8"
    )
    assert "static int client_request_id_valid" in source
    assert "request_id != UINT64_MAX" in source
    assert source.count(
        "if (!client_request_id_valid(client->next_request_id))"
    ) == 1
    assert "!client_request_id_valid(client->next_request_id))" in source
    print("accessibility_service_request_identity_boundary_test: PASS")


if __name__ == "__main__":
    main()
