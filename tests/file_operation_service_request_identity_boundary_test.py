"""Keep public FileOperation request counters away from terminal identities."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = (ROOT / "src/file_operation_service_client.c").read_text(
        encoding="utf-8"
    )
    assert "static int service_client_request_id_valid" in source
    assert "request_id != UINT64_MAX" in source
    assert source.count(
        "if (!service_client_request_id_valid(client->next_request_id))"
    ) == 2
    assert "!service_client_request_id_valid(next_request_id)" in source
    print("file_operation_service_request_identity_boundary_test: PASS")


if __name__ == "__main__":
    main()
