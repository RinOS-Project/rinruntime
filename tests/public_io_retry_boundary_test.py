"""Source-level regression checks for public runtime EINTR handling."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    expected = {
        "src/file_portal_startup.c": (
            "RINRUNTIME_FILE_PORTAL_STARTUP_IO_INTERRUPTION_LIMIT",
            2,
        ),
        "src/accessibility_service_client.c": (
            "RIN_ACCESSIBILITY_CLIENT_IO_INTERRUPTION_LIMIT",
            2,
        ),
        "src/crash_service_client.c": (
            "RINRUNTIME_CRASH_SERVICE_IO_INTERRUPTION_LIMIT",
            2,
        ),
        "src/audio/rin_audio_service_client.c": (
            "CLIENT_IO_INTERRUPTION_LIMIT",
            2,
        ),
        "src/file_operation_service_client.c": (
            "RINRUNTIME_FILE_OPERATION_SERVICE_IO_INTERRUPTION_LIMIT",
            2,
        ),
        "src/file_chooser_portal.c": (
            "RINRUNTIME_FILE_CHOOSER_IO_INTERRUPTION_LIMIT",
            2,
        ),
        "src/compositor_gui.c": (
            "RIN_RUNTIME_GUI_IO_INTERRUPTION_LIMIT",
            2,
        ),
        "src/safe_save_posix.c": (
            "RINRUNTIME_SAFE_SAVE_WRITE_INTERRUPTION_LIMIT",
            1,
        ),
    }
    for relative, (limit_macro, counter_count) in expected.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert f"#define {limit_macro} 32u" in source, relative
        assert source.count("uint32_t interrupted = 0u;") == counter_count, relative
        assert "errno == EINTR) continue;" not in source, relative

    compositor = (ROOT / "src/compositor_gui.c").read_text(encoding="utf-8")
    assert compositor.count("return (int)completed_count;") >= 3
    safe_save = (ROOT / "src/safe_save_posix.c").read_text(encoding="utf-8")
    assert "while (written < 0 && errno == EINTR)" not in safe_save
    print("public_io_retry_boundary_test: PASS")


if __name__ == "__main__":
    main()
