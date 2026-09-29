/* SPDX-License-Identifier: MIT */
#include <rinruntime/rinruntime.hpp>

#include <cassert>
#include <cstdint>
#include <vector>

struct DownloadModelOwner {
    unsigned reads = 0u;
};

static int beginDownloadModelRange(
    void*, const RinRuntime::DownloadRangeRequest* request,
    RinRuntime::DownloadRangeResponse* response) {
    if (request == nullptr || response == nullptr) return -1;
    response->statusCode = 206u;
    response->contentRangeStart = request->offset;
    response->contentRangeEnd = request->totalBytes - 1u;
    response->contentRangeTotal = request->totalBytes;
    response->contentLength = request->totalBytes - request->offset;
    response->generation = request->generation;
    response->validator = request->validator;
    return 0;
}

static int readDownloadModelRange(void* context, std::uint8_t* buffer,
                                  std::size_t capacity,
                                  std::size_t* bytesRead) {
    auto* owner = static_cast<DownloadModelOwner*>(context);
    if (owner == nullptr || buffer == nullptr || bytesRead == nullptr ||
        capacity == 0u)
        return -1;
    if (owner->reads++ == 0u) {
        if (capacity < 1u) return -1;
        buffer[0] = 0x5au;
        *bytesRead = 1u;
        return 0;
    }
    *bytesRead = 0u;
    return 0;
}

static void abortDownloadModelRange(void*) {}

int main() {
    RinRuntime::EventLoop event_loop;
    assert(event_loop.pendingEvents() == 0u);

    static_assert(RIN_I18N_RMSG_VERSION == 1u,
                  "public i18n catalog version must remain stable");
    RinI18nCatalog i18n_catalog = {};
    RinI18nArg i18n_arg = {"name", "RinOS"};
    assert(i18n_catalog.data == nullptr && i18n_catalog.size == 0u);
    assert(i18n_arg.name != nullptr && i18n_arg.value != nullptr);
    assert(rin_i18n_hash("RinOS") != 0u);
    assert(RinRuntime::utf8GraphemeSpacingMark(0x1a55u));
#if !defined(_WIN32)
    RinRuntime::PollEventLoopBackend* poll_backend = nullptr;
    (void)poll_backend;
#endif
    RinRuntime::RinEventLoopBackend* rin_backend = nullptr;
    (void)rin_backend;
    RinRuntime::BackupArchiveReader backup_reader;
    RinRuntime::KnownFolder known_folder = RinRuntime::KnownFolder::Home;
    RinRuntime::ApplicationDirectory application_directory =
        RinRuntime::ApplicationDirectory::Data;
    const std::string known_folder_path =
        RinRuntime::knownFolder(known_folder);
    const std::string application_directory_path =
        RinRuntime::applicationDirectory(application_directory, "rinruntime-model");
    (void)known_folder;
    (void)application_directory;
    (void)known_folder_path;
    (void)application_directory_path;

    DownloadModelOwner download_owner;
    RinRuntime::DownloadRangeTransportOpsV1 download_ops;
    download_ops.structSize = sizeof(download_ops);
    download_ops.context = &download_owner;
    download_ops.begin = beginDownloadModelRange;
    download_ops.read = readDownloadModelRange;
    download_ops.abort = abortDownloadModelRange;
    RinRuntime::DownloadRangeTransportAdapter download;
    assert(download.bind(download_ops));
    RinRuntime::DownloadRangeRequest download_request;
    download_request.requestId = 1u;
    download_request.generation = 1u;
    download_request.totalBytes = 1u;
    download_request.validator = "model";
    RinRuntime::DownloadRangeResponse download_response;
    assert(download.begin(download_request, download_response));
    std::uint8_t download_buffer[1u] = {};
    std::size_t download_bytes = 0u;
    assert(download.read(download_buffer, sizeof(download_buffer),
                         download_bytes));
    assert(download_bytes == 1u && download_buffer[0] == 0x5au);
    assert(download.read(download_buffer, sizeof(download_buffer),
                         download_bytes));
    assert(download_bytes == 0u);

    RinCompression::ZstdFrameEncoder zstd_encoder;
    RinCompression::ZstdFrameDecoder zstd_decoder;
    const std::uint8_t zstd_payload[] = {'R', 'i', 'n', 'O', 'S'};
    std::vector<std::uint8_t> zstd_frame;
    std::vector<std::uint8_t> zstd_decoded;
    assert(zstd_encoder.encode(zstd_payload, sizeof(zstd_payload), zstd_frame) ==
           RinCompression::ZstdResult::Ok);
    assert(zstd_decoder.decode(zstd_frame.data(), zstd_frame.size(), zstd_decoded) ==
           RinCompression::ZstdResult::Ok);
    assert(zstd_decoded ==
           std::vector<std::uint8_t>(zstd_payload,
                                     zstd_payload + sizeof(zstd_payload)));

    RinRuntime::Button button("Open");
    assert(button.setAccessibilityName("Open"));
    assert(button.accessibilityDefaultName() == "Open");

    RinRuntime::TextEditorModel editor;
    assert(editor.setText("RinOS"));
    editor.moveEnd(false);
    assert(editor.insertCodepoint(0x1f680u));
    assert(editor.backspace());
    assert(editor.text() == "RinOS");

    RinRuntime::ArchivePlan plan;
    RinRuntime::ArchiveSource source{"app/main.rin", "main.rin", false};
    assert(plan.addSource(source));
    RinRuntime::ArchiveSource traversal{"../escape", "escape", false};
    assert(!plan.addSource(traversal));
    RinRuntime::ArchiveEntry link{};
    link.name = "link";
    link.sourcePath = "target";
    link.compressedSize = 1u;
    link.uncompressedSize = 1u;
    link.symbolicLink = true;
    assert(!plan.add(link));

    RinRuntime::AccessibilityTree tree = {};
    tree.window = 7u;
    tree.generation = 3u;
    RinRuntime::AccessibilityNode root = {};
    root.id = 1u;
    root.metadata.role = RinRuntime::AccessibilityRole::Window;
    root.metadata.name = "Main";
    root.metadata.state = RinRuntime::ACCESSIBILITY_STATE_VISIBLE;
    root.metadata.actions = RinRuntime::ACCESSIBILITY_ACTION_NONE;
    tree.nodes.push_back(root);
    RinRuntime::AccessibilityWireSnapshotV1 wire = {};
    assert(RinRuntime::AccessibilityWireCodec::encode(tree, &wire));
    RinRuntime::AccessibilityTree decoded = {};
    assert(RinRuntime::AccessibilityWireCodec::decode(wire, &decoded));
    assert(decoded.nodes.size() == 1u && decoded.nodes[0].id == 1u);
    wire.nodes[0].name.bytes[0] = 0xffu;
    assert(!RinRuntime::AccessibilityWireCodec::decode(wire, &decoded));

    Rin::Application application;
    assert(application.start());
    assert(application.requestQuit());
    assert(application.stop());
    Rin::Document document;
    assert(document.setText("Rin"));
    assert(document.insert(3u, "OS"));
    assert(document.text() == "RinOS");
    Rin::FormValidator form;
    form.required("name");
    assert(!form.validate({{"name", ""}}));
    assert(form.validate({{"name", "Rin"}}));
    Rin::PrintSettings print;
    assert(print.valid());
    Rin::ActivityFeed feed;
    assert(feed.add({"Build", "completed", false}));
    assert(feed.markRead(0u));

    RinRuntime::RadioButton radio("Choice", "main");
    assert(radio.setLabel("Updated"));
    assert(radio.setGroup("options"));
    RinRuntime::List list;
    assert(list.addItem("first"));
    assert(list.setItems({"second", "third"}));
    assert(list.selectedItem() == nullptr);
    RinRuntime::Table table;
    assert(table.addColumn({"Name", 96, true}));
    assert(table.setColumnValue(0, [](int32_t) { return std::string("value"); }));
    RinRuntime::Tree widget_tree;
    const uint64_t tree_root = widget_tree.addRoot("Root");
    assert(tree_root != 0u);
    assert(widget_tree.addChild(tree_root, "Child") != 0u);
    RinRuntime::TabView tabs;
    assert(tabs.addTab("One"));
    assert(tabs.setTabs({"Two", "Three"}));
    RinRuntime::ComboBox combo;
    assert(combo.addItem("One"));
    assert(combo.setItems({"Two", "Three"}));
    RinRuntime::PopupMenu popup("Actions");
    assert(popup.addItem("Run") == 0);
    assert(popup.setItemAction(0, [] {}));
    RinRuntime::MenuBar menu_bar;
    const int32_t menu = menu_bar.addMenu("File");
    assert(menu >= 0);
    assert(menu_bar.addItem(menu, {"Open", "", [] {}}));
    assert(menu_bar.setAction("File", "Open", [] {}));
    return 0;
}
