/* SPDX-License-Identifier: MIT */
#include <rinruntime/rinruntime.hpp>

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
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

static int throwingEventLoopCancellation(void*) {
    throw std::runtime_error("event loop cancellation callback failure");
}

static bool throwingEventLoopBackend(
    void*, const RinRuntime::EventLoop::WaitRequest*,
    RinRuntime::EventLoop::Size, std::uint64_t,
    RinRuntime::EventLoop::WaitResult*) {
    throw std::runtime_error("event loop backend failure");
}

struct EventLoopWatchMutationContext {
    RinRuntime::EventLoop* loop = nullptr;
    bool mutate = true;
};

static bool mutateEventLoopWatch(
    void* context, const RinRuntime::EventLoop::WaitRequest* requests,
    RinRuntime::EventLoop::Size count, std::uint64_t,
    RinRuntime::EventLoop::WaitResult* ready) {
    auto* mutation = static_cast<EventLoopWatchMutationContext*>(context);
    if (mutation == nullptr || mutation->loop == nullptr || requests == nullptr ||
        count != 1u || ready == nullptr) return false;
    if (mutation->mutate) {
        RinRuntime::Event replacement = {};
        replacement.type = RinRuntime::EventType::KeyDown;
        replacement.key = 0x41u;
        if (!mutation->loop->updateWatch(requests[0].id, 99u,
                                         RinRuntime::EventLoop::WAIT_READABLE,
                                         replacement))
            return false;
        mutation->mutate = false;
    }
    ready->id = requests[0].id;
    ready->events = requests[0].events;
    return true;
}

static int throwingDnsExchange(
    void*, const RinRuntime::DnsTransportEndpoint&, const std::uint8_t*,
    std::size_t, std::uint8_t*, std::size_t, std::size_t*) {
    throw std::runtime_error("dns exchange callback failure");
}

struct ReentrantDnsContext {
    RinRuntime::DnsTransportSession* session = nullptr;
};

static int reentrantDnsExchange(
    void* opaque, const RinRuntime::DnsTransportEndpoint&,
    const std::uint8_t* query, std::size_t query_length,
    std::uint8_t* response, std::size_t response_capacity,
    std::size_t* response_length) {
    auto* context = static_cast<ReentrantDnsContext*>(opaque);
    if (context == nullptr || context->session == nullptr || query == nullptr ||
        query_length == 0u || response == nullptr || response_capacity < 2u ||
        response_length == nullptr)
        return -1;
    response[1] = 0x77u;
    std::size_t nested_length = 0x2468ace0u;
    if (context->session->exchange(query, query_length, response,
                                   response_capacity, &nested_length) ||
        nested_length != 0x2468ace0u || response[1] != 0x77u)
        return -1;
    response[0] = 0x5au;
    *response_length = 1u;
    return 0;
}

int main() {
    static_assert(std::is_const_v<std::remove_reference_t<
                      decltype(std::declval<RinRuntime::Table&>().columns())>>);
    static_assert(std::is_const_v<std::remove_reference_t<
                      decltype(std::declval<RinRuntime::PopupMenu&>().items())>>);
    static_assert(std::is_const_v<std::remove_reference_t<
                      decltype(std::declval<RinRuntime::MenuBar&>().menus())>>);

    RinRuntime::EventLoop event_loop;
    assert(event_loop.pendingEvents() == 0u);
    RinRuntime::Event cancellable_output = {};
    cancellable_output.type = RinRuntime::EventType::Close;
    assert(!event_loop.runOneCancellable(
        0u, &cancellable_output, throwingEventLoopCancellation, nullptr));
    assert(cancellable_output.type == RinRuntime::EventType::None);
    RinRuntime::EventLoop backend_loop;
    RinRuntime::Event backend_event = {};
    backend_event.type = RinRuntime::EventType::Close;
    assert(backend_loop.scheduleAt(1u, backend_event) != 0u);
    RinRuntime::Event backend_output = {};
    backend_output.type = RinRuntime::EventType::Close;
    assert(!backend_loop.wait(0u, throwingEventLoopBackend, nullptr,
                              &backend_output));
    assert(backend_output.type == RinRuntime::EventType::None);

    RinRuntime::EventLoop watch_loop;
    RinRuntime::Event watched_event = {};
    watched_event.type = RinRuntime::EventType::Close;
    const RinRuntime::EventLoop::WaitId watched_id = watch_loop.watch(
        7u, RinRuntime::EventLoop::WAIT_READABLE, watched_event);
    assert(watched_id != 0u);
    EventLoopWatchMutationContext watch_mutation{&watch_loop};
    RinRuntime::Event watch_output = {};
    assert(!watch_loop.wait(0u, mutateEventLoopWatch, &watch_mutation,
                            &watch_output));
    assert(watch_output.type == RinRuntime::EventType::None);
    assert(watch_loop.wait(0u, mutateEventLoopWatch, &watch_mutation,
                           &watch_output));
    assert(watch_output.type == RinRuntime::EventType::KeyDown);
    assert(watch_output.key == 0x41u);

    RinRuntime::DnsTransportEndpoint::NamespaceId dns_namespace = {};
    dns_namespace[0] = 1u;
    RinRuntime::DnsTransportEndpoint dns_endpoint;
    assert(RinRuntime::DnsTransportEndpoint::build(
        RinRuntime::DnsTransportKind::Udp, "Resolver.Example", 53u, 1u,
        1u, dns_namespace, dns_endpoint));
    RinRuntime::DnsTransportSession dns_session;
    int dns_context = 1;
    assert(dns_session.bind(dns_endpoint, throwingDnsExchange, &dns_context));
    const std::uint8_t dns_query[] = {0x01u};
    std::uint8_t dns_response[4u] = {0xffu, 0xffu, 0xffu, 0xffu};
    std::size_t dns_response_length = 99u;
    assert(!dns_session.exchange(dns_query, sizeof(dns_query), dns_response,
                                  sizeof(dns_response),
                                  &dns_response_length));
    assert(dns_response_length == 0u);
    for (std::uint8_t byte : dns_response) assert(byte == 0u);

    std::uint8_t aliased_dns_storage[4u] = {0xa1u, 0xa2u, 0xa3u, 0xa4u};
    const std::uint8_t aliased_dns_before[4u] = {0xa1u, 0xa2u, 0xa3u, 0xa4u};
    std::size_t aliased_dns_length = 0x13579bdfu;
    assert(!dns_session.exchange(aliased_dns_storage, 1u,
                                 aliased_dns_storage,
                                 sizeof(aliased_dns_storage),
                                 &aliased_dns_length));
    assert(aliased_dns_length == 0x13579bdfu);
    for (std::size_t index = 0u; index < sizeof(aliased_dns_storage); ++index)
        assert(aliased_dns_storage[index] == aliased_dns_before[index]);

    union {
        std::uint8_t bytes[sizeof(std::size_t)];
        std::size_t length;
    } aliased_dns_length_storage = {};
    aliased_dns_length_storage.length = 0x2468ace0u;
    const auto aliased_dns_length_before = aliased_dns_length_storage;
    assert(!dns_session.exchange(aliased_dns_length_storage.bytes,
                                 sizeof(aliased_dns_length_storage.bytes),
                                 dns_response, sizeof(dns_response),
                                 &aliased_dns_length_storage.length));
    assert(aliased_dns_length_storage.length ==
           aliased_dns_length_before.length);
    assert(aliased_dns_length_storage.bytes[0] ==
           aliased_dns_length_before.bytes[0]);
    assert(dns_session.bound());

    RinRuntime::DnsTransportSession reentrant_dns_session;
    ReentrantDnsContext reentrant_dns_context;
    reentrant_dns_context.session = &reentrant_dns_session;
    assert(reentrant_dns_session.bind(
        dns_endpoint, reentrantDnsExchange, &reentrant_dns_context));
    std::uint8_t reentrant_dns_response[4u] = {};
    std::size_t reentrant_dns_length = 0u;
    assert(reentrant_dns_session.exchange(
        dns_query, sizeof(dns_query), reentrant_dns_response,
        sizeof(reentrant_dns_response), &reentrant_dns_length));
    assert(reentrant_dns_length == 1u && reentrant_dns_response[0] == 0x5au &&
           reentrant_dns_response[1] == 0x77u);

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

    assert(!RinRuntime::ApplicationMetadata::validRelativePath(
        "bin/../editor.rin"));
    assert(!RinRuntime::PackageMetadata::validRelativePath(
        "lib/./runtime.rll"));
    RinRuntime::DnsTransportEndpoint::NamespaceId dns_path_namespace = {};
    dns_path_namespace[0] = 1u;
    RinRuntime::DnsTransportEndpoint dns_path_endpoint;
    assert(!RinRuntime::DnsTransportEndpoint::build(
        RinRuntime::DnsTransportKind::Doh, "resolver.example", 443u, 1u,
        1u, dns_path_namespace, dns_path_endpoint, "/dns/../query"));

    std::string ellipsized = "stale";
    assert(RinRuntime::tryEllipsizeText("Aあいうえお", 40, &ellipsized));
    assert(ellipsized == "Aあ...");
    assert(RinRuntime::tryEllipsizeText("unused", 0, &ellipsized));
    assert(ellipsized.empty());
    assert(!RinRuntime::tryEllipsizeText("unused", 40, nullptr));

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
    Rin::Application throwingStart;
    throwingStart.onStarted([] {
        throw std::runtime_error("start callback failure");
    });
    assert(!throwingStart.start());
    assert(throwingStart.state() == Rin::Application::State::Stopped);

    Rin::Application throwingDispatch;
    assert(throwingDispatch.start());
    throwingDispatch.onEvent([](const Rin::Event&) -> bool {
        throw std::runtime_error("event callback failure");
    });
    assert(!throwingDispatch.dispatch(Rin::Event{}));
    assert(throwingDispatch.state() == Rin::Application::State::QuitRequested);
    assert(throwingDispatch.stop());

    Rin::Application throwingStop;
    assert(throwingStop.start());
    throwingStop.onStopped([] {
        throw std::runtime_error("stop callback failure");
    });
    assert(!throwingStop.stop());
    assert(throwingStop.state() == Rin::Application::State::Stopped);
    RinRuntime::PermissionPrompt prompt;
    assert(prompt.request("https://example.test", "camera", "Use camera"));
    prompt.setOnDecision([](RinRuntime::PermissionPromptDecision) {
        throw std::runtime_error("permission callback failure");
    });
    assert(!prompt.allow());
    assert(prompt.decision() == RinRuntime::PermissionPromptDecision::Allow);
    assert(!prompt.isPending());

    RinRuntime::SemanticWidget semantic;
    assert(semantic.configure("Name", "old", "", 0u,
                              RinRuntime::ACCESSIBILITY_ACTION_ACTIVATE |
                                  RinRuntime::ACCESSIBILITY_ACTION_SET_VALUE,
                              true, true));
    semantic.setActivate([]() -> bool {
        throw std::runtime_error("semantic activate failure");
    });
    assert(!semantic.activate());
    semantic.setValueHandler([](const std::string&) -> bool {
        throw std::runtime_error("semantic value callback failure");
    });
    assert(!semantic.setAccessibilityValue("new"));
    assert(semantic.value() == "old");

    RinRuntime::SemanticWidget reentrant_semantic;
    assert(reentrant_semantic.configure("Name", "old", "", 0u,
                                        RinRuntime::ACCESSIBILITY_ACTION_SET_VALUE,
                                        true, true));
    bool reentrant_semantic_called = false;
    reentrant_semantic.setValueHandler([&](const std::string&) {
        reentrant_semantic_called = true;
        assert(!reentrant_semantic.setAccessibilityValue("nested"));
        assert(!reentrant_semantic.configure(
            "Name", "nested", "", 0u,
            RinRuntime::ACCESSIBILITY_ACTION_SET_VALUE, true, true));
        return true;
    });
    assert(reentrant_semantic.setAccessibilityValue("new"));
    assert(reentrant_semantic_called && reentrant_semantic.value() == "new");

    RinRuntime::Button throwing_button("Throwing");
    throwing_button.setBounds({0, 0, 100, 40});
    throwing_button.setOnClick([] {
        throw std::runtime_error("button callback failure");
    });
    RinRuntime::Event button_down = {};
    button_down.type = RinRuntime::EventType::MouseDown;
    button_down.x = 1;
    button_down.y = 1;
    RinRuntime::Event button_up = button_down;
    button_up.type = RinRuntime::EventType::MouseUp;
    assert(throwing_button.handleEvent(button_down));
    assert(throwing_button.handleEvent(button_up));

    RinRuntime::Button reentrant_button("Reentrant");
    reentrant_button.setAccessibilityFocused(true);
    RinRuntime::Event activate_button = {};
    activate_button.type = RinRuntime::EventType::KeyDown;
    activate_button.key = 0x0du;
    unsigned reentrant_button_calls = 0u;
    reentrant_button.setOnClick([&] {
        ++reentrant_button_calls;
        assert(reentrant_button.handleEvent(activate_button));
    });
    assert(reentrant_button.handleEvent(activate_button));
    assert(reentrant_button_calls == 1u);

    RinRuntime::CheckBox throwing_check("Check");
    throwing_check.setOnChange([](bool) {
        throw std::runtime_error("checkbox callback failure");
    });
    assert(throwing_check.toggle());
    assert(throwing_check.isChecked());

    RinRuntime::CheckBox reentrant_check("Reentrant");
    bool reentrant_check_called = false;
    reentrant_check.setOnChange([&](bool) {
        reentrant_check_called = true;
        assert(!reentrant_check.toggle());
    });
    assert(reentrant_check.toggle());
    assert(reentrant_check_called && reentrant_check.isChecked());

    RinRuntime::Slider reentrant_slider;
    reentrant_slider.setBounds({0, 0, 100, 20});
    reentrant_slider.setAccessibilityFocused(true);
    RinRuntime::Event increase_slider = {};
    increase_slider.type = RinRuntime::EventType::KeyDown;
    increase_slider.key = 0x27u;
    unsigned reentrant_slider_calls = 0u;
    reentrant_slider.setOnChange([&](int32_t) {
        ++reentrant_slider_calls;
        assert(reentrant_slider.setValueFromPosition(100));
    });
    assert(reentrant_slider.handleEvent(increase_slider));
    assert(reentrant_slider_calls == 1u && reentrant_slider.value() == 100);

    RinRuntime::List reentrant_list;
    assert(reentrant_list.addItem("one"));
    assert(reentrant_list.addItem("two"));
    assert(reentrant_list.addItem("three"));
    assert(reentrant_list.setSelectedIndex(0));
    reentrant_list.setAccessibilityFocused(true);
    RinRuntime::Event move_list = {};
    move_list.type = RinRuntime::EventType::KeyDown;
    move_list.key = 0x28u;
    unsigned reentrant_list_calls = 0u;
    reentrant_list.setOnSelect([&](int32_t) {
        ++reentrant_list_calls;
        assert(reentrant_list.handleEvent(move_list));
    });
    assert(reentrant_list.handleEvent(move_list));
    assert(reentrant_list_calls == 1u &&
           reentrant_list.selectedIndex() == 2);

    RinRuntime::Slider throwing_slider;
    throwing_slider.setBounds({0, 0, 100, 20});
    throwing_slider.setOnChange([](int32_t) {
        throw std::runtime_error("slider callback failure");
    });
    assert(throwing_slider.setValueFromPosition(80));
    assert(throwing_slider.value() == 80);

    RinRuntime::Dialog throwing_dialog("Dialog");
    throwing_dialog.setCancelAction([] {
        throw std::runtime_error("dialog callback failure");
    });
    throwing_dialog.show();
    RinRuntime::Event escape = {};
    escape.type = RinRuntime::EventType::KeyDown;
    escape.key = 0x1bu;
    assert(throwing_dialog.handleEvent(escape));
    assert(throwing_dialog.isOpen());

    RinRuntime::List throwing_list;
    assert(throwing_list.setItems({"first", "second"}));
    throwing_list.setBounds({0, 0, 120, 64});
    throwing_list.setOnSelect([](int32_t) {
        throw std::runtime_error("list callback failure");
    });
    RinRuntime::Event list_click = {};
    list_click.type = RinRuntime::EventType::MouseDown;
    list_click.x = 1;
    list_click.y = 1;
    assert(throwing_list.handleEvent(list_click));
    assert(throwing_list.selectedIndex() == 0);

    RinRuntime::Table throwing_table;
    assert(throwing_table.addColumn({"Name", 96, true}));
    throwing_table.setOnSort([](int32_t, bool) {
        throw std::runtime_error("table callback failure");
    });
    assert(throwing_table.sortBy(0));
    assert(throwing_table.sortedColumn() == 0);

    RinRuntime::Tree throwing_tree;
    const uint64_t throwing_root = throwing_tree.addRoot("Root");
    assert(throwing_root != 0u);
    throwing_tree.setOnSelect([](uint64_t) {
        throw std::runtime_error("tree callback failure");
    });
    throwing_tree.setBounds({0, 0, 120, 64});
    assert(throwing_tree.handleEvent(list_click));
    assert(throwing_tree.selectedItemId() == throwing_root);

    RinRuntime::TabView throwing_tabs;
    assert(throwing_tabs.setTabs({"One", "Two"}));
    throwing_tabs.setOnTabChange([](int32_t) {
        throw std::runtime_error("tab callback failure");
    });
    throwing_tabs.setActiveTab(1);
    assert(throwing_tabs.activeTab() == 1);

    RinRuntime::ComboBox throwing_combo;
    assert(throwing_combo.setItems({"One", "Two"}));
    throwing_combo.setOnSelect([](int32_t) {
        throw std::runtime_error("combo callback failure");
    });
    assert(throwing_combo.selectIndex(0));
    assert(throwing_combo.selectedIndex() == 0);

    RinRuntime::RadioButton throwing_radio("Radio");
    throwing_radio.setOnChange([](bool) {
        throw std::runtime_error("radio callback failure");
    });
    throwing_radio.setChecked(true);
    assert(throwing_radio.isChecked());

    RinRuntime::PopupMenu throwing_popup("Popup");
    assert(throwing_popup.addItem("Run", "", [] {
        throw std::runtime_error("popup callback failure");
    }) == 0);
    assert(throwing_popup.activate(0));
    assert(!throwing_popup.isOpen());

    RinRuntime::Dialog reentrant_dialog("Dialog");
    RinRuntime::Event reentrant_escape = {};
    reentrant_escape.type = RinRuntime::EventType::KeyDown;
    reentrant_escape.key = 0x1bu;
    unsigned reentrant_dialog_calls = 0u;
    reentrant_dialog.setCancelAction([&] {
        ++reentrant_dialog_calls;
        assert(reentrant_dialog.handleEvent(reentrant_escape));
        reentrant_dialog.dismiss();
    });
    reentrant_dialog.show();
    assert(reentrant_dialog.handleEvent(reentrant_escape));
    assert(reentrant_dialog_calls == 1u && !reentrant_dialog.isOpen());

    RinRuntime::Table reentrant_table;
    assert(reentrant_table.addColumn({"Name", 96, true}));
    unsigned reentrant_table_calls = 0u;
    reentrant_table.setOnSort([&](int32_t column, bool ascending) {
        ++reentrant_table_calls;
        assert(reentrant_table.sortBy(column));
        (void)ascending;
    });
    assert(reentrant_table.sortBy(0));
    assert(reentrant_table_calls == 1u &&
           !reentrant_table.ascending());

    RinRuntime::Tree reentrant_tree;
    const uint64_t reentrant_tree_first = reentrant_tree.addRoot("First");
    const uint64_t reentrant_tree_second = reentrant_tree.addRoot("Second");
    assert(reentrant_tree_first != 0u && reentrant_tree_second != 0u);
    reentrant_tree.setBounds({0, 0, 120, 64});
    reentrant_tree.setAccessibilityFocused(true);
    RinRuntime::Event move_tree = {};
    move_tree.type = RinRuntime::EventType::KeyDown;
    move_tree.key = 0x28u;
    unsigned reentrant_tree_calls = 0u;
    reentrant_tree.setOnSelect([&](uint64_t) {
        ++reentrant_tree_calls;
        assert(reentrant_tree.handleEvent(move_tree));
    });
    assert(reentrant_tree.handleEvent(list_click));
    assert(reentrant_tree_calls == 1u &&
           reentrant_tree.selectedItemId() == reentrant_tree_second);

    RinRuntime::TabView reentrant_tabs;
    assert(reentrant_tabs.setTabs({"One", "Two"}));
    unsigned reentrant_tab_calls = 0u;
    reentrant_tabs.setOnTabChange([&](int32_t) {
        ++reentrant_tab_calls;
        reentrant_tabs.setActiveTab(0);
    });
    reentrant_tabs.setActiveTab(1);
    assert(reentrant_tab_calls == 1u && reentrant_tabs.activeTab() == 0);

    RinRuntime::ComboBox reentrant_combo;
    assert(reentrant_combo.setItems({"One", "Two"}));
    unsigned reentrant_combo_calls = 0u;
    reentrant_combo.setOnSelect([&](int32_t) {
        ++reentrant_combo_calls;
        assert(reentrant_combo.selectIndex(1));
    });
    assert(reentrant_combo.selectIndex(0));
    assert(reentrant_combo_calls == 1u && reentrant_combo.selectedIndex() == 1);

    RinRuntime::RadioButton reentrant_radio("Radio");
    unsigned reentrant_radio_calls = 0u;
    reentrant_radio.setOnChange([&](bool) {
        ++reentrant_radio_calls;
        reentrant_radio.setChecked(false);
    });
    reentrant_radio.setChecked(true);
    assert(reentrant_radio_calls == 1u && !reentrant_radio.isChecked());

    RinRuntime::PopupMenu reentrant_popup("Popup");
    unsigned reentrant_popup_calls = 0u;
    assert(reentrant_popup.addItem("Run", "", [&] {
        ++reentrant_popup_calls;
        assert(!reentrant_popup.activate(0));
    }) == 0);
    assert(reentrant_popup.activate(0));
    assert(reentrant_popup_calls == 1u && !reentrant_popup.isOpen());

    RinRuntime::MenuBar reentrant_menu_bar(320);
    const int32_t reentrant_menu = reentrant_menu_bar.addMenu("File");
    assert(reentrant_menu == 0);
    assert(reentrant_menu_bar.addItem(
               reentrant_menu, {"Run", "", nullptr, false, true}));
    unsigned reentrant_menu_calls = 0u;
    reentrant_menu_bar.setAction("File", "Run", [&] {
        ++reentrant_menu_calls;
        RinRuntime::Event activate_menu = {};
        activate_menu.type = RinRuntime::EventType::KeyDown;
        activate_menu.key = 0x0du;
        reentrant_menu_bar.setAccessibilityFocused(true);
        assert(reentrant_menu_bar.handleEvent(activate_menu));
    });
    reentrant_menu_bar.setAccessibilityFocused(true);
    RinRuntime::Event activate_menu = {};
    activate_menu.type = RinRuntime::EventType::KeyDown;
    activate_menu.key = 0x0du;
    assert(reentrant_menu_bar.handleEvent(activate_menu));
    assert(reentrant_menu_bar.handleEvent(activate_menu));
    assert(reentrant_menu_calls == 1u);

    Rin::Document document;
    assert(document.setText("Rin"));
    assert(document.insert(3u, "OS"));
    assert(document.text() == "RinOS");
    Rin::FormValidator form;
    assert(form.required("name"));
    assert(form.minimumLength("name", 1u));
    assert(!form.validate({{"name", ""}}));
    assert(form.validate({{"name", "Rin"}}));
    Rin::FormValidator boundedForm;
    for (size_t index = 0u; index < boundedForm.maximumRules(); ++index)
        assert(boundedForm.required("field"));
    assert(!boundedForm.required("overflow"));
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
    assert(table.setColumns({{"Name", 120, true}, {"Age", 96, false}}));
    assert(table.columns().size() == 2u);
    assert(table.replaceColumn(1, {"Years", 96, true}));
    assert(table.columns()[1].header == "Years");
    assert(!table.replaceColumn(1, {"Invalid", 1, false}));
    assert(table.removeColumn(1));
    assert(table.columns().size() == 1u);
    assert(table.addColumn({"Years", 96, true}));
    assert(!table.setColumns({{"Invalid", 1, false}}));
    assert(table.columns().size() == 2u);
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
    std::vector<RinRuntime::MenuItem> popup_items;
    popup_items.emplace_back("Open", "", [] {});
    assert(popup.setItems(popup_items));
    assert(popup.items().size() == 1u);
    assert(popup.replaceItem(0, {"Save", "Ctrl+S", [] {}, false, true}));
    assert(popup.items()[0].label == "Save");
    assert(popup.removeItem(0));
    assert(popup.items().empty());
    assert(popup.addItem("Open") == 0);
    popup.clearItems();
    assert(popup.items().empty());
    assert(popup.addItem("Open") == 0);
    assert(popup.setItemAction(0, [] {}));
    RinRuntime::MenuBar menu_bar;
    const int32_t menu = menu_bar.addMenu("File");
    assert(menu >= 0);
    assert(menu_bar.addItem(menu, {"Open", "", [] {}}));
    assert(menu_bar.setAction("File", "Open", [] {}));
    RinRuntime::Menu replacement;
    replacement.title = "Edit";
    replacement.items.emplace_back("Copy", "", [] {});
    assert(menu_bar.setMenus({replacement}));
    assert(menu_bar.menus().size() == 1u);
    RinRuntime::Menu replacement_again;
    replacement_again.title = "View";
    replacement_again.items.emplace_back("Zoom", "", [] {});
    assert(menu_bar.replaceMenu(0, replacement_again));
    assert(menu_bar.menus()[0].title == "View");
    std::vector<RinRuntime::MenuItem> menu_items;
    menu_items.emplace_back("Full Screen", "F11", [] {});
    assert(menu_bar.setMenuItems(0, menu_items));
    assert(menu_bar.menus()[0].items.size() == 1u);
    assert(menu_bar.removeMenu(0));
    assert(menu_bar.menus().empty());
    return 0;
}
