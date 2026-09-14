/* SPDX-License-Identifier: MIT */

#include <rinruntime/rin_audio_service_client.h>
#include "../platform.h"

#include <rin/shm_abi.h>
#include <rin/socket_abi.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CLIENT_STREAM_SLOTS 8u
#define CLIENT_IO_RETRIES 4096u
#define RIN_AUDIO_SERVICE_SOCKET_PATH "/run/rin/audiod.sock"

typedef struct ClientStream {
    uint32_t in_use;
    uint32_t frame_bytes;
    uint32_t capacity_frames;
    uint32_t device_kind;
    uint64_t stream_handle;
    int32_t shm_handle;
    void* mapping;
    uint32_t mapping_bytes;
    RinAudioServiceSharedRingV1* ring;
} ClientStream;

typedef struct ClientState {
    int fd;
    uint64_t next_request_id;
    uint64_t connection_id;
    ClientStream streams[CLIENT_STREAM_SLOTS];
} ClientState;

static ClientState g_client = {-1, 1u, 0u, {{0}}};
static volatile int g_client_io_lock = 0;

static void client_io_lock(void)
{
    while (__sync_lock_test_and_set(&g_client_io_lock, 1) != 0)
        rin_sleep(1u);
}

static void client_io_unlock(void)
{
    __sync_lock_release(&g_client_io_lock);
}

int rin_audio_service_client_init(void)
{
    int result = 0;
    client_io_lock();
    if (g_client.fd >= 0) {
        result = -1;
        goto done;
    }
    for (uint32_t index = 0u; index < CLIENT_STREAM_SLOTS; ++index) {
        if (g_client.streams[index].in_use != 0u) {
            result = -1;
            goto done;
        }
    }
    memset(&g_client, 0, sizeof(g_client));
    g_client.fd = -1;
    g_client.next_request_id = 1u;
done:
    client_io_unlock();
    return result;
}

static void reset_after_connection_failure(void)
{
    uint32_t index;
    if (g_client.fd >= 0) close(g_client.fd);
    g_client.fd = -1;
    g_client.connection_id = 0u;
    for (index = 0u; index < CLIENT_STREAM_SLOTS; ++index) {
        ClientStream* stream = &g_client.streams[index];
        if (stream->in_use != 0u)
            (void)rin_shm_dt(stream->shm_handle, stream->mapping);
        memset(stream, 0, sizeof(*stream));
    }
}

static int send_exact(const void* data, uint32_t bytes)
{
    const uint8_t* input = (const uint8_t*)data;
    uint32_t offset = 0u;
    while (offset < bytes) {
        ssize_t result = send(g_client.fd, input + offset, bytes - offset,
                              MSG_NOSIGNAL);
        if (result > 0) {
            if ((uint32_t)result > bytes - offset) return -1;
            offset += (uint32_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int receive_exact(void* data, uint32_t bytes)
{
    uint8_t* output = (uint8_t*)data;
    uint32_t offset = 0u;
    while (offset < bytes) {
        ssize_t result = recv(g_client.fd, output + offset, bytes - offset, 0);
        if (result > 0) {
            if ((uint32_t)result > bytes - offset) return -1;
            offset += (uint32_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int service_identity_valid(void)
{
    rin_unix_service_identity_v1 identity;
    socklen_t size = sizeof(identity);
    memset(&identity, 0, sizeof(identity));
    return getsockopt(g_client.fd, SOL_SOCKET, SO_RIN_UNIX_SERVICE_IDENTITY,
                      &identity, &size) == 0 && size == sizeof(identity) &&
           identity.slot_id != 0u &&
           (identity.flags & RIN_UNIX_SERVICE_IDENTITY_FLAG_PUBLISHED) != 0u;
}

static void header_init(RinAudioServiceMessageHeaderV1* header,
                        uint32_t operation, uint64_t stream_handle,
                        uint32_t payload_bytes)
{
    memset(header, 0, sizeof(*header));
    header->magic = RIN_AUDIO_SERVICE_PROTOCOL_MAGIC;
    header->version = RIN_AUDIO_SERVICE_PROTOCOL_VERSION;
    header->operation = operation;
    header->request_id = g_client.next_request_id++;
    if (g_client.next_request_id == 0u) g_client.next_request_id = 1u;
    header->stream_handle = stream_handle;
    header->payload_bytes = payload_bytes;
}

/* The caller must hold g_client_io_lock.  Keeping the lock-taking wrapper
 * separate lets disconnect drain streams atomically without recursively
 * acquiring the same spin lock through stream_destroy(). */
static int transact_locked(uint32_t operation, uint64_t stream_handle,
                           const void* request, uint32_t request_bytes,
                           void* reply, uint32_t reply_capacity)
{
    RinAudioServiceMessageHeaderV1 header;
    RinAudioServiceMessageHeaderV1 response;
    int result;
    if (request_bytes != 0u && request == NULL)
        return RIN_AUDIO_SERVICE_PROTOCOL;
    header_init(&header, operation, stream_handle, request_bytes);
    if (g_client.fd < 0) {
        result = RIN_AUDIO_SERVICE_PROTOCOL;
        goto done;
    }
    if (send_exact(&header, sizeof(header)) != 0 ||
        (request_bytes != 0u && send_exact(request, request_bytes) != 0) ||
        receive_exact(&response, sizeof(response)) != 0) {
        reset_after_connection_failure();
        result = RIN_AUDIO_SERVICE_PROTOCOL;
        goto done;
    }
    if (response.magic != RIN_AUDIO_SERVICE_PROTOCOL_MAGIC ||
        response.version != RIN_AUDIO_SERVICE_PROTOCOL_VERSION ||
        response.operation != operation || response.request_id != header.request_id ||
        response.stream_handle != stream_handle || response.reserved0 != 0u ||
        response.status > 0 ||
        (response.status != RIN_AUDIO_SERVICE_OK && response.payload_bytes != 0u) ||
        response.payload_bytes > reply_capacity ||
        (response.payload_bytes != 0u && reply == NULL)) {
        reset_after_connection_failure();
        result = RIN_AUDIO_SERVICE_PROTOCOL;
        goto done;
    }
    if (response.payload_bytes != 0u &&
        receive_exact(reply, response.payload_bytes) != 0) {
        reset_after_connection_failure();
        result = RIN_AUDIO_SERVICE_PROTOCOL;
        goto done;
    }
    result = response.status;
done:
    return result;
}

static int transact(uint32_t operation, uint64_t stream_handle,
                    const void* request, uint32_t request_bytes,
                    void* reply, uint32_t reply_capacity)
{
    int result;
    client_io_lock();
    result = transact_locked(operation, stream_handle, request, request_bytes,
                             reply, reply_capacity);
    client_io_unlock();
    return result;
}

static int stream_index_valid(int stream)
{
    return stream >= 0 && (uint32_t)stream < CLIENT_STREAM_SLOTS &&
           g_client.streams[stream].in_use != 0u;
}

static int client_stream_ring_valid(const ClientStream* state)
{
    uint64_t required_bytes;
    if (state == NULL || state->ring == NULL || state->mapping == NULL ||
        state->frame_bytes == 0u || state->capacity_frames == 0u)
        return 0;
    required_bytes = sizeof(*state->ring) +
        (uint64_t)state->capacity_frames * state->frame_bytes;
    return required_bytes <= UINT32_MAX &&
           state->mapping_bytes >= (uint32_t)required_bytes &&
           state->ring->frame_bytes == state->frame_bytes &&
           state->ring->capacity_frames == state->capacity_frames &&
           rin_audio_service_shared_ring_valid(state->ring);
}

static uint32_t format_frame_bytes(uint32_t channels, uint32_t sample_format)
{
    if (channels != 1u && channels != 2u) return 0u;
    if (sample_format != RIN_AUDIO_SERVICE_FORMAT_S16LE &&
        sample_format != RIN_AUDIO_SERVICE_FORMAT_F32LE) return 0u;
    return channels * (sample_format == RIN_AUDIO_SERVICE_FORMAT_F32LE ? 4u : 2u);
}

/* The caller must hold g_client_io_lock. */
static int client_connect_locked(void)
{
    struct sockaddr_un address;
    RinAudioServiceMessageHeaderV1 response;
    RinAudioServiceConnectReplyV1 payload;
    RinAudioServiceMessageHeaderV1 request;
    int fd;
    int result = -1;
    if (g_client.fd >= 0) {
        result = 0;
        goto done;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) goto done;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (sizeof(RIN_AUDIO_SERVICE_SOCKET_PATH) > sizeof(address.sun_path)) {
        close(fd);
        goto done;
    }
    memcpy(address.sun_path, RIN_AUDIO_SERVICE_SOCKET_PATH,
           sizeof(RIN_AUDIO_SERVICE_SOCKET_PATH));
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0) {
        close(fd);
        goto done;
    }
    g_client.fd = fd;
    if (!service_identity_valid()) {
        close(fd);
        g_client.fd = -1;
        goto done;
    }
    header_init(&request, RIN_AUDIO_SERVICE_OP_CONNECT, 0u, 0u);
    if (send_exact(&request, sizeof(request)) != 0 ||
        receive_exact(&response, sizeof(response)) != 0 ||
        response.magic != RIN_AUDIO_SERVICE_PROTOCOL_MAGIC ||
        response.version != RIN_AUDIO_SERVICE_PROTOCOL_VERSION ||
        response.operation != RIN_AUDIO_SERVICE_OP_CONNECT ||
        response.request_id != request.request_id || response.stream_handle != 0u ||
        response.reserved0 != 0u ||
        response.payload_bytes != sizeof(payload) || response.status != 0 ||
        receive_exact(&payload, sizeof(payload)) != 0 ||
        payload.struct_size != sizeof(payload) ||
        !rin_audio_service_connect_reply_valid(&payload)) {
        close(fd);
        g_client.fd = -1;
        goto done;
    }
    g_client.connection_id = payload.connection_id;
    result = 0;
done:
    return result;
}

int rin_audio_service_client_connect(void)
{
    int result;
    client_io_lock();
    result = client_connect_locked();
    client_io_unlock();
    return result;
}

int rin_audio_service_client_is_connected(void)
{
    int result;
    client_io_lock();
    result = g_client.fd >= 0 ? 1 : 0;
    client_io_unlock();
    return result;
}

static int stream_destroy_locked(int stream)
{
    ClientStream snapshot;
    int result;
    if (!stream_index_valid(stream)) return -1;
    snapshot = g_client.streams[stream];
    result = transact_locked(RIN_AUDIO_SERVICE_OP_DESTROY_STREAM,
                             snapshot.stream_handle, NULL, 0u, NULL, 0u);
    /* A failed transaction resets every stale stream and releases its SHM;
     * do not detach this snapshot a second time in that case.  BUSY is
     * retryable: retain both local and server ownership and return the exact
     * service status to the caller. */
    if (!stream_index_valid(stream)) return result == 0 ? 0 : -1;
    if (result == RIN_AUDIO_SERVICE_BUSY) return result;
    memset(&g_client.streams[stream], 0, sizeof(g_client.streams[stream]));
    (void)rin_shm_dt(snapshot.shm_handle, snapshot.mapping);
    return result == 0 ? 0 : -1;
}

int rin_audio_service_client_disconnect(void)
{
    uint32_t index;
    client_io_lock();
    if (g_client.fd < 0) {
        client_io_unlock();
        return 0;
    }
    for (index = 0u; index < CLIENT_STREAM_SLOTS; ++index)
        if (g_client.streams[index].in_use != 0u)
            (void)stream_destroy_locked((int)index);
    reset_after_connection_failure();
    client_io_unlock();
    return 0;
}

void rin_audio_service_client_reset(void)
{
    (void)rin_audio_service_client_disconnect();
    (void)rin_audio_service_client_init();
}

static int stream_create_kind_category(uint32_t sample_rate,
                                       uint32_t channels,
                                       uint32_t sample_format,
                                       uint32_t capacity_frames,
                                       uint32_t device_kind,
                                       uint64_t device_id,
                                       uint32_t category)
{
    RinAudioServiceCreateStreamRequestV1 request;
    RinAudioServiceStreamReplyV1 reply;
    ClientStream* stream = NULL;
    uint32_t index;
    uint32_t frame_bytes = format_frame_bytes(channels, sample_format);
    uint64_t data_bytes;
    uint32_t mapping_bytes;
    uint64_t nonce;
    char name[64];
    int handle = -1;
    void* mapping = NULL;
    int result = -1;
    client_io_lock();
    if (g_client.fd < 0 && client_connect_locked() != 0) goto done;
    if (frame_bytes == 0u || sample_rate < 8000u || sample_rate > 192000u ||
        (device_kind != RIN_MEDIA_AUDIO_DEVICE_OUTPUT &&
         device_kind != RIN_MEDIA_AUDIO_DEVICE_INPUT) ||
         category >= RIN_AUDIO_SERVICE_STREAM_CATEGORY_MAX ||
         capacity_frames < RIN_AUDIO_SERVICE_MIN_RING_FRAMES ||
         capacity_frames > RIN_AUDIO_SERVICE_MAX_RING_FRAMES ||
         capacity_frames > UINT32_MAX / frame_bytes)
        goto done;
    for (index = 0u; index < CLIENT_STREAM_SLOTS; ++index)
        if (g_client.streams[index].in_use == 0u) { stream = &g_client.streams[index]; break; }
    if (stream == NULL) goto done;
    nonce = rin_monotonic_ms();
    if (snprintf(name, sizeof(name), ".rin.audio:%u:%llu:%u", index,
                 (unsigned long long)nonce,
                 (unsigned int)g_client.connection_id) <= 0)
        goto done;
    data_bytes = (uint64_t)capacity_frames * frame_bytes;
    if (data_bytes > UINT32_MAX - sizeof(RinAudioServiceSharedRingV1)) goto done;
    mapping_bytes = (uint32_t)(sizeof(RinAudioServiceSharedRingV1) + data_bytes);
    handle = rin_shm_get(name, mapping_bytes,
                         RIN_SHM_FLAG_CREAT | RIN_SHM_FLAG_EXCL |
                         RIN_SHM_FLAG_UNLINK_ON_CLOSE);
    if (handle < 0) goto done;
    mapping = rin_shm_at(handle, NULL, RIN_SHM_PROT_READ | RIN_SHM_PROT_WRITE);
    if (mapping == NULL) goto done;
    memset(mapping, 0, mapping_bytes);
    memset(&request, 0, sizeof(request));
    request.format.struct_size = sizeof(request.format);
    request.format.version = RIN_AUDIO_SERVICE_PROTOCOL_VERSION;
    request.format.sample_rate = sample_rate;
    request.format.channels = channels;
    request.format.sample_format = sample_format;
    request.capacity_frames = capacity_frames;
    request.device_kind = device_kind;
    request.device_id = device_id;
    request.category = category;
    memcpy(request.ring_name, name, strlen(name) + 1u);
    if (!rin_audio_service_create_stream_request_valid(&request)) goto done;
    if (transact_locked(RIN_AUDIO_SERVICE_OP_CREATE_STREAM, 0u, &request,
                 sizeof(request), &reply, sizeof(reply)) != 0 ||
        !rin_audio_service_stream_reply_valid(&reply, capacity_frames,
                                              frame_bytes)) {
        goto done;
    }
    {
        RinAudioServiceSharedRingV1* ring = (RinAudioServiceSharedRingV1*)mapping;
        ring->magic = RIN_AUDIO_SERVICE_RING_MAGIC;
        ring->version = RIN_AUDIO_SERVICE_PROTOCOL_VERSION;
        ring->header_bytes = sizeof(*ring);
        ring->frame_bytes = frame_bytes;
        ring->capacity_frames = capacity_frames;
        ring->stream_generation = reply.stream_generation;
        __atomic_store_n(&ring->producer_frames, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ring->consumer_frames, 0u, __ATOMIC_RELEASE);
        stream->ring = ring;
    }
    stream->in_use = 1u;
    stream->frame_bytes = frame_bytes;
    stream->capacity_frames = capacity_frames;
    stream->device_kind = device_kind;
    stream->stream_handle = reply.stream_handle;
    stream->shm_handle = handle;
    stream->mapping = mapping;
    stream->mapping_bytes = mapping_bytes;
    result = (int)index;
done:
    if (result < 0 && handle >= 0) (void)rin_shm_dt(handle, mapping);
    client_io_unlock();
    return result;
}

int rin_audio_service_stream_create(uint32_t sample_rate, uint32_t channels,
                                    uint32_t sample_format,
                                    uint32_t capacity_frames)
{
    return rin_audio_service_stream_create_category(
        sample_rate, channels, sample_format, capacity_frames,
        RIN_AUDIO_SERVICE_STREAM_CATEGORY_APPLICATION);
}

int rin_audio_service_stream_create_category(uint32_t sample_rate,
                                             uint32_t channels,
                                             uint32_t sample_format,
                                             uint32_t capacity_frames,
                                             uint32_t category)
{
    return stream_create_kind_category(
        sample_rate, channels, sample_format, capacity_frames,
        RIN_MEDIA_AUDIO_DEVICE_OUTPUT, 0u, category);
}

int rin_audio_service_stream_create_category_for_device(
    uint32_t sample_rate, uint32_t channels, uint32_t sample_format,
    uint32_t capacity_frames, uint64_t device_id, uint32_t category)
{
    return stream_create_kind_category(
        sample_rate, channels, sample_format, capacity_frames,
        RIN_MEDIA_AUDIO_DEVICE_OUTPUT, device_id, category);
}

int rin_audio_service_capture_stream_create(uint32_t sample_rate,
                                            uint32_t channels,
                                            uint32_t sample_format,
                                            uint32_t capacity_frames)
{
    return stream_create_kind_category(
        sample_rate, channels, sample_format, capacity_frames,
        RIN_MEDIA_AUDIO_DEVICE_INPUT,
        0u, RIN_AUDIO_SERVICE_STREAM_CATEGORY_APPLICATION);
}

int rin_audio_service_capture_stream_create_for_device(
    uint32_t sample_rate, uint32_t channels, uint32_t sample_format,
    uint32_t capacity_frames, uint64_t device_id)
{
    return stream_create_kind_category(
        sample_rate, channels, sample_format, capacity_frames,
        RIN_MEDIA_AUDIO_DEVICE_INPUT, device_id,
        RIN_AUDIO_SERVICE_STREAM_CATEGORY_APPLICATION);
}

int rin_audio_service_stream_destroy(int stream)
{
    int result;
    client_io_lock();
    result = stream_index_valid(stream) ? stream_destroy_locked(stream) : -1;
    client_io_unlock();
    return result;
}

int rin_audio_service_stream_write(int stream, const void* samples,
                                   uint32_t bytes)
{
    ClientStream* state;
    uint32_t offset = 0u;
    uint32_t retries = 0u;
    int result;
    client_io_lock();
    if (!stream_index_valid(stream) || (bytes != 0u && samples == NULL)) {
        result = -1;
        goto done;
    }
    state = &g_client.streams[stream];
    if (!client_stream_ring_valid(state) || bytes % state->frame_bytes != 0u) {
        result = -1;
        goto done;
    }
    while (offset < bytes) {
        uint64_t producer = __atomic_load_n(&state->ring->producer_frames,
                                            __ATOMIC_RELAXED);
        uint64_t consumer = __atomic_load_n(&state->ring->consumer_frames,
                                            __ATOMIC_ACQUIRE);
        uint64_t queued;
        uint32_t writable;
        uint32_t first;
        uint32_t frame_offset;
        uint32_t bytes_to_end;
        if (producer < consumer || producer - consumer > state->capacity_frames)
        {
            result = offset == 0u ? -1 : (int)offset;
            goto done;
        }
        queued = producer - consumer;
        writable = (uint32_t)((state->capacity_frames - queued) * state->frame_bytes);
        if (writable > bytes - offset) writable = bytes - offset;
        if (writable == 0u) {
            if (++retries >= CLIENT_IO_RETRIES) break;
            rin_sleep(1u);
            continue;
        }
        frame_offset = (uint32_t)(producer % state->capacity_frames);
        bytes_to_end = (state->capacity_frames - frame_offset) * state->frame_bytes;
        first = writable > bytes_to_end ? bytes_to_end : writable;
        memcpy((uint8_t*)state->mapping + sizeof(*state->ring) +
                   frame_offset * state->frame_bytes,
               (const uint8_t*)samples + offset, first);
        if (writable > first)
            memcpy((uint8_t*)state->mapping + sizeof(*state->ring),
                   (const uint8_t*)samples + offset + first, writable - first);
        if (producer > UINT64_MAX - writable / state->frame_bytes) {
            result = offset == 0u ? -1 : (int)offset;
            goto done;
        }
        __atomic_store_n(&state->ring->producer_frames,
                         producer + writable / state->frame_bytes,
                         __ATOMIC_RELEASE);
        offset += writable;
        retries = 0u;
    }
    result = (int)offset;
done:
    client_io_unlock();
    return result;
}

int rin_audio_service_capture_stream_read(int stream, void* samples,
                                          uint32_t bytes)
{
    ClientStream* state;
    uint64_t producer;
    uint64_t consumer;
    uint64_t available;
    uint32_t readable;
    uint32_t first;
    int result;
    client_io_lock();
    if (!stream_index_valid(stream) ||
        g_client.streams[stream].device_kind != RIN_MEDIA_AUDIO_DEVICE_INPUT ||
        (bytes != 0u && samples == NULL)) {
        result = -1;
        goto done;
    }
    state = &g_client.streams[stream];
    if (!client_stream_ring_valid(state) || bytes % state->frame_bytes != 0u) {
        result = -1;
        goto done;
    }
    producer = __atomic_load_n(&state->ring->producer_frames, __ATOMIC_ACQUIRE);
    consumer = __atomic_load_n(&state->ring->consumer_frames, __ATOMIC_RELAXED);
    if (producer < consumer || producer - consumer > state->capacity_frames)
    {
        result = -1;
        goto done;
    }
    available = producer - consumer;
    readable = bytes > available * state->frame_bytes
        ? (uint32_t)(available * state->frame_bytes) : bytes;
    first = readable;
    if (readable != 0u) {
        uint32_t frame_offset = (uint32_t)(consumer % state->capacity_frames);
        uint32_t bytes_to_end = (state->capacity_frames - frame_offset) *
            state->frame_bytes;
        if (first > bytes_to_end) first = bytes_to_end;
        memcpy(samples, (uint8_t*)state->mapping + sizeof(*state->ring) +
                   frame_offset * state->frame_bytes, first);
        if (readable > first)
            memcpy((uint8_t*)samples + first,
                   (uint8_t*)state->mapping + sizeof(*state->ring),
                   readable - first);
        if (consumer > UINT64_MAX - readable / state->frame_bytes) {
            result = -1;
            goto done;
        }
        __atomic_store_n(&state->ring->consumer_frames,
                         consumer + readable / state->frame_bytes,
                         __ATOMIC_RELEASE);
    }
    result = (int)readable;
done:
    client_io_unlock();
    return result;
}

static int stream_operation(int stream, uint32_t operation)
{
    int result;
    client_io_lock();
    result = stream_index_valid(stream)
        ? transact_locked(operation, g_client.streams[stream].stream_handle,
                          NULL, 0u, NULL, 0u)
        : -1;
    client_io_unlock();
    return result;
}

int rin_audio_service_stream_start(int stream)
{ return stream_operation(stream, RIN_AUDIO_SERVICE_OP_START); }
int rin_audio_service_stream_pause(int stream)
{ return stream_operation(stream, RIN_AUDIO_SERVICE_OP_PAUSE); }
int rin_audio_service_stream_resume(int stream)
{ return stream_operation(stream, RIN_AUDIO_SERVICE_OP_RESUME); }
int rin_audio_service_stream_flush(int stream)
{ return stream_operation(stream, RIN_AUDIO_SERVICE_OP_FLUSH); }

int rin_audio_service_stream_drain(int stream)
{
    uint32_t retries = 0u;
    int result;
    client_io_lock();
    if (!stream_index_valid(stream)) {
        client_io_unlock();
        return -1;
    }
    do {
        result = transact_locked(RIN_AUDIO_SERVICE_OP_DRAIN,
                                 g_client.streams[stream].stream_handle,
                                 NULL, 0u, NULL, 0u);
        if (result != 0) break;
        if (__atomic_load_n(&g_client.streams[stream].ring->producer_frames,
                            __ATOMIC_ACQUIRE) ==
            __atomic_load_n(&g_client.streams[stream].ring->consumer_frames,
            __ATOMIC_ACQUIRE)) {
            result = 0;
            break;
        }
        if (++retries >= CLIENT_IO_RETRIES) {
            result = -1;
            break;
        }
        rin_sleep(1u);
    } while (1);
    client_io_unlock();
    return result;
}

static int stream_value(int stream, uint32_t operation, uint32_t value)
{
    RinAudioServiceValueRequestV1 request = {value, 0u};
    int result;
    if ((operation == RIN_AUDIO_SERVICE_OP_SET_STREAM_MUTE && value > 1u) ||
        (operation == RIN_AUDIO_SERVICE_OP_SET_STREAM_VOLUME && value > 100u))
        return -1;
    client_io_lock();
    result = stream_index_valid(stream)
        ? transact_locked(operation, g_client.streams[stream].stream_handle,
                          &request, sizeof(request), NULL, 0u)
        : -1;
    client_io_unlock();
    return result;
}

int rin_audio_service_stream_set_volume(int stream, uint32_t volume)
{ return stream_value(stream, RIN_AUDIO_SERVICE_OP_SET_STREAM_VOLUME, volume); }
int rin_audio_service_stream_set_mute(int stream, uint32_t muted)
{ return stream_value(stream, RIN_AUDIO_SERVICE_OP_SET_STREAM_MUTE, muted); }

int rin_audio_service_stream_set_pan(int stream, int32_t pan)
{
    RinAudioServicePanRequestV1 request;
    int result;
    if (pan < -100 || pan > 100) return -1;
    request.pan = pan;
    request.reserved0 = 0u;
    client_io_lock();
    result = stream_index_valid(stream)
        ? transact_locked(RIN_AUDIO_SERVICE_OP_SET_STREAM_PAN,
                          g_client.streams[stream].stream_handle,
                          &request, sizeof(request), NULL, 0u)
        : -1;
    client_io_unlock();
    return result;
}

int rin_audio_service_client_set_policy(
    const RinRuntimeAudioPolicyCatalogV1* policy)
{
    int result;
    if (policy == NULL || !rinruntime_audio_policy_catalog_valid(policy))
        return -1;
    client_io_lock();
    result = client_connect_locked() == 0
        ? transact_locked(RIN_AUDIO_SERVICE_OP_SET_POLICY, 0u, policy,
                          sizeof(*policy), NULL, 0u)
        : -1;
    client_io_unlock();
    return result;
}

static int connection_value(uint32_t operation, uint32_t value)
{
    RinAudioServiceValueRequestV1 request = {value, 0u};
    int result;
    client_io_lock();
    result = client_connect_locked() == 0
        ? transact_locked(operation, 0u, &request, sizeof(request), NULL, 0u)
        : -1;
    client_io_unlock();
    return result;
}

int rin_audio_service_client_set_application_volume(uint32_t volume)
{ return volume <= 100u ? connection_value(RIN_AUDIO_SERVICE_OP_SET_APPLICATION_VOLUME, volume) : -1; }
int rin_audio_service_client_set_application_mute(uint32_t muted)
{ return muted <= 1u ? connection_value(RIN_AUDIO_SERVICE_OP_SET_APPLICATION_MUTE, muted) : -1; }
int rin_audio_service_client_set_master_volume(uint32_t volume)
{ return volume <= 100u ? connection_value(RIN_AUDIO_SERVICE_OP_SET_MASTER_VOLUME, volume) : -1; }
int rin_audio_service_client_set_master_mute(uint32_t muted)
{ return muted <= 1u ? connection_value(RIN_AUDIO_SERVICE_OP_SET_MASTER_MUTE, muted) : -1; }
int rin_audio_service_client_set_input_volume(uint32_t volume)
{ return volume <= 100u ? connection_value(RIN_AUDIO_SERVICE_OP_SET_INPUT_VOLUME, volume) : -1; }
int rin_audio_service_client_set_input_mute(uint32_t muted)
{ return muted <= 1u ? connection_value(RIN_AUDIO_SERVICE_OP_SET_INPUT_MUTE, muted) : -1; }

static int category_value(uint32_t operation, uint32_t category,
                          uint32_t value)
{
    RinAudioServiceCategoryValueRequestV1 request;
    int result;
    if (category >= RIN_AUDIO_SERVICE_STREAM_CATEGORY_MAX ||
        (operation == RIN_AUDIO_SERVICE_OP_SET_CATEGORY_MUTE
             ? value > 1u : value > 100u))
        return -1;
    request.category = category;
    request.value = value;
    client_io_lock();
    result = client_connect_locked() == 0
        ? transact_locked(operation, 0u, &request, sizeof(request), NULL, 0u)
        : -1;
    client_io_unlock();
    return result;
}

int rin_audio_service_client_set_category_volume(uint32_t category,
                                                 uint32_t volume)
{ return category_value(RIN_AUDIO_SERVICE_OP_SET_CATEGORY_VOLUME, category,
                        volume); }

int rin_audio_service_client_set_category_mute(uint32_t category,
                                               uint32_t muted)
{ return category_value(RIN_AUDIO_SERVICE_OP_SET_CATEGORY_MUTE, category,
                        muted); }

int rin_audio_service_stream_status(int stream, RinAudioServiceStatusV1* status)
{
    int result;
    client_io_lock();
    if (!stream_index_valid(stream) || status == NULL) {
        client_io_unlock();
        return -1;
    }
    result = transact_locked(RIN_AUDIO_SERVICE_OP_GET_STATUS,
                             g_client.streams[stream].stream_handle,
                             NULL, 0u, status, sizeof(*status));
    if (result != 0 || !rin_audio_service_status_valid(status))
        result = result == 0 ? RIN_AUDIO_SERVICE_PROTOCOL : result;
    else
        result = 0;
    client_io_unlock();
    return result;
}

int rin_audio_service_probe(RinAudioServiceStatusV1* status)
{
    int stream;
    int result;
    if (status == NULL) return -1;
    stream = rin_audio_service_stream_create(
        48000u, 2u, RIN_AUDIO_SERVICE_FORMAT_S16LE,
        RIN_AUDIO_SERVICE_MIN_RING_FRAMES);
    if (stream < 0) return -1;
    result = rin_audio_service_stream_status(stream, status);
    (void)rin_audio_service_stream_destroy(stream);
    return result;
}

int rin_audio_service_client_devices(RinAudioServiceDeviceListV1* devices)
{
    int result;
    if (devices == NULL)
        return -1;
    client_io_lock();
    if (client_connect_locked() != 0) {
        client_io_unlock();
        return -1;
    }
    result = transact_locked(RIN_AUDIO_SERVICE_OP_ENUMERATE_DEVICES, 0u,
                             NULL, 0u, devices, sizeof(*devices));
    if (result != 0 || !rin_audio_service_device_list_valid(devices))
        result = result == 0 ? RIN_AUDIO_SERVICE_PROTOCOL : result;
    else
        result = 0;
    client_io_unlock();
    return result;
}

static int select_device_kind(uint32_t kind, uint64_t device_id,
                              uint64_t generation)
{
    RinAudioServiceDeviceListV1 devices;
    uint32_t index;
    if (rin_audio_service_client_devices(&devices) != 0 ||
        generation != devices.snapshot_generation || device_id == 0u) return -1;
    for (index = 0u; index < devices.device_count; ++index)
        if (devices.devices[index].device_id == device_id &&
            devices.devices[index].kind == kind &&
            devices.devices[index].available != 0u) {
            RinAudioServiceSelectDeviceRequestV1 request;
            memset(&request, 0, sizeof(request));
            request.snapshot_generation = generation;
            request.device_id = device_id;
            request.kind = kind;
            return transact(RIN_AUDIO_SERVICE_OP_SELECT_DEVICE, 0u,
                            &request, sizeof(request), NULL, 0u);
        }
    return -1;
}

int rin_audio_service_select_output(uint64_t device_id, uint64_t generation)
{
    return select_device_kind(RIN_MEDIA_AUDIO_DEVICE_OUTPUT, device_id,
                              generation);
}

int rin_audio_service_select_input(uint64_t device_id, uint64_t generation)
{
    return select_device_kind(RIN_MEDIA_AUDIO_DEVICE_INPUT, device_id,
                              generation);
}

static int playToneCategory(uint32_t frames, int16_t amplitude,
                            uint32_t category)
{
    int16_t samples[480u * 2u];
    int stream;
    int result = 0;
    uint32_t frame;
    stream = rin_audio_service_stream_create_category(
        48000u, 2u, RIN_AUDIO_SERVICE_FORMAT_S16LE, 512u, category);
    if (stream < 0) return -1;
    if (frames > 480u) frames = 480u;
    for (frame = 0u; frame < frames; ++frame) {
        const int16_t value = (frame & 16u) != 0u ? amplitude : -amplitude;
        samples[frame * 2u] = value;
        samples[frame * 2u + 1u] = value;
    }
    if (rin_audio_service_stream_write(stream, samples,
                                       frames * 2u * sizeof(samples[0])) !=
        (int)(frames * 2u * sizeof(samples[0])) ||
        rin_audio_service_stream_start(stream) != 0 ||
        rin_audio_service_stream_drain(stream) != 0)
        result = -1;
    if (rin_audio_service_stream_destroy(stream) != 0) result = -1;
    return result;
}

int rin_audio_service_test_tone(void)
{
    return playToneCategory(
        480u, 4096, RIN_AUDIO_SERVICE_STREAM_CATEGORY_APPLICATION);
}

int rin_audio_service_system_notification_tone(void)
{
    return playToneCategory(
        240u, 2048, RIN_AUDIO_SERVICE_STREAM_CATEGORY_NOTIFICATION);
}

int rin_audio_service_system_login_tone(void)
{
    return playToneCategory(
        480u, 3072, RIN_AUDIO_SERVICE_STREAM_CATEGORY_LOGIN);
}

int rin_audio_service_system_logout_tone(void)
{
    return playToneCategory(
        360u, 3072, RIN_AUDIO_SERVICE_STREAM_CATEGORY_LOGOUT);
}

int rin_audio_service_system_error_tone(void)
{
    return playToneCategory(
        180u, 4096, RIN_AUDIO_SERVICE_STREAM_CATEGORY_ERROR);
}

int rin_audio_service_client_poll_events(RinAudioServiceEventBatchV1* events)
{
    int result;
    if (events == NULL)
        return -1;
    client_io_lock();
    if (client_connect_locked() != 0) {
        client_io_unlock();
        return -1;
    }
    result = transact_locked(RIN_AUDIO_SERVICE_OP_POLL_EVENTS, 0u, NULL, 0u,
                             events, sizeof(*events));
    if (result != 0 || !rin_audio_service_event_batch_valid(events))
        result = result == 0 ? RIN_AUDIO_SERVICE_PROTOCOL : result;
    else
        result = 0;
    client_io_unlock();
    return result;
}

int rin_audio_service_client_diagnostics(RinAudioServiceDiagnosticsV1* diagnostics)
{
    int result;
    if (diagnostics == NULL)
        return -1;
    client_io_lock();
    if (client_connect_locked() != 0) {
        client_io_unlock();
        return -1;
    }
    result = transact_locked(RIN_AUDIO_SERVICE_OP_GET_DIAGNOSTICS, 0u, NULL,
                             0u, diagnostics, sizeof(*diagnostics));
    if (result != 0 || !rin_audio_service_diagnostics_valid(diagnostics))
        result = result == 0 ? RIN_AUDIO_SERVICE_PROTOCOL : result;
    else
        result = 0;
    client_io_unlock();
    return result;
}

int rin_audio_service_client_applications(
    RinAudioServiceApplicationSnapshotListV1* applications)
{
    int result;
    if (applications == NULL)
        return -1;
    client_io_lock();
    if (client_connect_locked() != 0) {
        client_io_unlock();
        return -1;
    }
    result = transact_locked(RIN_AUDIO_SERVICE_OP_ENUMERATE_APPLICATIONS, 0u,
                             NULL, 0u, applications, sizeof(*applications));
    if (result != 0 || !rin_audio_service_application_snapshot_list_valid(
                             applications))
        result = result == 0 ? RIN_AUDIO_SERVICE_PROTOCOL : result;
    else
        result = 0;
    client_io_unlock();
    return result;
}

static int application_value_for(uint32_t operation, uint64_t application_id,
                                 uint64_t application_generation,
                                 uint32_t value)
{
    RinAudioServiceApplicationValueRequestV1 request;
    int result;
    if (application_id == 0u || application_generation == 0u ||
        (operation == RIN_AUDIO_SERVICE_OP_SET_APPLICATION_MUTE_FOR
             ? value > 1u : value > 100u))
        return -1;
    request.application_id = application_id;
    request.application_generation = application_generation;
    request.value = value;
    request.reserved0 = 0u;
    client_io_lock();
    result = client_connect_locked() == 0
        ? transact_locked(operation, 0u, &request, sizeof(request), NULL, 0u)
        : -1;
    client_io_unlock();
    return result;
}

int rin_audio_service_client_set_application_volume_for(
    uint64_t application_id, uint64_t application_generation,
    uint32_t volume)
{
    return application_value_for(
        RIN_AUDIO_SERVICE_OP_SET_APPLICATION_VOLUME_FOR,
        application_id, application_generation, volume);
}

int rin_audio_service_client_set_application_mute_for(
    uint64_t application_id, uint64_t application_generation,
    uint32_t muted)
{
    return application_value_for(
        RIN_AUDIO_SERVICE_OP_SET_APPLICATION_MUTE_FOR,
        application_id, application_generation, muted);
}

int rin_audio_admin_set_policy(const RinRuntimeAudioPolicyCatalogV1* policy)
{
    return rin_audio_service_client_set_policy(policy);
}

int rin_audio_admin_set_master_volume(uint32_t volume)
{
    return rin_audio_service_client_set_master_volume(volume);
}

int rin_audio_admin_set_master_mute(uint32_t muted)
{
    return rin_audio_service_client_set_master_mute(muted);
}

int rin_audio_admin_set_input_volume(uint32_t volume)
{
    return rin_audio_service_client_set_input_volume(volume);
}

int rin_audio_admin_set_input_mute(uint32_t muted)
{
    return rin_audio_service_client_set_input_mute(muted);
}

int rin_audio_admin_set_category_volume(uint32_t category, uint32_t volume)
{
    return rin_audio_service_client_set_category_volume(category, volume);
}

int rin_audio_admin_set_category_mute(uint32_t category, uint32_t muted)
{
    return rin_audio_service_client_set_category_mute(category, muted);
}

int rin_audio_admin_select_output(uint64_t device_id, uint64_t generation)
{
    return rin_audio_service_select_output(device_id, generation);
}

int rin_audio_admin_select_input(uint64_t device_id, uint64_t generation)
{
    return rin_audio_service_select_input(device_id, generation);
}

int rin_audio_admin_applications(
    RinAudioServiceApplicationSnapshotListV1* applications)
{
    return rin_audio_service_client_applications(applications);
}

int rin_audio_admin_set_application_volume_for(
    uint64_t application_id, uint64_t application_generation,
    uint32_t volume)
{
    return rin_audio_service_client_set_application_volume_for(
        application_id, application_generation, volume);
}

int rin_audio_admin_set_application_mute_for(
    uint64_t application_id, uint64_t application_generation,
    uint32_t muted)
{
    return rin_audio_service_client_set_application_mute_for(
        application_id, application_generation, muted);
}
