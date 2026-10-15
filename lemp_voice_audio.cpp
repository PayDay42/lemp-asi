// lemp_voice_audio.cpp — see lemp_voice_audio.h.
#define MA_NO_DECODING
#define MA_NO_ENCODING
#define MA_NO_GENERATION
#define MA_NO_RESOURCE_MANAGER
#define MA_NO_NODE_GRAPH
#define MA_NO_ENGINE
#define MA_ENABLE_ONLY_SPECIFIC_BACKENDS
#define MA_ENABLE_WASAPI
#define MA_ENABLE_DSOUND
#define MA_ENABLE_WINMM
#define MA_ENABLE_PULSEAUDIO     // native test builds only; ignored on Windows
#define MA_ENABLE_ALSA
#define MA_ENABLE_NULL
#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"
#include <opus.h>
#include "lemp_voice.h"
#include "lemp_voice_audio.h"

namespace voice {

namespace {

// One context for enumeration, made on first use.
ma_context* Ctx() {
    static ma_context ctx;
    static bool tried = false, ok = false;
    if (!tried) { tried = true; ok = ma_context_init(nullptr, 0, nullptr, &ctx) == MA_SUCCESS; }
    return ok ? &ctx : nullptr;
}

struct DeviceList {
    std::vector<std::string> names;
    std::vector<ma_device_id> ids;
    int def = -1;
};

DeviceList List(bool capture) {
    DeviceList out;
    ma_context* c = Ctx();
    if (!c) return out;
    ma_device_info* play = nullptr; ma_uint32 nPlay = 0;
    ma_device_info* cap = nullptr;  ma_uint32 nCap = 0;
    if (ma_context_get_devices(c, &play, &nPlay, &cap, &nCap) != MA_SUCCESS) return out;
    ma_device_info* d = capture ? cap : play;
    ma_uint32 n = capture ? nCap : nPlay;
    for (ma_uint32 i = 0; i < n; ++i) {
        // PulseAudio (Proton/Wine) offers every output's loopback as a capture
        // device, "Monitor of ...": never a microphone, and they took the
        // options screen's 8 slots ahead of the real ones.
        if (capture && strstr(d[i].name, "Monitor of ")) continue;
        out.names.push_back(d[i].name);
        out.ids.push_back(d[i].id);
        if (d[i].isDefault && out.def < 0) out.def = (int)out.names.size() - 1;
    }
    return out;
}

}  // namespace

std::vector<std::string> InputDevices() { return List(true).names; }
std::vector<std::string> OutputDevices() { return List(false).names; }
int DefaultInputDevice() { return List(true).def; }
int DefaultOutputDevice() { return List(false).def; }

struct Audio::Impl {
    Audio* owner = nullptr;
    ma_device cap, play;
    bool capOk = false, playOk = false;
    ma_device_id capId, playId;
};

static void CaptureCb(ma_device* dev, void*, const void* in, ma_uint32 frames) {
    auto* impl = (Audio::Impl*)dev->pUserData;
    if (!in || !impl->owner->onCaptured) return;
    // Fixed-size callbacks (periodSizeInFrames, noFixedSizedCallback off), so
    // frames is kFrameSamples; split defensively if a backend ever differs.
    const int16_t* p = (const int16_t*)in;
    for (ma_uint32 off = 0; off + kFrameSamples <= frames; off += kFrameSamples)
        impl->owner->onCaptured(p + off);
}

static void PlaybackCb(ma_device* dev, void* out, const void*, ma_uint32 frames) {
    auto* impl = (Audio::Impl*)dev->pUserData;
    int16_t* p = (int16_t*)out;
    ma_uint32 off = 0;
    for (; off + kFrameSamples <= frames; off += kFrameSamples) {
        if (impl->owner->onPlayback) impl->owner->onPlayback(p + off);
        else memset(p + off, 0, kFrameSamples * sizeof(int16_t));
    }
    if (off < frames) memset(p + off, 0, (frames - off) * sizeof(int16_t));
}

Audio::Audio() : impl_(new Impl) { impl_->owner = this; }
Audio::~Audio() { Stop(); delete impl_; }

bool Audio::Start(int inputIndex, int outputIndex) {
    Stop();
    error_.clear();
    ma_context* c = Ctx();
    if (!c) { error_ = "no audio backend"; return false; }

    DeviceList ins = List(true), outs = List(false);

    ma_device_config cc = ma_device_config_init(ma_device_type_capture);
    cc.capture.format = ma_format_s16;
    cc.capture.channels = 1;
    cc.sampleRate = kRate;
    cc.periodSizeInFrames = kFrameSamples;
    cc.dataCallback = CaptureCb;
    cc.pUserData = impl_;
    if (inputIndex >= 0 && inputIndex < (int)ins.ids.size()) { impl_->capId = ins.ids[inputIndex]; cc.capture.pDeviceID = &impl_->capId; }
    if (ma_device_init(c, &cc, &impl_->cap) == MA_SUCCESS) {
        if (ma_device_start(&impl_->cap) == MA_SUCCESS) impl_->capOk = true;
        else ma_device_uninit(&impl_->cap);
    }
    if (!impl_->capOk) error_ += "no microphone; ";

    ma_device_config pc = ma_device_config_init(ma_device_type_playback);
    pc.playback.format = ma_format_s16;
    pc.playback.channels = 1;
    pc.sampleRate = kRate;
    pc.periodSizeInFrames = kFrameSamples;
    pc.dataCallback = PlaybackCb;
    pc.pUserData = impl_;
    if (outputIndex >= 0 && outputIndex < (int)outs.ids.size()) { impl_->playId = outs.ids[outputIndex]; pc.playback.pDeviceID = &impl_->playId; }
    if (ma_device_init(c, &pc, &impl_->play) == MA_SUCCESS) {
        if (ma_device_start(&impl_->play) == MA_SUCCESS) impl_->playOk = true;
        else ma_device_uninit(&impl_->play);
    }
    if (!impl_->playOk) error_ += "no speakers; ";
    return impl_->capOk || impl_->playOk;
}

void Audio::Stop() {
    if (impl_->capOk) { ma_device_uninit(&impl_->cap); impl_->capOk = false; }
    if (impl_->playOk) { ma_device_uninit(&impl_->play); impl_->playOk = false; }
}

bool Audio::CaptureRunning() const { return impl_->capOk; }
bool Audio::PlaybackRunning() const { return impl_->playOk; }

// --- Opus --------------------------------------------------------------------------

Encoder::Encoder() {
    int err = 0;
    OpusEncoder* e = opus_encoder_create(kRate, 1, OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK || !e) return;
    opus_encoder_ctl(e, OPUS_SET_BITRATE(24000));
    opus_encoder_ctl(e, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(e, OPUS_SET_PACKET_LOSS_PERC(10));
    opus_encoder_ctl(e, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
    enc_ = e;
}
Encoder::~Encoder() { if (enc_) opus_encoder_destroy((OpusEncoder*)enc_); }

std::vector<uint8_t> Encoder::Encode(const int16_t* pcm) {
    std::vector<uint8_t> out;
    if (!enc_) return out;
    uint8_t buf[kMaxPayload];
    int n = opus_encode((OpusEncoder*)enc_, pcm, kFrameSamples, buf, (opus_int32)sizeof(buf));
    if (n > 0) out.assign(buf, buf + n);
    return out;
}

Decoder::Decoder() {
    int err = 0;
    OpusDecoder* d = opus_decoder_create(kRate, 1, &err);
    if (err == OPUS_OK) dec_ = d;
}
Decoder::~Decoder() { if (dec_) opus_decoder_destroy((OpusDecoder*)dec_); }

bool Decoder::Decode(const uint8_t* data, size_t n, int16_t* pcm) {
    if (!dec_) return false;
    int got = opus_decode((OpusDecoder*)dec_, data, data ? (opus_int32)n : 0, pcm, kFrameSamples, 0);
    return got == kFrameSamples;
}

}  // namespace voice
