// lemp_voice_audio.h — voice chat's sound: microphone, speakers, codec.
//
// Stands in for 2012's DirtySDK voipheadset (capture and playback) and its
// Speex narrowband codec, neither of which LE3 has [V]:
//   - capture and playback: miniaudio (vendor/miniaudio, public domain / MIT-0),
//     WASAPI first, DirectSound and WinMM as fallbacks. It converts from the
//     device's own format, so this side only ever sees 16 kHz mono 16-bit in
//     20 ms frames (lemp_voice.h kRate/kFrameSamples).
//   - codec: Opus (vendor/opus, BSD), voice mode, 24 kbit/s, in-band FEC.
//     Speex's successor from the same project; 2012 sent Speex at 8 kHz.
//
// Callbacks run on miniaudio's device threads: keep them short (lemp_voice.cpp
// only moves frames through its queues there).
#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace voice {

// Devices by name, in the backend's order. Index into these is what
// SetInputDevice/SetOutputDevice and MPVoiceChat*Device carry; -1 = default.
std::vector<std::string> InputDevices();
std::vector<std::string> OutputDevices();
int DefaultInputDevice();    // index of the system default, or -1
int DefaultOutputDevice();

class Audio {
public:
    Audio();
    ~Audio();
    Audio(const Audio&) = delete;
    Audio& operator=(const Audio&) = delete;

    // One 20 ms frame captured (kFrameSamples samples).
    std::function<void(const int16_t*)> onCaptured;
    // Fill one 20 ms frame for the speakers (kFrameSamples samples).
    std::function<void(int16_t*)> onPlayback;

    // Opens both devices (index -1 = default). Either may fail on its own:
    // no microphone still hears others. Returns false only if both failed.
    bool Start(int inputIndex, int outputIndex);
    void Stop();
    bool CaptureRunning() const;
    bool PlaybackRunning() const;
    const std::string& Error() const { return error_; }

    struct Impl;   // public only so the device callbacks can name it
private:
    Impl* impl_;
    std::string error_;
};

class Encoder {
public:
    Encoder();
    ~Encoder();
    bool Ok() const { return enc_ != nullptr; }
    // One 20 ms frame -> one Opus packet (empty on error).
    std::vector<uint8_t> Encode(const int16_t* pcm);
private:
    void* enc_ = nullptr;
};

class Decoder {
public:
    Decoder();
    ~Decoder();
    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;
    Decoder(Decoder&& o) noexcept : dec_(o.dec_) { o.dec_ = nullptr; }
    bool Ok() const { return dec_ != nullptr; }
    // One packet -> one 20 ms frame. A null packet conceals one lost frame.
    bool Decode(const uint8_t* data, size_t n, int16_t* pcm);
private:
    void* dec_ = nullptr;
};

}  // namespace voice
