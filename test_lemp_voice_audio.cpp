// test_lemp_voice_audio.cpp — lemp_voice_audio: Opus round trip (must pass),
// device enumeration and a 1 s open of the default devices (reported, not
// required: a headless prefix has no microphone).
#include "lemp_voice.h"
#include "lemp_voice_audio.h"
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <thread>

static int g_fail = 0, g_pass = 0;
#define CHECK(c) do { if (c) ++g_pass; else { ++g_fail; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

using namespace voice;

static void TestCodec() {
    Encoder enc; Decoder dec;
    CHECK(enc.Ok() && dec.Ok());
    // 400 Hz tone, 1 s: the decoded signal must carry about the input's energy
    // (Opus is lossy and delays a few ms; compare energies, not samples).
    double inE = 0, outE = 0; size_t bytes = 0; int frames = 0;
    int16_t pcm[kFrameSamples], back[kFrameSamples];
    for (int f = 0; f < 50; ++f) {
        for (int i = 0; i < kFrameSamples; ++i) {
            double t = (double)(f * kFrameSamples + i) / kRate;
            pcm[i] = (int16_t)(8000 * std::sin(2 * 3.14159265358979 * 400 * t));
        }
        auto pkt = enc.Encode(pcm);
        CHECK(!pkt.empty() && pkt.size() <= kMaxPayload);
        bytes += pkt.size();
        CHECK(dec.Decode(pkt.data(), pkt.size(), back));
        if (f >= 5) {   // past the codec's start-up
            for (int i = 0; i < kFrameSamples; ++i) { inE += (double)pcm[i] * pcm[i]; outE += (double)back[i] * back[i]; }
            ++frames;
        }
    }
    double ratio = outE / inE;
    printf("codec: %zu bytes/s (%.1f kbit/s), energy ratio %.2f\n", bytes, bytes * 8 / 1000.0, ratio);
    CHECK(ratio > 0.5 && ratio < 1.5);
    CHECK(bytes * 8 < 40000);   // ~24 kbit/s
    // Concealment of a lost frame.
    CHECK(dec.Decode(nullptr, 0, back));
    // Silence is cheap.
    for (int i = 0; i < kFrameSamples; ++i) pcm[i] = 0;
    auto s = enc.Encode(pcm);
    CHECK(!s.empty());
}

static void TestDevices() {
    auto ins = InputDevices(), outs = OutputDevices();
    printf("inputs %zu (default %d), outputs %zu (default %d)\n", ins.size(), DefaultInputDevice(), outs.size(), DefaultOutputDevice());
    for (auto& n : ins) printf("  in:  %s\n", n.c_str());
    for (auto& n : outs) printf("  out: %s\n", n.c_str());
    Audio a;
    std::atomic<int> caps{0}, plays{0};
    a.onCaptured = [&](const int16_t*) { ++caps; };
    a.onPlayback = [&](int16_t* p) { for (int i = 0; i < kFrameSamples; ++i) p[i] = 0; ++plays; };
    bool ok = a.Start(-1, -1);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    printf("start %s: capture %s (%d frames), playback %s (%d frames) %s\n", ok ? "ok" : "failed",
           a.CaptureRunning() ? "on" : "off", caps.load(), a.PlaybackRunning() ? "on" : "off", plays.load(), a.Error().c_str());
    a.Stop();
}

int main() {
    TestCodec();
    TestDevices();
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
