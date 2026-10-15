// test_lemp_voice.cpp — lemp_voice.h alone: wire format, relay, talkers, mute,
// playout. Native: g++ -std=c++17 -O2 -o /tmp/t test_lemp_voice.cpp && /tmp/t
// Under Wine: x86_64-w64-mingw32-g++ -std=c++17 -static ... && wine t.exe
#include "lemp_voice.h"
#include <cstdio>

static int g_fail = 0, g_pass = 0;
#define CHECK(c) do { if (c) ++g_pass; else { ++g_fail; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

using namespace voice;

static std::vector<uint8_t> Payload(uint8_t b, size_t n = 40) { return std::vector<uint8_t>(n, b); }

static void TestWire() {
    Frame f; f.sender = 0x1122334455667788ull; f.seq = 0xBEEF; f.flags = 0; f.payload = Payload(7, 60);
    auto b = Encode(f);
    CHECK(b.size() == kHeaderLen + 60);
    CHECK(IsVoice(b.data(), b.size()));
    Frame g; CHECK(Decode(b.data(), b.size(), g));
    CHECK(g.sender == f.sender && g.seq == f.seq && g.payload == f.payload);
    // Length must agree exactly: truncated or padded datagrams are the game's.
    CHECK(!IsVoice(b.data(), b.size() - 1));
    std::vector<uint8_t> longer = b; longer.push_back(0);
    CHECK(!IsVoice(longer.data(), longer.size()));
    // lemp_punch.h's control packets ("LEMP", 24 bytes) are not voice.
    uint8_t ctl[24] = {'L', 'E', 'M', 'P', 1, 1};
    CHECK(!IsVoice(ctl, sizeof(ctl)));
    // Wrong version / type.
    std::vector<uint8_t> v = b; v[4] = 2; CHECK(!IsVoice(v.data(), v.size()));
    v = b; v[5] = 9; CHECK(!IsVoice(v.data(), v.size()));
    // Empty and oversized payloads are refused at encode.
    Frame e; e.sender = 1; CHECK(Encode(e).empty());
    e.payload = Payload(1, kMaxPayload + 1); CHECK(Encode(e).empty());
    e.payload = Payload(1, kMaxPayload); CHECK(IsVoice(Encode(e).data(), Encode(e).size()));
}

// Host H with joiners A and B. A's frame reaches H; H plays it and forwards it,
// marked relayed, to B only; B plays it and forwards nothing.
static void TestRelay() {
    Engine host, a, b;
    host.SetLocalId(100); a.SetLocalId(1); b.SetLocalId(2);
    uint32_t t = 1000;
    host.NoteGameTraffic("A", t); host.NoteGameTraffic("B", t);
    a.NoteGameTraffic("H", t); b.NoteGameTraffic("H", t);

    auto sends = a.LocalFrame(Payload(5), t);
    CHECK(sends.size() == 1 && sends[0].to == "H");
    Frame heard;
    auto fwd = host.Received("A", sends[0].bytes.data(), sends[0].bytes.size(), t, &heard);
    CHECK(heard.sender == 1 && !heard.payload.empty());
    CHECK(fwd.size() == 1 && fwd[0].to == "B");
    Frame r; CHECK(Decode(fwd[0].bytes.data(), fwd[0].bytes.size(), r) && (r.flags & kFlagRelayed) && r.sender == 1);

    auto fwd2 = b.Received("H", fwd[0].bytes.data(), fwd[0].bytes.size(), t, &heard);
    CHECK(fwd2.empty());                       // relayed: never forwarded again
    CHECK(heard.sender == 1);
    CHECK(b.RemoteTalking(1, t + 100));
    CHECK(!b.RemoteTalking(1, t + kTalkingMs + 1));
    CHECK(b.RemoteStatus(1) == kStatusHasHeadset);
    CHECK(b.RemoteStatus(77) == 0);

    // The host's own frame goes to both joiners.
    auto hs = host.LocalFrame(Payload(6), t);
    CHECK(hs.size() == 2);

    // A joiner forwards nothing even for an unrelayed frame: its only peer is the source.
    Frame f; f.sender = 100; f.seq = 0; f.payload = Payload(1);
    auto bytes = Encode(f);
    CHECK(a.Received("H", bytes.data(), bytes.size(), t, &heard).empty());

    // Our own frame echoed back is not played.
    Frame mine; mine.sender = 1; mine.seq = 50; mine.flags = kFlagRelayed; mine.payload = Payload(1);
    auto mb = Encode(mine);
    a.Received("H", mb.data(), mb.size(), t, &heard);
    CHECK(heard.payload.empty());
}

static void TestPeersExpire() {
    Engine e; e.SetLocalId(1);
    e.NoteGameTraffic("X", 0);
    CHECK(e.Peers(kPeerTimeoutMs).size() == 1);
    CHECK(e.Peers(kPeerTimeoutMs + 1).empty());
    // No peers, no sends; no id, no sends.
    CHECK(e.LocalFrame(Payload(1), kPeerTimeoutMs + 2).empty());
    Engine n; n.NoteGameTraffic("X", 0);
    CHECK(n.LocalFrame(Payload(1), 0).empty());
}

static void TestSequence() {
    Engine e; e.SetLocalId(1); e.NoteGameTraffic("H", 0);
    Frame heard;
    auto send = [&](uint64_t who, uint16_t seq) {
        Frame f; f.sender = who; f.seq = seq; f.flags = kFlagRelayed; f.payload = Payload(1);
        auto b = Encode(f);
        e.Received("H", b.data(), b.size(), 0, &heard);
        return !heard.payload.empty();
    };
    CHECK(send(9, 10));
    CHECK(!send(9, 10));      // duplicate
    CHECK(!send(9, 9));       // late
    CHECK(send(9, 11));
    CHECK(send(9, 20));       // a gap (lost frames) is fine
    // The sequence wraps: 65534, 65535, 0, 1 all play.
    CHECK(send(8, 65534));
    CHECK(send(8, 65535));
    CHECK(send(8, 0));
    CHECK(send(8, 1));
    CHECK(!send(8, 65535));   // and the pre-wrap one is now late
}

static void TestMute() {
    Engine e; e.SetLocalId(1); e.NoteGameTraffic("H", 0);
    Frame heard;
    Frame f; f.sender = 9; f.seq = 1; f.flags = kFlagRelayed; f.payload = Payload(1);
    auto b = Encode(f);
    e.Mute(9, true);
    CHECK(e.Muted(9));
    e.Received("H", b.data(), b.size(), 0, &heard);
    CHECK(heard.payload.empty());              // not played
    CHECK(!e.RemoteTalking(9, 10));            // a muted talker shows as silent
    CHECK(e.RemoteStatus(9) == kStatusHasHeadset);   // but still has a headset
    e.Queue(9, std::vector<int16_t>(kFrameSamples, 100));
    CHECK(e.QueuedFor(9) == 0);
    e.Mute(9, false);
    CHECK(!e.Muted(9));
    f.seq = 2; b = Encode(f);
    e.Received("H", b.data(), b.size(), 20, &heard);
    CHECK(!heard.payload.empty());
    e.MuteAll(true); CHECK(e.Muted(9) && e.AllMuted());
    e.MuteAll(false); CHECK(!e.Muted(9) && !e.AllMuted());
}

static void TestTransmit() {
    Engine e;
    CHECK(e.GetMode() == Mode::Off);           // the microphone starts off
    e.SetHeadset(true); e.SetLocalId(5); e.PushToTalk(true);
    CHECK(!e.Transmitting(true) && !e.PushToTalkDown());
    e = Engine();
    e.SetMode(Mode::PushToTalk);
    CHECK(!e.Transmitting(true));              // no headset, no id
    e.SetHeadset(true); e.SetLocalId(5);
    CHECK(!e.Transmitting(true));              // push to talk, not held
    e.PushToTalk(true); CHECK(e.Transmitting(false));
    e.PushToTalk(false); CHECK(!e.Transmitting(true));
    e.SetMode(Mode::OpenMic);
    CHECK(e.Transmitting(true) && !e.Transmitting(false));
    e.SetMode(Mode::Off); e.PushToTalk(true);
    CHECK(!e.Transmitting(true) && !e.PushToTalkDown());
    e.SetMode(Mode::PushToTalk); e.NoteGameTraffic("H", 0);
    CHECK(!e.LocalTalking(0));
    e.LocalFrame(Payload(1), 100);
    CHECK(e.LocalTalking(200) && !e.LocalTalking(100 + kTalkingMs));
}

static void TestMix() {
    Engine e; e.SetLocalId(1);
    int16_t out[kFrameSamples];
    CHECK(!e.Mix(out));
    e.Queue(7, std::vector<int16_t>(kFrameSamples, 1000));
    e.Queue(7, std::vector<int16_t>(kFrameSamples, 1000));
    CHECK(!e.Mix(out));                        // under the prebuffer
    e.Queue(7, std::vector<int16_t>(kFrameSamples, 1000));
    e.Queue(8, std::vector<int16_t>(kFrameSamples, 30000));
    e.Queue(8, std::vector<int16_t>(kFrameSamples, 30000));
    e.Queue(8, std::vector<int16_t>(kFrameSamples, 30000));
    CHECK(e.Mix(out));
    CHECK(out[0] == 31000);
    CHECK(e.Mix(out) && e.Mix(out));           // drains both
    CHECK(e.QueuedFor(7) == 0);
    CHECK(!e.Mix(out));
    // Clipping and volume.
    for (int i = 0; i < 3; ++i) { e.Queue(7, std::vector<int16_t>(kFrameSamples, 30000)); e.Queue(8, std::vector<int16_t>(kFrameSamples, 30000)); }
    CHECK(e.Mix(out) && out[5] == 32767);
    e.SetVolume(0.5f);
    CHECK(e.Mix(out) && out[5] == 30000);
    // Overflow drops the oldest.
    for (size_t i = 0; i < kMaxQueue + 5; ++i) e.Queue(9, std::vector<int16_t>(kFrameSamples, (int16_t)i));
    CHECK(e.QueuedFor(9) == kMaxQueue);
}

static void TestGate() {
    Gate g(330, 2);
    std::vector<int16_t> quiet(kFrameSamples, 10), loud(kFrameSamples, 2000);
    CHECK(!g.Voiced(quiet.data(), kFrameSamples));
    CHECK(g.Voiced(loud.data(), kFrameSamples));
    CHECK(g.Voiced(quiet.data(), kFrameSamples));    // hold
    CHECK(!g.Voiced(quiet.data(), kFrameSamples));
}

int main() {
    TestWire(); TestRelay(); TestPeersExpire(); TestSequence(); TestMute();
    TestTransmit(); TestMix(); TestGate();
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
