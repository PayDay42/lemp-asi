// lemp_voice.h — voice chat's core for lemp.asi: framing, relay, talkers.
//
// 2012 had push-to-talk voice: EA DirtySDK's voipheadset (capture, playback)
// with Speex narrowband, carried peer to peer by BlazeSDK's
// ConnApiVoipManager, reached from script through the all-native
// SFXOnlineComponentVoiceInterface. LE3 kept that class (byte-identical) and
// dropped everything behind it: no capture, no codec, no transport [V].
// This is the engine behind the class again, in the
// same shape, with three substitutions forced by LE3:
//   - Speex -> Opus (lemp_voice_audio.h): Xiph's successor to Speex.
//   - voipheadset -> WASAPI (lemp_voice_audio.h).
//   - Blaze's peer-to-peer mesh -> frames on the game's own UDP socket, relayed
//     by the host. UE3 is client-server: a joiner knows only the host's
//     address. Every path a join takes already carries that socket (direct,
//     LAN, forwarded port, and lemp_punch.h's proxy, which passes any datagram
//     that is not one of its 24-byte control packets unchanged).
//
// This file is the part with no Windows, audio or game in it, so it is tested
// natively (test_lemp_voice.cpp): the wire format, who a frame goes to, who is
// talking, who is muted, and the per-talker playout queues and mix.
//
// The wire format, one datagram per frame:
//   "LEMV" | version 1 | type 1 (FRAME) | flags (1 = relayed) | 0
//   | sender UniqueNetId (8, LE) | sequence (2, LE) | payload length (2, LE)
//   | payload (one Opus packet, 20 ms)
// A datagram is voice only if the magic, version, type AND the exact length
// agree; anything else is the game's and is left alone. A UE3 packet matching
// all of that by chance would be dropped once (2^-32 on the magic alone).
//
// Who a frame goes to. Peers are the addresses the game's socket talks to (it
// sends to them, or hears from them) within the last kPeerTimeoutMs. Our own
// frames go to every peer. A frame heard from a peer is played, and, unless it
// is already marked relayed, forwarded marked relayed to every OTHER peer. On
// a joiner the only peer is the host, the source, so nothing is forwarded; on
// the host each joiner's frame reaches the other joiners. A relayed frame is
// never forwarded again, so no loops whatever the topology.
//
// Not thread-safe by itself: Engine is used under one lock (lemp_voice.cpp).
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <string>
#include <vector>

namespace voice {

constexpr uint8_t  kVersion       = 1;
constexpr uint8_t  kTypeFrame     = 1;
constexpr uint8_t  kFlagRelayed   = 1;
constexpr size_t   kHeaderLen     = 20;
constexpr size_t   kMaxPayload    = 512;     // an Opus 20 ms packet at 24 kbit/s is ~60 bytes
constexpr int      kRate          = 16000;   // Hz, mono
constexpr int      kFrameSamples  = 320;     // 20 ms at 16 kHz
constexpr uint32_t kFrameMs       = 20;
constexpr uint32_t kTalkingMs     = 300;     // "is talking": a frame within this
constexpr uint32_t kPeerTimeoutMs = 15000;   // longer than any gap in game traffic but a map load
constexpr size_t   kMaxQueue      = 15;      // 300 ms: more and the oldest go
constexpr size_t   kPrebuffer     = 3;       // 60 ms of jitter absorbed before playing

// GetRemotePlayerStatus's bits, as 2012's lobby reads them (SFXGUI_MPLobby:
// "& 16" = has a headset). Only that bit is known to be read [V]; the
// others are not set.
constexpr int kStatusHasHeadset = 16;

// The interface's modes. MPVoiceChatMode's own values are not yet known;
// SetVoiceMode's argument is logged and mapped here
// once they are. Until then: push to talk, 2012's binding (Tab).
enum class Mode { PushToTalk, OpenMic, Off };

struct Frame {
    uint64_t sender = 0;
    uint16_t seq = 0;
    uint8_t  flags = 0;
    std::vector<uint8_t> payload;
};

inline void Put16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
inline uint16_t Get16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
inline void Put64(uint8_t* p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
inline uint64_t Get64(const uint8_t* p) { uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }

inline std::vector<uint8_t> Encode(const Frame& f) {
    std::vector<uint8_t> out;
    if (f.payload.empty() || f.payload.size() > kMaxPayload) return out;
    out.resize(kHeaderLen + f.payload.size());
    uint8_t* p = out.data();
    p[0] = 'L'; p[1] = 'E'; p[2] = 'M'; p[3] = 'V';
    p[4] = kVersion; p[5] = kTypeFrame; p[6] = f.flags; p[7] = 0;
    Put64(p + 8, f.sender);
    Put16(p + 16, f.seq);
    Put16(p + 18, (uint16_t)f.payload.size());
    memcpy(p + kHeaderLen, f.payload.data(), f.payload.size());
    return out;
}

// True only for a whole, well-formed voice datagram.
inline bool IsVoice(const uint8_t* p, size_t n) {
    if (n <= kHeaderLen || n > kHeaderLen + kMaxPayload) return false;
    if (p[0] != 'L' || p[1] != 'E' || p[2] != 'M' || p[3] != 'V') return false;
    if (p[4] != kVersion || p[5] != kTypeFrame) return false;
    return (size_t)Get16(p + 18) + kHeaderLen == n;
}

inline bool Decode(const uint8_t* p, size_t n, Frame& f) {
    if (!IsVoice(p, n)) return false;
    f.flags = p[6];
    f.sender = Get64(p + 8);
    f.seq = Get16(p + 16);
    f.payload.assign(p + kHeaderLen, p + n);
    return true;
}

// What the engine asks its owner to put on the wire: a datagram for an address.
// Addresses are opaque bytes (a sockaddr, as the socket hook sees it).
struct Send {
    std::string to;
    std::vector<uint8_t> bytes;
};

// One remote talker: who, when last heard, muted, and its decoded 20 ms frames
// waiting to be played.
struct Talker {
    uint32_t lastHeard = 0;
    bool     heard = false;
    bool     muted = false;
    bool     playing = false;          // prebuffer reached; drains until empty
    uint16_t lastSeq = 0;
    std::deque<std::vector<int16_t>> queue;
};

class Engine {
public:
    // --- identity and settings ---------------------------------------------------
    void SetLocalId(uint64_t id) { localId_ = id; }
    uint64_t LocalId() const { return localId_; }
    void SetMode(Mode m) { mode_ = m; if (m == Mode::Off) ptt_ = false; }
    Mode GetMode() const { return mode_; }
    void SetVolume(float v) { volume_ = std::max(0.0f, std::min(v, 2.0f)); }
    float Volume() const { return volume_; }
    void SetHeadset(bool present) { headset_ = present; }
    bool Headset() const { return headset_; }

    // --- peers: the addresses the game's socket talks to ----------------------
    void NoteGameTraffic(const std::string& addr, uint32_t now) { peers_[addr] = now; }
    std::vector<std::string> Peers(uint32_t now) {
        std::vector<std::string> out;
        for (auto it = peers_.begin(); it != peers_.end();) {
            if (now - it->second > kPeerTimeoutMs) it = peers_.erase(it);
            else { out.push_back(it->first); ++it; }
        }
        return out;
    }

    // --- local talker ------------------------------------------------------------
    void PushToTalk(bool down) { ptt_ = down && mode_ != Mode::Off; }
    bool PushToTalkDown() const { return ptt_; }
    // Whether captured audio is sent now: PTT held, or open mic and voice in
    // the frame (`voiced`, the capture side's energy gate).
    bool Transmitting(bool voiced) const {
        if (!headset_ || mode_ == Mode::Off || !localId_) return false;
        return mode_ == Mode::PushToTalk ? ptt_ : voiced;
    }
    bool LocalTalking(uint32_t now) const { return sentAny_ && now - lastSent_ < kTalkingMs; }

    // One encoded 20 ms frame of ours -> a datagram for every peer.
    std::vector<Send> LocalFrame(const std::vector<uint8_t>& payload, uint32_t now) {
        std::vector<Send> out;
        if (!localId_ || payload.empty()) return out;
        Frame f; f.sender = localId_; f.seq = seq_++; f.payload = payload;
        std::vector<uint8_t> bytes = Encode(f);
        if (bytes.empty()) return out;
        for (auto& p : Peers(now)) out.push_back({p, bytes});
        lastSent_ = now; sentAny_ = true;
        return out;
    }

    // A voice datagram from `from`. Returns the forwards (host only, in effect).
    // `heard` is set to the frame to decode and play, or left empty (muted,
    // our own echo, stale or malformed).
    std::vector<Send> Received(const std::string& from, const uint8_t* p, size_t n,
                               uint32_t now, Frame* heard) {
        std::vector<Send> out;
        if (heard) heard->payload.clear();
        Frame f;
        if (!Decode(p, n, f)) return out;
        peers_[from] = now;   // voice keeps a peer alive as game traffic does
        if (!(f.flags & kFlagRelayed)) {
            Frame r = f; r.flags |= kFlagRelayed;
            std::vector<uint8_t> bytes = Encode(r);
            for (auto& peer : Peers(now)) if (peer != from) out.push_back({peer, bytes});
        }
        if (f.sender == 0 || f.sender == localId_) return out;
        Talker& t = talkers_[f.sender];
        // Late or duplicate (sequence behind the last one played, mod 2^16).
        if (t.heard && (int16_t)(f.seq - t.lastSeq) <= 0) return out;
        t.heard = true; t.lastSeq = f.seq; t.lastHeard = now;
        if (!t.muted && heard) *heard = f;
        return out;
    }

    // --- remote talkers, as the natives ask about them ------------------------
    bool RemoteTalking(uint64_t id, uint32_t now) const {
        auto it = talkers_.find(id);
        return it != talkers_.end() && it->second.heard && !it->second.muted && now - it->second.lastHeard < kTalkingMs;
    }
    // Has a headset: we have heard from it during this session. 2012's lobby
    // shows the speaker icon from this bit (-1 = no icon otherwise).
    int RemoteStatus(uint64_t id) const {
        auto it = talkers_.find(id);
        return (it != talkers_.end() && it->second.heard) ? kStatusHasHeadset : 0;
    }
    void Mute(uint64_t id, bool m) {
        Talker& t = talkers_[id];
        t.muted = m;
        if (m) { t.queue.clear(); t.playing = false; }
        if (m) muted_[id] = true; else muted_.erase(id);
    }
    bool Muted(uint64_t id) const { return muted_.count(id) != 0; }
    void MuteAll(bool m) {
        for (auto& kv : talkers_) Mute(kv.first, m);
        allMuted_ = m;
    }
    bool AllMuted() const { return allMuted_; }

    // --- playout --------------------------------------------------------------------
    // A decoded frame for a talker (kFrameSamples samples).
    void Queue(uint64_t id, std::vector<int16_t> pcm) {
        Talker& t = talkers_[id];
        if (t.muted || allMuted_) return;
        t.queue.push_back(std::move(pcm));
        while (t.queue.size() > kMaxQueue) t.queue.pop_front();
    }
    // Mix one 20 ms frame from every talker that has reached its prebuffer.
    // Returns false when nothing was mixed (silence).
    bool Mix(int16_t* out) {
        int32_t acc[kFrameSamples] = {0};
        bool any = false;
        for (auto& kv : talkers_) {
            Talker& t = kv.second;
            if (!t.playing && t.queue.size() >= kPrebuffer) t.playing = true;
            if (!t.playing) continue;
            if (t.queue.empty()) { t.playing = false; continue; }
            const std::vector<int16_t>& f = t.queue.front();
            for (int i = 0; i < kFrameSamples && i < (int)f.size(); ++i) acc[i] += f[i];
            t.queue.pop_front();
            any = true;
        }
        for (int i = 0; i < kFrameSamples; ++i) {
            int32_t v = (int32_t)(acc[i] * volume_);
            out[i] = (int16_t)std::max(-32768, std::min(32767, v));
        }
        return any;
    }

    size_t QueuedFor(uint64_t id) const {
        auto it = talkers_.find(id);
        return it == talkers_.end() ? 0 : it->second.queue.size();
    }

private:
    uint64_t localId_ = 0;
    // Off by default: no one's microphone is sent until they
    // choose push to talk or always on; others are heard either way.
    Mode     mode_ = Mode::Off;
    float    volume_ = 1.0f;
    bool     headset_ = false;
    bool     ptt_ = false;
    bool     allMuted_ = false;
    bool     sentAny_ = false;
    uint32_t lastSent_ = 0;
    uint16_t seq_ = 0;
    std::map<std::string, uint32_t> peers_;
    std::map<uint64_t, Talker> talkers_;
    std::map<uint64_t, bool> muted_;
};

// Open mic's gate: a frame is voiced when its RMS is above the threshold
// (in 16-bit units; ~-40 dBFS by default), held for a short tail so the ends
// of words are not cut.
class Gate {
public:
    explicit Gate(int threshold = 330, int holdFrames = 15) : threshold_(threshold), hold_(holdFrames) {}
    bool Voiced(const int16_t* pcm, int n) {
        int64_t sum = 0;
        for (int i = 0; i < n; ++i) sum += (int64_t)pcm[i] * pcm[i];
        double rms = n ? __builtin_sqrt((double)sum / n) : 0;
        if (rms > peak_) peak_ = rms;
        if (rms >= threshold_) left_ = hold_;
        else if (left_ > 0) --left_;
        return left_ > 0;
    }
    int Threshold() const { return threshold_; }
    // The loudest frame since the last call (for the log: is the microphone
    // reaching the threshold at all).
    int TakePeak() { int p = (int)peak_; peak_ = 0; return p; }
private:
    int threshold_, hold_, left_ = 0;
    double peak_ = 0;
};

}  // namespace voice
