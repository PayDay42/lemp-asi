// balance_classify.h — what the engine's SET/GET text means. No Windows dependency: testable with a plain g++ build
// (test_balance_classify.cpp), the way mp_save_format.h is.
//
// mp_save.cpp's ops 57 (SET) and 58/59 (GET) both go through PerformSetCommand
// or the exec dispatcher's GET case on the SAME class/property lookup
// (VerifySetCommand pins both call sites to one function, RVA_EXEC_DISPATCH).
// That lookup, on this exe, answers one of four ways:
//   nothing                                a quiet build, or SETNOPEC
//   "Executing set command <value>"        its own trace of a WORKING set —
//                                          SET always gets this with
//                                          bNotify=1 [V, a game log: the one
//                                          sfxweaponmod_shotgunstability row
//                                          among 241 attempts: 57 such lines,
//                                          184 "Unrecognized...", 57+184=241]
//   "Unrecognized class or object <C>"     the class is not loaded (yet, or
//                                          ever, under that name)
//   "Unrecognized property <P> on class <C>"  the class IS loaded; it has no
//                                          such property. No retry resolves
//                                          this [V, same log: "Unrecognized
//                                          property adhesionrot on class
//                                          sfxweapon(_sniperrifle_base)", 20
//                                          occurrences over the run — a
//                                          genuinely wrong property name,
//                                          unrelated to load timing]
//
// Before this fix, op 57 treated ANY non-empty text as a failure (so a
// WORKING set was logged and reported exactly like a broken one — harmless
// on its own, since the UnrealScript side never read AsiSet's result), and
// op 58/59 passed EITHER kind of message through as if it were the
// property's value: always non-empty, so SFXGRIMP's "is this class loaded
// yet" check (AsiGet(...) == "") never once came back true in a build 6
// run. nPending stayed 0 for the whole session (that run's log: "0 not
// loaded", every single time), the 2-second retry was never armed ("0
// applied late" — grep -c across the whole run), and `set` was attempted,
// and genuinely failed, for every weapon whose package had not loaded yet,
// including the Crusader in the match itself (13:02:01).
#ifndef LEMP_BALANCE_CLASSIFY_H
#define LEMP_BALANCE_CLASSIFY_H

#include <string>

namespace balance {

enum class Outcome {
    Nothing,          // the engine printed nothing
    Success,          // a real value (GET) or the "Executing..." trace (SET)
    ClassNotFound,    // "Unrecognized class or object ..." — may load later
    PropertyNotFound, // "Unrecognized property ... on class ..." — never will
    Other,            // some other message: logged, treated as a failure
};

inline bool StartsWithLiteral(const std::u16string& s, const char16_t* lit) {
    size_t n = 0;
    while (lit[n]) ++n;
    return s.size() >= n && s.compare(0, n, lit) == 0;
}

inline Outcome Classify(const std::u16string& text) {
    if (text.empty()) return Outcome::Nothing;
    if (StartsWithLiteral(text, u"Executing set command")) return Outcome::Success;
    if (StartsWithLiteral(text, u"Unrecognized class or object")) return Outcome::ClassNotFound;
    if (StartsWithLiteral(text, u"Unrecognized property")) return Outcome::PropertyNotFound;
    return Outcome::Other;
}

// GET's own text, which is not SET's. UE3's GET prints the property's
// exported value on success and, on failure, "Unrecognized class <C>" or
// "Unrecognized property <P>" -- NOT SET's "Unrecognized class or object".
// Classify() above was written from SET's text alone and was used for GET
// too, which got both cases wrong: every real value (no known prefix) fell to
// Other, and so did every not-loaded class, so GET never once succeeded and
// nothing a GET guarded was ever applied. Here anything that is neither
// failure form is the value. Empty stays Nothing: GET prints an empty line
// for a property whose exported value is empty, which cannot be told from no
// output at all.
inline Outcome ClassifyGet(const std::u16string& text) {
    if (text.empty()) return Outcome::Nothing;
    if (StartsWithLiteral(text, u"Unrecognized class ")) return Outcome::ClassNotFound;
    if (StartsWithLiteral(text, u"Unrecognized property ")) return Outcome::PropertyNotFound;
    return Outcome::Success;
}

} // namespace balance

#endif
