#include "crash_reporter.h"

// The POSIX crash reporter: a handler for the fatal signals, on its own stack,
// writes <crash_root>/<session>-<signal>.txt with the signal, the faulting
// address, the program counter (with its library and offset) and a backtrace,
// then forwards to the dump writer it displaced (Android's debuggerd, so the
// system still writes its tombstone) or lets the default action end the process
// (and leave a core dump where the system keeps them). Only async-signal-safe
// calls run in the handler, except dladdr() and backtrace(), which glibc,
// bionic and macOS support there once backtrace() has been called before the
// fault.

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(__GLIBC__) || defined(__APPLE__) || \
    (defined(__ANDROID__) && __ANDROID_API__ >= 33)
#include <execinfo.h>
#define PINYON_SHIFT_HAVE_BACKTRACE 1
#endif
#include <dlfcn.h>

#include <rex/logging.h>

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace pinyon_shift::diagnostics::crash {
namespace {

constexpr int kSignals[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT};
constexpr size_t kSignalCount = sizeof(kSignals) / sizeof(kSignals[0]);
// "<crash_root>/<session>-" prepared at install; the handler appends the
// signal name, so it never allocates.
std::array<char, 4096> g_report_prefix{};
size_t g_report_prefix_length = 0;
std::atomic_flag g_reported = ATOMIC_FLAG_INIT;
std::array<std::byte, 64 * 1024> g_signal_stack{};
// The action this reporter displaced, per signal, forwarded to after the
// report is written (Android's debuggerd, which dumps a tombstone).
std::array<struct sigaction, kSignalCount> g_displaced{};
std::array<bool, kSignalCount> g_displaced_valid{};

const char* SignalName(int signal) {
  switch (signal) {
    case SIGSEGV:
      return "sigsegv";
    case SIGBUS:
      return "sigbus";
    case SIGILL:
      return "sigill";
    case SIGFPE:
      return "sigfpe";
    case SIGABRT:
      return "sigabrt";
    default:
      return "signal";
  }
}

void Write(int file, const char* text) { (void)!write(file, text, std::strlen(text)); }

void WriteHex(int file, const char* label, uint64_t value) {
  char buffer[40];
  size_t length = 0;
  for (const char* c = label; *c && length < 16; ++c) buffer[length++] = *c;
  buffer[length++] = '0';
  buffer[length++] = 'x';
  for (int shift = 60; shift >= 0; shift -= 4) {
    buffer[length++] = "0123456789ABCDEF"[(value >> shift) & 0xF];
  }
  buffer[length++] = '\n';
  (void)!write(file, buffer, length);
}

uint64_t ProgramCounter(const void* context) {
  const auto* user = static_cast<const ucontext_t*>(context);
  if (!user) return 0;
#if defined(__APPLE__) && defined(__x86_64__)
  return user->uc_mcontext->__ss.__rip;
#elif defined(__APPLE__) && defined(__aarch64__)
  return user->uc_mcontext->__ss.__pc;
#elif defined(__linux__) && defined(__x86_64__)
  return uint64_t(user->uc_mcontext.gregs[REG_RIP]);
#elif defined(__linux__) && defined(__aarch64__)
  return user->uc_mcontext.pc;
#else
  return 0;
#endif
}

void Handler(int signal, siginfo_t* info, void* context) {
  if (!g_reported.test_and_set()) {
#if defined(__ANDROID__)
    // logcat's crash buffer is the only trace when the report file cannot be
    // written; liblog's write is a socket send, as safe here as the file write.
    __android_log_print(ANDROID_LOG_FATAL, "pinyon_shift", "fatal signal %d (%s) address=%p pc=%p",
                        signal, SignalName(signal), info ? info->si_addr : nullptr,
                        reinterpret_cast<void*>(uintptr_t(ProgramCounter(context))));
#endif
    char path[4200];
    std::memcpy(path, g_report_prefix.data(), g_report_prefix_length);
    size_t length = g_report_prefix_length;
    for (const char* c = SignalName(signal); *c; ++c) path[length++] = *c;
    for (const char* c = ".txt"; *c; ++c) path[length++] = *c;
    path[length] = '\0';
    const int file = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (file >= 0) {
      Write(file, "Pinyon Shift fatal signal\nsignal=");
      Write(file, SignalName(signal));
      Write(file, "\n");
      WriteHex(file, "fault_address=", uint64_t(uintptr_t(info ? info->si_addr : nullptr)));
      const uint64_t pc = ProgramCounter(context);
      WriteHex(file, "pc=", pc);
      // The library holding the PC and the offset into it, which a
      // symbolizer needs where the load address differs per run.
      Dl_info module{};
      if (pc && dladdr(reinterpret_cast<void*>(uintptr_t(pc)), &module) && module.dli_fname) {
        Write(file, "pc_module=");
        Write(file, module.dli_fname);
        Write(file, "\n");
        WriteHex(file, "pc_offset=", pc - uint64_t(uintptr_t(module.dli_fbase)));
      }
#if defined(PINYON_SHIFT_HAVE_BACKTRACE)
      void* frames[64];
      const int count = backtrace(frames, 64);
      backtrace_symbols_fd(frames, count, file);
#endif
      close(file);
    }
  }
  // Forward to the dump writer displaced at install (Android's debuggerd), so
  // the system still writes its own tombstone for the crash.
  for (size_t index = 0; index < kSignalCount; ++index) {
    if (kSignals[index] != signal || !g_displaced_valid[index]) continue;
    const struct sigaction& displaced = g_displaced[index];
    if ((displaced.sa_flags & SA_SIGINFO) && displaced.sa_sigaction &&
        reinterpret_cast<void*>(displaced.sa_sigaction) != reinterpret_cast<void*>(Handler)) {
      displaced.sa_sigaction(signal, info, context);
      return;
    }
    if (displaced.sa_handler != SIG_DFL && displaced.sa_handler != SIG_IGN &&
        displaced.sa_handler && reinterpret_cast<void*>(displaced.sa_handler) !=
                                    reinterpret_cast<void*>(Handler)) {
      displaced.sa_handler(signal);
      return;
    }
    break;
  }
  // Nothing was displaced: the default action ends the process as the signal
  // would have.
  struct sigaction default_action {};
  default_action.sa_handler = SIG_DFL;
  sigemptyset(&default_action.sa_mask);
  sigaction(signal, &default_action, nullptr);
  raise(signal);
}

}  // namespace

void Install(const std::filesystem::path& crash_root, const std::string& session_id) {
  const std::string prefix = (crash_root / session_id).string() + "-";
  g_report_prefix_length = std::min(prefix.size(), g_report_prefix.size() - 1);
  std::memcpy(g_report_prefix.data(), prefix.data(), g_report_prefix_length);
#if defined(PINYON_SHIFT_HAVE_BACKTRACE)
  // The first backtrace() loads the unwinder; do it now, not in the handler.
  void* frame;
  backtrace(&frame, 1);
#endif
  stack_t stack{};
  stack.ss_sp = g_signal_stack.data();
  stack.ss_size = g_signal_stack.size();
  sigaltstack(&stack, nullptr);
  Refresh();
}

// The C library's own crash handler (bionic's debuggerd on Android) is the one
// action this reporter may displace: it only writes a dump, so forwarding to it
// after the report keeps that dump. Everything else stays in front — in
// particular the runtime's guest fault handler, which serves guest MMIO and
// write watches through SIGSEGV and must keep receiving those faults.
bool Displaceable(const struct sigaction& action) {
  void* entry = (action.sa_flags & SA_SIGINFO) ? reinterpret_cast<void*>(action.sa_sigaction)
                                               : reinterpret_cast<void*>(action.sa_handler);
  if (!entry || entry == reinterpret_cast<void*>(SIG_DFL) ||
      entry == reinterpret_cast<void*>(SIG_IGN)) {
    return true;
  }
  Dl_info info{};
  if (dladdr(entry, &info) && info.dli_fname) {
    // The runtime's guest fault handler serves guest MMIO and write watches
    // through SIGSEGV and must keep receiving those faults; the report is
    // written by this reporter before anything it displaces runs.
    return std::strstr(info.dli_fname, "rexruntime") == nullptr &&
           std::strstr(info.dli_fname, "rexgpu") == nullptr;
  }
  return true;
}

void Refresh() {
  struct sigaction action {};
  action.sa_sigaction = Handler;
  action.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&action.sa_mask);
  for (size_t index = 0; index < kSignalCount; ++index) {
    const int signal = kSignals[index];
    struct sigaction current {};
    if (sigaction(signal, nullptr, &current) != 0) {
      continue;
    }
    if (reinterpret_cast<void*>(current.sa_sigaction) == reinterpret_cast<void*>(Handler)) {
      continue;  // Already the reporter; the displaced action is kept.
    }
    if (!Displaceable(current)) {
      REXLOG_INFO("Crash reporter: {} keeps its handler (runtime guest faults)", SignalName(signal));
      continue;  // A handler installed after this one (the runtime's) is in front.
    }
    Dl_info module{};
    const void* entry = (current.sa_flags & SA_SIGINFO)
                            ? reinterpret_cast<const void*>(current.sa_sigaction)
                            : reinterpret_cast<const void*>(current.sa_handler);
    const char* name = (dladdr(entry, &module) && module.dli_fname) ? module.dli_fname : "no module";
    if (sigaction(signal, &action, &g_displaced[index]) == 0) {
      g_displaced_valid[index] = true;
      REXLOG_INFO("Crash reporter: {} handler installed over {}", SignalName(signal), name);
    } else {
      REXLOG_ERROR("Crash reporter: cannot install the {} handler", SignalName(signal));
    }
  }
}

void RaiseAccessViolation() { raise(SIGSEGV); }

void ExecuteNull() {
  volatile uintptr_t null_target = 0;
  reinterpret_cast<void (*)()>(null_target)();
}

}  // namespace pinyon_shift::diagnostics::crash
