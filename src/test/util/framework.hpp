/** Copyright (c) 2026-present The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <format>
#include <ostream>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace framework {

struct TestType {
    static inline constexpr const char* CHECK = "CHECK";
    static inline constexpr const char* REQUIRE = "REQUIRE";
    static inline constexpr const char* CHECK_THROWS = "CHECK_THROWS";
    static inline constexpr const char* CHECK_NOTHROW = "CHECK_NOTHROW";
    static inline constexpr const char* REQUIRE_NOTHROW = "REQUIRE_NOTHROW";
    static inline constexpr const char* CHECK_THROWS_AS = "CHECK_THROWS_AS";
    static inline constexpr const char* CHECK_EXCEPTION = "CHECK_EXCEPTION";
    static inline constexpr const char* CHECK_EQUAL_RANGES = "CHECK_EQUAL_RANGES";
};

struct TestCase {
    const char* suite;
    const char* name;
    void (*fn)();
};

/** Construct-on-first-use list of test cases. Prevents use of a global variable before initialization. */
inline std::vector<TestCase>& registry()
{
    static std::vector<TestCase> tests;
    return tests;
}

/** Construct-on-first-use suite name. */
inline const char*& current_test_suite()
{
    static const char* s = "";
    return s;
}

/** Convenience struct for adding functions to the registry. */
struct Registrar {
    Registrar(const char* name, void (*fn)())
    {
        registry().emplace_back(TestCase{current_test_suite(), name, fn});
    }
};

/** Name of the test currently running, in `suite::case` form. */
inline std::string& current_test_full_name()
{
    static std::string s;
    return s;
}

/** Single test metadata */
struct TestStats {
    int checks = 0;
    int failed_checks = 0;
};

inline TestStats& current_stats()
{
    static TestStats stats;
    return stats;
}

struct RunSummary {
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    int total_checks = 0;
};

enum class LogLevel {
    None = 0,
    /** Print `FAIL` cases. */
    Error = 1,
    /** Print `OK` and `FAIL` cases. */
    Info = 2,
    /** Show all checks. */
    All = 3
};

inline LogLevel& current_log_level()
{
    static LogLevel level = LogLevel::Error;
    return level;
}

template <typename... Args>
inline void log(LogLevel level, const char* fmt, Args&&... args)
{
    if (current_log_level() >= level) {
        std::printf(fmt, std::forward<Args>(args)...);
    }
}

/** Types that implement the `<<` operator. Pointers are excluded: operator<< for
 * char-like pointers calls strlen on the pointee, which is unsafe for raw memory. */
template <typename T>
concept Streamable = !std::is_pointer_v<T> && requires(std::ostream& os, const T& value) { os << value; };

/** `std::formattable` is C++23; this codebase is C++20. The primary
 * `std::formatter<T>` template has `= delete` constructors for unformattable
 * types, so default-constructibility is a SFINAE-safe proxy that works in C++20. */
template <typename T>
concept Formattable = std::is_default_constructible_v<std::formatter<T, char>>;

template <typename T>
std::string stringify(const T& value)
{
    if constexpr (Streamable<T>) {
        std::ostringstream os;
        os << value;
        return os.str();
    } else if constexpr (Formattable<T>) {
        return std::format("{}", value);
    } else {
        return "<unknown type>";
    }
}

inline std::string stringify(bool v) { return v ? "true" : "false"; }
inline std::string stringify(std::nullptr_t) { return "nullptr"; }
inline std::string stringify(const char* s)
{
    return s ? std::string("\"") + s + "\"" : std::string("nullptr");
}

struct Result {
    std::string expression;
    bool ok;
};

/** A captured expression is used to stringify the result before evaluation.
 * When an expression evaluates to `false`, the string is reported to the user. */
template <typename T>
struct CapturedExpression {
    const T& lhs;

    /** No right-hand-side exists to evaluate. */
    operator Result() const
    {
        return {stringify(lhs), static_cast<bool>(lhs)};
    }

    template <typename U>
    auto operator&&(const U&) = delete;

    template <typename U>
    auto operator||(const U&) = delete;

#define DECOMPOSE_OP(op)                                                                                               \
    template <typename U>                                                                                              \
    Result operator op(const U& rhs) const                                                                             \
    {                                                                                                                  \
        _Pragma("GCC diagnostic push")                                                                                 \
            _Pragma("GCC diagnostic ignored \"-Wsign-compare\"") bool btc_test_result = static_cast<bool>(lhs op rhs); \
        _Pragma("GCC diagnostic pop") return {stringify(lhs) + " " #op " " + stringify(rhs), btc_test_result};         \
    }

    DECOMPOSE_OP(==)
    DECOMPOSE_OP(!=)
    DECOMPOSE_OP(<)
    DECOMPOSE_OP(<=)
    DECOMPOSE_OP(>)
    DECOMPOSE_OP(>=)
#undef DECOMPOSE_OP
};

/** Decomposer overloads a high-precedence operator so the expression is captured before evalution. */
struct Decomposer {
    template <typename T>
    CapturedExpression<T> operator<=(const T& lhs) const
    {
        return {lhs};
    }
};


inline std::optional<LogLevel> to_log_level(std::string_view s)
{
    static const std::unordered_map<std::string_view, LogLevel> levels{
        {"none", LogLevel::None},
        {"error", LogLevel::Error},
        {"info", LogLevel::Info},
        {"all", LogLevel::All},
    };
    if (auto it = levels.find(s); it != levels.end())
        return it->second;
    return std::nullopt;
}


inline void record_check(const Result& result, const char* kind, const char* expr,
                         const char* file, int line, const std::string& message = {})
{
    auto& stats = current_stats();
    ++stats.checks;
    if (!result.ok) {
        ++stats.failed_checks;
        log(LogLevel::Error, "[FAIL]: %s:%d: %s(%s)\n", file, line, kind, expr);
        log(LogLevel::Error, "%s\n", result.expression.c_str());
        log(LogLevel::Error, "%s\n", message.c_str());
        return;
    }
    log(LogLevel::All, "[PASS]: %s:%d: %s(%s)\n", file, line, kind, expr);
}

template <std::ranges::range R1, std::ranges::range R2>
    requires std::same_as<std::ranges::range_value_t<R1>, std::ranges::range_value_t<R2>>
Result check_equal_ranges(const R1& r1, const R2& r2)
{
    if (std::ranges::equal(r1, r2)) return {"", true};

    using E = std::ranges::range_value_t<R1>;
    /** Byte-like types are printed as hex; everything else falls back to stringify. */
    auto fmt = [](const E& v) -> std::string {
        if constexpr (std::same_as<E, std::byte>) {
            return std::format("0x{:02x}", std::to_integer<unsigned>(v));
        } else if constexpr (std::same_as<E, unsigned char> || std::same_as<E, signed char>) {
            return std::format("0x{:02x}", static_cast<unsigned>(v) & 0xffU);
        } else {
            return stringify(v);
        }
    };

    std::size_t idx = 0;
    auto it1 = std::ranges::begin(r1);
    auto it2 = std::ranges::begin(r2);
    const auto end1 = std::ranges::end(r1);
    const auto end2 = std::ranges::end(r2);

    while (it1 != end1 && it2 != end2) {
        if (!(*it1 == *it2)) {
            return {"[index " + stringify(idx) + "]: " + fmt(*it1) + " != " + fmt(*it2), false};
        }
        ++it1;
        ++it2;
        ++idx;
    }
    if (it1 != end1 || it2 != end2) {
        const auto sz1 = idx + static_cast<std::size_t>(std::ranges::distance(it1, end1));
        const auto sz2 = idx + static_cast<std::size_t>(std::ranges::distance(it2, end2));
        return {"size mismatch: " + stringify(sz1) + " != " + stringify(sz2), false};
    }
    return {"", true};
}

/** Thrown by REQUIRE on failure to abort the current test. Not treated as a
 * test exception by run() — failure is already counted via record_check. */
struct RequireFailed {
};

inline std::string test_name(const TestCase& test_case)
{
    if (test_case.suite && test_case.suite[0] != '\0') {
        return std::string{test_case.suite} + "::" + test_case.name;
    }
    return test_case.name;
}

inline bool matches_filter(const TestCase& tc, const std::string_view& filter)
{
    if (filter.empty()) return true;
    if (filter.find("::") != std::string::npos) {
        return test_name(tc) == filter;
    }
    return (tc.suite && filter == tc.suite) || filter == tc.name;
}

inline void list_tests(const std::string_view& filter = {})
{
    for (const auto& test_case : registry()) {
        if (matches_filter(test_case, filter)) {
            std::printf("%s\n", test_name(test_case).c_str());
        }
    }
}

inline void print_usage(const std::string& prog)
{
    std::printf("Usage: %s [--run_test=|-t=<suite|suite::case>] [--log_level=|-l=<none|error|info|all>] [--list] [-h|--help] [-- USER_ARGS...]\n",
                prog.c_str());
}

inline std::vector<const char*>& user_args()
{
    static std::vector<const char*> ua;
    return ua;
}

enum ExitStatus {
    Success = 0,
    Failure = 1,
    UnknownArgs = 2,
};

struct RuntimeOptions {
    const char* prog;
    std::string_view filter;
    LogLevel log_level = LogLevel::Error;
    bool show_list;
    bool show_help;
    std::vector<const char*> passthrough;
};

inline ExitStatus parse_args(RuntimeOptions& opts, int argc, char** argv)
{
    opts.prog = argv[0];
    for (int i{1}; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--") {
            for (int j{i + 1}; j < argc; ++j) {
                opts.passthrough.emplace_back(argv[j]);
            }
            break;
        }
        if (arg == "--list") {
            opts.show_list = true;
            continue;
        }
        if (arg == "-h" || arg == "--help") {
            opts.show_help = true;
            return ExitStatus::Success;
        }
        if (arg.starts_with("--run_test=")) {
            arg.remove_prefix(std::string{"--run_test="}.size());
            opts.filter = arg;
            continue;
        }
        if (arg.starts_with("-t=")) {
            arg.remove_prefix(std::string{"-t="}.size());
            opts.filter = arg;
            continue;
        }
        if (arg.starts_with("--log_level=")) {
            arg.remove_prefix(std::string{"--log_level="}.size());
            auto log_level = to_log_level(arg);
            if (!log_level.has_value()) {
                opts.show_help = true;
                return ExitStatus::UnknownArgs;
            }
            opts.log_level = log_level.value();
            continue;
        }
        if (arg.starts_with("-l=")) {
            arg.remove_prefix(std::string{"-l="}.size());
            auto log_level = to_log_level(arg);
            if (!log_level.has_value()) {
                opts.show_help = true;
                return ExitStatus::UnknownArgs;
            }
            opts.log_level = log_level.value();
            continue;
        }
        std::printf("Unknown argument: %s\n", argv[i]);
        opts.show_help = true;
        return ExitStatus::UnknownArgs;
    }

    return ExitStatus::Success;
}

inline int run(int argc, char** argv)
{
    RuntimeOptions opts{};
    auto status = parse_args(opts, argc, argv);
    if (opts.show_help) {
        print_usage(opts.prog);
        return status;
    }
    if (opts.show_list) {
        list_tests(opts.filter);
        return status;
    }
    current_log_level() = opts.log_level;
    RunSummary summary{};
    int total_matching = 0;
    for (const auto& tc : registry()) {
        if (matches_filter(tc, opts.filter)) ++total_matching;
    }
    log(LogLevel::Error, "Running %d test case(s)...\n", total_matching);
    for (const auto& test_case : registry()) {
        if (!matches_filter(test_case, opts.filter)) {
            ++summary.skipped;
            continue;
        }
        current_stats() = {};
        current_test_full_name() = test_name(test_case);
        try {
            test_case.fn();
        } catch (const RequireFailed&) {
        } catch (const std::exception& e) {
            ++summary.failed;
            log(LogLevel::Error, "EXCEPTION in %s: %s\n", test_case.name, e.what());
            continue;
        } catch (...) {
            ++summary.failed;
            log(LogLevel::Error, "EXCEPTION in %s: %s\n", test_case.name, "unknown exception");
            continue;
        }
        const auto stats = current_stats();
        summary.total_checks += stats.checks;
        if (stats.failed_checks == 0) {
            ++summary.passed;
            log(LogLevel::Info, "[ OK ] %s (%d check(s))\n", test_case.name, stats.checks);
        } else {
            ++summary.failed;
            log(LogLevel::Error, "[FAIL] %s (%d/%d check(s) failed)\n",
                test_case.name, stats.failed_checks, stats.checks);
        }
    }
    const int total_tests = summary.passed + summary.failed + summary.skipped;
    std::printf("\n%d tests: %d passed, %d failed, %d skipped (%d check(s))\n",
                total_tests,
                summary.passed, summary.failed, summary.skipped,
                summary.total_checks);
    /** When a filter matches nothing, emit the marker line ctest looks for
     * via SKIP_REGULAR_EXPRESSION so the test is reported as SKIP, not PASS. */
    if (!opts.filter.empty() && summary.passed + summary.failed == 0) {
        std::printf("no test cases matching filter\n");
    }
    return summary.failed == 0 ? ExitStatus::Success : ExitStatus::Failure;
}


} // namespace framework

#if defined(__GNUC__) || defined(__clang__)
#define BITCOIN_TEST_DIAG_PUSH     \
    _Pragma("GCC diagnostic push") \
        _Pragma("GCC diagnostic ignored \"-Wparentheses\"")

#define BITCOIN_TEST_DIAG_POP \
    _Pragma("GCC diagnostic pop")
#else
#define BITCOIN_TEST_DIAG_PUSH
#define BITCOIN_TEST_DIAG_POP
#endif

/** Without this internal concatenation logic, the preprocessor would evaluate
 * `example_test_fn` + `__LINE__` as `example_test_fn__LINE__` rather than the
 * actual line number. */
#define BITCOIN_TEST_CAT_EVAL(a, b) a##b
#define BITCOIN_TEST_CAT(a, b) BITCOIN_TEST_CAT_EVAL(a, b)

/** For the case with no fixtures, we forward declare the function, store the function pointer
 * in the registry, and populate the function with the user's behavior.
 *
 * Example:
 * TEST_CASE(my_test):
 *
 * static void btc_test_fn34();
 * static Registrar btc_test_reg{my_test, &btc_test_fn34};
 * static void btc_test_fn34()
 *
 * ... user defines behavior */
#define TEST_CASE(name)                                                                                                     \
    static void BITCOIN_TEST_CAT(btc_test_fn, __LINE__)();                                                                  \
    static ::framework::Registrar BITCOIN_TEST_CAT(btc_test_reg, __LINE__){name, &BITCOIN_TEST_CAT(btc_test_fn, __LINE__)}; \
    static void BITCOIN_TEST_CAT(btc_test_fn, __LINE__)()


/** This is a similar mechanism as above, this time with a few extra steps.
 * The first anon namespace is so two translation units may declare a
 * `btc_test_fixture64` if they both happen to define tests at line 64.
 * The following namespace is to give a per-test isolation, so one translation
 * unit may have multiple fixture tests, each defining `Impl`. The `Impl`
 * inheritance from `Fixture` allows access to the members of `Fixture` from
 * the test case. Now the usual forward declaration of the test function
 * is implement with the `runner()` function. That runner is registered.
 * Finally the function body is defined by the user. */
#define FIXTURE_TEST_CASE(name, Fixture)                     \
    namespace {                                              \
    namespace BITCOIN_TEST_CAT(btc_test_fixture, __LINE__) { \
    struct Impl : Fixture {                                  \
        void btc_test_run();                                 \
    };                                                       \
    static void runner()                                     \
    {                                                        \
        Impl impl;                                           \
        impl.btc_test_run();                                 \
    }                                                        \
    static ::framework::Registrar reg{name, &runner};        \
    }                                                        \
    }                                                        \
    void BITCOIN_TEST_CAT(btc_test_fixture, __LINE__)::Impl::btc_test_run()

/** Define a variable who's side-effect is to change the test suite name.
 * The variable is unused and is only created to cause the side effect. */
#define TEST_SUITE_BEGIN(suite) \
    static const char* BITCOIN_TEST_CAT(btc_test_suite, __LINE__) = (::framework::current_test_suite() = (suite));

/** Reset the test suite using the same side effect. */
#define TEST_SUITE_END() \
    static const char* BITCOIN_TEST_CAT(btc_test_suite, __LINE__) = (::framework::current_test_suite() = "");

/** The `do... while` syntax is to allow users to write `CHECK(expr);`
 * in a `if` block, for instance. Otherwise, there would be a trailing
 * `;` after expansion. The compiler can optimize this behavior away.
 *
 * An optional stream-style failure message is supported as a second argument.
 *
 * Example: CHECK(a == b, "context: a=" << a << " b=" << b); */
#define CHECK(expr, ...)                                                                                  \
    do {                                                                                                  \
        BITCOIN_TEST_DIAG_PUSH                                                                            \
        ::framework::Result btc_test_res_ = ::framework::Decomposer{} <= expr;                            \
        BITCOIN_TEST_DIAG_POP                                                                             \
        std::ostringstream btc_test_os_;                                                                  \
        __VA_OPT__(if (!btc_test_res_.ok) btc_test_os_ << __VA_ARGS__;)                                   \
        ::framework::record_check(btc_test_res_, ::framework::TestType::CHECK, #expr, __FILE__, __LINE__, \
                                  btc_test_res_.ok ? std::string{} : btc_test_os_.str());                 \
    } while (false)

/** Like CHECK, but aborts the current test on failure by throwing.
 * Subsequent checks in the test are skipped.
 *
 * Accepts the same optional stream-style failure message as CHECK. */
#define REQUIRE(expr, ...)                                                                                  \
    do {                                                                                                    \
        BITCOIN_TEST_DIAG_PUSH                                                                              \
        ::framework::Result btc_test_res_ = ::framework::Decomposer{} <= expr;                              \
        BITCOIN_TEST_DIAG_POP                                                                               \
        std::ostringstream btc_test_os_;                                                                    \
        __VA_OPT__(if (!btc_test_res_.ok) btc_test_os_ << __VA_ARGS__;)                                     \
        ::framework::record_check(btc_test_res_, ::framework::TestType::REQUIRE, #expr, __FILE__, __LINE__, \
                                  btc_test_res_.ok ? std::string{} : btc_test_os_.str());                   \
        if (!btc_test_res_.ok) throw ::framework::RequireFailed{};                                          \
    } while (false)

/** Passes if `expr` throws any exception. */
#define CHECK_THROWS(expr)                                                                                     \
    do {                                                                                                       \
        bool btc_test_threw_ = false;                                                                          \
        try {                                                                                                  \
            expr;                                                                                              \
        } catch (...) {                                                                                        \
            btc_test_threw_ = true;                                                                            \
        }                                                                                                      \
        ::framework::Result btc_test_res_{btc_test_threw_ ? "" : "expression did not throw", btc_test_threw_}; \
        ::framework::record_check(btc_test_res_, ::framework::TestType::CHECK_THROWS,                          \
                                  #expr, __FILE__, __LINE__);                                                  \
    } while (false)

/** Passes if `expr` does NOT throw any exception. */
#define CHECK_NOTHROW(expr)                                                                               \
    do {                                                                                                  \
        bool btc_test_threw_ = false;                                                                     \
        try {                                                                                             \
            expr;                                                                                         \
        } catch (...) {                                                                                   \
            btc_test_threw_ = true;                                                                       \
        }                                                                                                 \
        ::framework::Result btc_test_res_{btc_test_threw_ ? "unexpectedly threw" : "", !btc_test_threw_}; \
        ::framework::record_check(btc_test_res_, ::framework::TestType::CHECK_NOTHROW,                    \
                                  #expr, __FILE__, __LINE__);                                             \
    } while (false)

/** Like CHECK_NOTHROW, but aborts the current test on failure. */
#define REQUIRE_NOTHROW(expr)                                                                             \
    do {                                                                                                  \
        bool btc_test_threw_ = false;                                                                     \
        try {                                                                                             \
            expr;                                                                                         \
        } catch (...) {                                                                                   \
            btc_test_threw_ = true;                                                                       \
        }                                                                                                 \
        ::framework::Result btc_test_res_{btc_test_threw_ ? "unexpectedly threw" : "", !btc_test_threw_}; \
        ::framework::record_check(btc_test_res_, ::framework::TestType::REQUIRE_NOTHROW,                  \
                                  #expr, __FILE__, __LINE__);                                             \
        if (!btc_test_res_.ok) throw ::framework::RequireFailed{};                                        \
    } while (false)

/** Passes only if `expr` throws an exception derived from `ExceptionType`. */
#define CHECK_THROWS_AS(expr, ExceptionType)                                                    \
    do {                                                                                        \
        ::framework::Result btc_test_res_{"expression did not throw", false};                   \
        try {                                                                                   \
            expr;                                                                               \
        } catch (ExceptionType const&) {                                                        \
            btc_test_res_ = {"threw expected exception type", true};                            \
        } catch (...) {                                                                         \
            btc_test_res_ = {"threw unexpected exception type", false};                         \
        }                                                                                       \
        ::framework::record_check(btc_test_res_, ::framework::TestType::CHECK_THROWS_AS,        \
                                  #expr, __FILE__, __LINE__);                                   \
    } while (false)

/** Passes only if `expr` throws an exception derived from `ExceptionType`
 * AND `Predicate(caught)` returns true. Useful for inspecting e.what() or
 * other fields of the caught exception.
 *
 * Example:
 *   CHECK_EXCEPTION(parse(input), ParseError,
 *                   [](const ParseError& e) { return e.line == 3; }); */
#define CHECK_EXCEPTION(expr, ExceptionType, Predicate)                           \
    do {                                                                          \
        ::framework::Result btc_test_res_{                                        \
            "expression did not throw expected type", false};                     \
        try {                                                                     \
            expr;                                                                 \
        } catch (ExceptionType const& e) {                                        \
            const bool btc_test_pred_ok_ = Predicate(e);                          \
            btc_test_res_ = {                                                     \
                btc_test_pred_ok_ ? "" : "threw expected type, predicate failed", \
                btc_test_pred_ok_};                                               \
        } catch (...) {                                                           \
            btc_test_res_ = {"threw unexpected exception type", false};           \
        }                                                                         \
        ::framework::record_check(                                                \
            btc_test_res_, ::framework::TestType::CHECK_EXCEPTION,                \
            #expr, __FILE__, __LINE__);                                           \
    } while (false)

/** Passes if two ranges contain equal elements. Accepts any two types that
 * satisfy std::ranges::range with comparable element types. */
#define CHECK_EQUAL_RANGES(a, b)                                                                          \
    do {                                                                                                  \
        ::framework::Result btc_test_res_ = ::framework::check_equal_ranges((a), (b));                    \
        ::framework::record_check(btc_test_res_, ::framework::TestType::CHECK_EQUAL_RANGES,               \
                                  #a " == " #b, __FILE__, __LINE__);                                      \
    } while (false)

/** Emits a diagnostic message when the log level is Info or higher.
 * Accepts stream-style expressions: TEST_MESSAGE("x=" << x); */
#define TEST_MESSAGE(msg)                                              \
    do {                                                               \
        std::ostringstream btc_test_os_;                               \
        btc_test_os_ << msg;                                           \
        ::framework::log(::framework::LogLevel::Info, "MESSAGE: %s\n", \
                         btc_test_os_.str().c_str());                  \
    } while (false)

/** Emits a warning message when `expr` is false. Does NOT fail the test —
 * use CHECK / REQUIRE for that. Accepts the same stream-style message as
 * TEST_MESSAGE: WARN_MESSAGE(have_data_file, "no test data, skipping"); */
#define WARN_MESSAGE(expr, msg)                                         \
    do {                                                                \
        if (!(expr)) {                                                  \
            std::ostringstream btc_test_os_;                            \
            btc_test_os_ << msg;                                        \
            ::framework::log(::framework::LogLevel::Info, "WARN: %s\n", \
                             btc_test_os_.str().c_str());               \
        }                                                               \
    } while (false)

#ifdef BITCOIN_TEST_MAIN
int main(int argc, char** argv)
{
    return ::framework::run(argc, argv);
}
#endif
