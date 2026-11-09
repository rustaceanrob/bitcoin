// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONINTERFACE_EVENTS_H
#define BITCOIN_VALIDATIONINTERFACE_EVENTS_H

//! Helpers for defining ValidationSignals members, see validationinterface.cpp.

#include <logging/categories.h>
#include <tinyformat.h>
#include <util/log.h>

#include <string>
#include <type_traits>
#include <utility>

// Use a macro instead of a function for conditional logging to prevent
// evaluating arguments when logging is not enabled.
#define ENQUEUE_AND_LOG_EVENT(event, log_msg)                                                                    \
    do {                                                                                                         \
        static_assert(std::is_rvalue_reference_v<decltype((event))>,                                             \
                      "event must be passed as an rvalue");                                                      \
        static_assert(std::is_rvalue_reference_v<decltype((log_msg))>,                                           \
                      "log_msg must be passed as an rvalue");                                                    \
        auto enqueue_log_msg = (log_msg);                                                                        \
        LOG_EVENT("Enqueuing %s", enqueue_log_msg);                                                              \
        Enqueue([local_log_msg = std::move(enqueue_log_msg), local_event = (event)] {                           \
            LOG_EVENT("%s", local_log_msg);                                                                      \
            local_event();                                                                                       \
        });                                                                                                      \
    } while (0)

#define LOG_MSG(fmt, ...) \
    (util::log::ShouldDebugLog(BCLog::VALIDATION) ? tfm::format((fmt), __VA_ARGS__) : std::string{})

#define LOG_EVENT(fmt, ...) \
    LogDebug(BCLog::VALIDATION, fmt, __VA_ARGS__)

#endif // BITCOIN_VALIDATIONINTERFACE_EVENTS_H
