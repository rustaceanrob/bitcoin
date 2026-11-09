# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GNUInstallDirs)

# The mempool library carries its own copy of the consensus code it needs, so
# it can be used without libbitcoinkernel. It performs no I/O: the UTXO set is
# read and pool events are delivered through callbacks.
add_library(bitcoinmempool
  bitcoinmempool.cpp
  ../arith_uint256.cpp
  ../blockencodings.cpp
  ../chain.cpp
  ../coins.cpp
  ../consensus/merkle.cpp
  ../consensus/tx_check.cpp
  ../consensus/tx_verify.cpp
  ../hash.cpp
  ../kernel/chainparams.cpp
  ../kernel/context.cpp
  ../kernel/cs_main.cpp
  ../kernel/disconnected_transactions.cpp
  ../kernel/mempool_removal_reason.cpp
  ../mempool_accept.cpp
  ../policy/ephemeral_policy.cpp
  ../policy/feerate.cpp
  ../policy/packages.cpp
  ../policy/policy.cpp
  ../policy/rbf.cpp
  ../policy/settings.cpp
  ../policy/truc_policy.cpp
  ../primitives/block.cpp
  ../primitives/transaction.cpp
  ../pubkey.cpp
  ../random.cpp
  ../script/interpreter.cpp
  ../script/script.cpp
  ../script/script_error.cpp
  ../script/sigcache.cpp
  ../script/solver.cpp
  ../sync.cpp
  ../txgraph.cpp
  ../txmempool.cpp
  ../uint256.cpp
  ../util/chaintype.cpp
  ../util/check.cpp
  ../util/feefrac.cpp
  ../util/hasher.cpp
  ../util/moneystr.cpp
  ../util/rbf.cpp
  ../util/threadnames.cpp
  ../util/time.cpp
  ../validation_common.cpp
  ../validationinterface.cpp
  ../validationinterface_mempool.cpp
  $<TARGET_OBJECTS:bitcoin_clientversion>
  $<TARGET_OBJECTS:bitcoin_crypto>
)

target_link_libraries(bitcoinmempool
  PRIVATE
    core_interface
    secp256k1_objs
    $<$<PLATFORM_ID:Windows>:bcrypt>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    Boost::headers
)

get_target_property(bitcoinmempool_type bitcoinmempool TYPE)
if(bitcoinmempool_type STREQUAL "STATIC_LIBRARY")
  target_compile_definitions(bitcoinmempool PUBLIC BITCOINMEMPOOL_STATIC)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_options(bitcoinmempool PRIVATE "LINKER:--no-undefined")
endif()

add_custom_target(libbitcoinmempool)
add_dependencies(libbitcoinmempool bitcoinmempool)

install(TARGETS bitcoinmempool
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT libbitcoinmempool
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libbitcoinmempool
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libbitcoinmempool
)
install(FILES bitcoinmempool.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT libbitcoinmempool)
