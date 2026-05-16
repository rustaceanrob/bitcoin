// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/license_info.h>
#include <common/system.h>
#include <compat/compat.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/exception.h>
#include <util/translation.h>

#include <memory>
#include <string>

const TranslateFn G_TRANSLATION_FUN{nullptr};

static const int CONTINUE_EXECUTION=-1;

static void SetupCliArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-conf=<file>", strprintf("Specify configuration file. Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    SetupChainParamsBaseOptions(argsman);
    argsman.AddArg("-ipcconnect=<address>", "Connect to bitcoin-node through IPC socket. Valid <address> values are 'auto' to connect to default socket path at <datadir>/node.sock, 'unix' to connect to the default socket and fail if it isn't available, or 'unix:<socket path>' to connect to a socket at a nonstandard path. Default value: auto", ArgsManager::ALLOW_ANY, OptionsCategory::IPC);
}

struct CConnectionFailed : std::runtime_error {
    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}
};

//
// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
//
static int AppInitRPC(int argc, char* argv[])
{
    SetupCliArgs(gArgs);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }
    const bool help_requested = HelpRequested(gArgs)
        || (argc >= 2 && std::string(argv[1]) == "help");
    if (help_requested || gArgs.GetBoolArg("-version", false)) {
        std::string strUsage = CLIENT_NAME " version " + FormatFullVersion() + "\n";

        if (gArgs.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "Usage: bitcoin-cli [options]\n"
                "\n"
                "Sends a stop request to bitcoin-node via IPC.\n"
                "\n";
            strUsage += "\n" + gArgs.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);
        return EXIT_SUCCESS;
    }
    if (!CheckDataDirOption(gArgs)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", gArgs.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    if (!gArgs.ReadConfigFiles(error, true)) {
        tfm::format(std::cerr, "Error reading configuration file: %s\n", error);
        return EXIT_FAILURE;
    }
    // Check for chain settings (BaseParams() calls are only valid after this clause)
    try {
        SelectBaseParams(gArgs.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }
    return CONTINUE_EXECUTION;
}



static void StopNode()
{
    std::unique_ptr<interfaces::Init> local_init{interfaces::MakeBasicInit("bitcoin-cli")};
    if (!local_init || !local_init->ipc()) {
        throw std::runtime_error("bitcoin-cli was not built with IPC support");
    }

    auto ipcconnect{gArgs.GetArg("-ipcconnect", "auto")};
    std::unique_ptr<interfaces::Init> node_init;
    try {
        node_init = local_init->ipc()->connectAddress(ipcconnect);
    } catch (const std::exception& e) {
        throw std::runtime_error{strprintf("%s\n\n"
            "Probably bitcoind is not running. Can be started with:\n\n"
            "    bitcoind -chain=%s", e.what(), gArgs.GetChainTypeString())};
    }
    if (!node_init) {
        throw std::runtime_error{strprintf(
            "Could not connect to bitcoind IPC socket.\n\n"
            "Probably bitcoind is not running. Can be started with:\n\n"
            "    bitcoind -chain=%s", gArgs.GetChainTypeString())};
    }

    node_init->stop();
}


static int CommandLineRPC(int argc, char *argv[])
{
    std::string strPrint;
    int nRet = 0;
    try {
        StopNode();
        strPrint = "Bitcoin Core stopping";
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "CommandLineRPC()");
        throw;
    }

    if (!strPrint.empty()) {
        tfm::format(nRet == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }
    return nRet;
}

MAIN_FUNCTION
{
    SetupEnvironment();
    if (!SetupNetworking()) {
        tfm::format(std::cerr, "Error: Initializing networking failed\n");
        return EXIT_FAILURE;
    }

    try {
        int ret = AppInitRPC(argc, argv);
        if (ret != CONTINUE_EXECUTION)
            return ret;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitRPC()");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    try {
        ret = CommandLineRPC(argc, argv);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRPC()");
    } catch (...) {
        PrintExceptionContinue(nullptr, "CommandLineRPC()");
    }
    return ret;
}
