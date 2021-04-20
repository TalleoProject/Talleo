/*
Copyright (C) 2018, The TurtleCoin developers
Copyright (C) 2018, The PinkstarcoinV2 developers
Copyright (C) 2018, The Bittorium developers
Copyright (C) 2019-2021, The Talleo developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "ParseArguments.h"
#include "Tools.h"

#include "CryptoNoteConfig.h"
#include "Logging/ILogger.h"

/* Thanks to https://stackoverflow.com/users/85381/iain for this small command
   line parsing snippet! https://stackoverflow.com/a/868894/8737306 */

char* getCmdOption(char ** begin, char ** end, const std::string & option)
{
    char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}

bool isNumeric(char *str)
{
    if (str == NULL || str[0] == 0)
    {
        return false;
    }
    for (size_t i = 0; i < strlen(str); i++)
    {
        if (!isdigit(static_cast<unsigned char>(str[i])))
        {
            return false;
        }
    }
    return true;
}

Config parseArguments(int argc, char **argv)
{
    Config config;

    config.exit = false;
    config.walletGiven = false;
    config.passGiven = false;

    config.host = "127.0.0.1";
    config.port = CryptoNote::RPC_DEFAULT_PORT;

    config.walletFile = "";
    config.walletPass = "";

    config.backgroundOptimize = true;
    config.optimizeThreshold = 0;

    config.logFile = "simplewallet.log";
    config.logLevel = Logging::INFO;

    if (cmdOptionExists(argv, argv+argc, "-h")
     || cmdOptionExists(argv, argv+argc, "--help"))
    {
        helpMessage();
        config.exit = true;
        return config;
    }

    if (cmdOptionExists(argv, argv+argc, "-v")
     || cmdOptionExists(argv, argv+argc, "--version"))
    {
        versionMessage();
        config.exit = true;
        return config;
    }

    if (cmdOptionExists(argv, argv+argc, "--wallet-file"))
    {
        char *wallet = getCmdOption(argv, argv+argc, "--wallet-file");

        if (!wallet)
        {
            std::cout << "--wallet-file was specified, but no wallet file was given!" << std::endl;

            helpMessage();
            config.exit = true;
            return config;
        }

        config.walletFile = std::string(wallet);
        config.walletGiven = true;
    }

    if (cmdOptionExists(argv, argv+argc, "--password"))
    {
        char *password = getCmdOption(argv, argv+argc, "--password");

        if (!password)
        {
            std::cout << "--password was specified, but no password was given!" << std::endl;

            helpMessage();
            config.exit = true;
            return config;
        }

        config.walletPass = std::string(password);
        config.passGiven = true;
    }

    if (cmdOptionExists(argv, argv+argc, "--remote-daemon"))
    {
        char *url = getCmdOption(argv, argv + argc, "--remote-daemon");

        /* No url following --remote-daemon */
        if (!url)
        {
            std::cout << "--remote-daemon was specified, but no daemon was given!" << std::endl;

            helpMessage();

            config.exit = true;
        }
        else
        {
            std::string urlString(url);

            /* Get the index of the ":" */
            size_t splitter = urlString.find_first_of(":");

            /* No ":" present */
            if (splitter == std::string::npos)
            {
                config.host = urlString;
            }
            else
            {
                /* Host is everything before ":" */
                config.host = urlString.substr(0, splitter);

                /* Port is everything after ":" */
                std::string port = urlString.substr(splitter + 1, std::string::npos);

                try
                {
                    config.port = std::stoi(port);
                }
                catch (const std::invalid_argument&)
                {
                    std::cout << "Failed to parse daemon port!" << std::endl;
                    config.exit = true;
                }
            }
        }
    }

    if (cmdOptionExists(argv, argv+argc, "--disable-background-optimize"))
    {
        config.backgroundOptimize = false;
    }

    if (cmdOptionExists(argv, argv+argc, "--optimize-threshold"))
    {
        char *optimizeThreshold = getCmdOption(argv, argv + argc, "--optimize-threshold");

        /* No threshold after --optimize-threshold */
        if (!optimizeThreshold)
        {
            std::cout << "--optimize-threshold was specified, but no threshold was given!" << std::endl;

            helpMessage();
            config.exit = true;
            return config;
        }

        uint64_t threshold;

        if (!parseAmount(optimizeThreshold, threshold) || ((threshold != 0) && (threshold < (CryptoNote::parameters::DEFAULT_DUST_THRESHOLD * CryptoNote::parameters::FUSION_TX_MIN_INPUT_COUNT))))
        {
            std::cout << "Invalid optimization threshold was given!" << std::endl;

            helpMessage();
            config.exit = true;
            return config;
        }

        config.optimizeThreshold = threshold;
    }

    if (cmdOptionExists(argv, argv+argc, "--log-file"))
    {
        char *logFile = getCmdOption(argv, argv + argc, "--log-file");

        /* No log filename after --log-file */
        if (!logFile)
        {
            std::cout << "--log-file was specified, but no filename was given!" << std::endl;

            helpMessage();
            config.exit = true;
            return config;
        }

        config.logFile = std::string(logFile);
    }

    if (cmdOptionExists(argv, argv+argc, "--log-level"))
    {
        char *logLevel = getCmdOption(argv, argv + argc, "--log-level");

        if (!logLevel)
        {
            std::cout << "--log-level was specified, but no level was given!" << std::endl;

            helpMessage();
            config.exit = true;
            return config;
        }

        int level = atoi(logLevel);

        if (!isNumeric(logLevel) || logLevel[1] != 0 || level < Logging::FATAL || level > Logging::TRACE) {
            std::cout << "Invalid logging level was given, it should be a number between " << std::to_string(Logging::FATAL) << " and " << std::to_string(Logging::TRACE) << "!" << std::endl;

            helpMessage();
            config.exit = true;
            return config;
        }

        config.logLevel = level;
    }

    return config;
}

void versionMessage() {
    std::cout << "Talleo v" << PROJECT_VERSION << " SimpleWallet" << std::endl;
}

void helpMessage()
{
    versionMessage();

    std::cout << std::endl
              << "simplewallet [--version] [--help] [--remote-daemon <url>] [--wallet-file <file>] [--password <pass>] [--disable-background-optimize] [--optimize-threshold <threshold>] [--log-file <file>] [--log-level <level>]" << std::endl
              << std::endl
              << "Commands:" << std::endl
              << "  -h, " << std::left << std::setw(36) << "--help" << "Display this help message and exit" << std::endl
              << "  -v, " << std::left << std::setw(36) << "--version" << "Display the version information and exit" << std::endl
              << "      " << std::left << std::setw(36) << "--remote-daemon <url>" << "Connect to the remote daemon at <url>" << std::endl
              << "      " << std::left << std::setw(36) << "--wallet-file <file>" << "Open the wallet <file>" << std::endl
              << "      " << std::left << std::setw(36) << "--password <pass>" << "Use the password <pass> to open the wallet" << std::endl
              << "      " << std::left << std::setw(36) << "--disable-background-optimize" << "Disable background wallet optimization" << std::endl
              << "      " << std::left << std::setw(36) << "--optimize-threshold <threshold>" << "Set optimization threshold to <threshold>" << std::endl
              << "      " << std::left << std::setw(36) << "--log-file <file>" << "Write logs to file <file>" << std::endl
              << "      " << std::left << std::setw(36) << "--log-level <level>" << "Set logging level to <level>" << std::endl;
}
