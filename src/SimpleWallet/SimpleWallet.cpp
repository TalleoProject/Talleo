/*
Copyright (C) 2018, The TurtleCoin developers
Copyright (C) 2018, The PinkstarcoinV2 developers
Copyright (C) 2018, The Bittorium developers
Copyright (c) 2018, The Karbo developers
Copyright (C) 2019-2024, The Talleo developers


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

#ifdef WIN32
#define NOMINMAX
#include <windows.h>
#endif

#include <SimpleWallet/SimpleWallet.h>
#include <SimpleWallet/SubWallet.h>
#include <cstring>
#include <limits>
#include <boost/algorithm/string.hpp>

#include "Common/JsonValue.h"
#include "Common/StringTools.h"
#include "Rpc/HttpClient.h"
#include "Cursor.h"

// Fee address is declared here so we can access it from other source files
std::string remote_fee_address;
// Current subwallet index
size_t subWallet = 0;
// Subwallet index that shouldn't exist and can be used as error response
const size_t invalidIndex = std::numeric_limits<size_t>::max();
// Background wallet optimization
bool backgroundOptimize = true;
uint64_t optimizeThreshold = 0;

int main(int argc, char **argv) {
    /* On ctrl+c the program seems to throw "simplewallet.exe has stopped
       working" when calling exit(0)... I'm not sure why, this is a bit of
       a hack, it disables that */
    #ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    std::string consoletitle = std::string(CryptoNote::CRYPTONOTE_NAME) + " SimpleWallet v" + std::string(PROJECT_VERSION_LONG);
    SetConsoleTitleA(consoletitle.c_str());
    #endif

    Config config = parseArguments(argc, argv);

    /* User requested --help or --version, or invalid arguments */
    if (config.exit) {
        return 0;
    }

    backgroundOptimize = config.backgroundOptimize;
    optimizeThreshold = config.optimizeThreshold;

    /* Only log to file so we don't have crap filling up the terminal */
    Logging::LoggerManager logManager;
    logManager.setMaxLevel(Logging::Level(config.logLevel));

    Logging::FileLogger fileLogger;
    fileLogger.init(config.logFile);
    logManager.addLogger(fileLogger);

    Logging::LoggerRef logger(logManager, "simplewallet");

    /* Currency contains our coin parameters, such as decimal places, supply */
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logManager).currency();

    System::Dispatcher localDispatcher;
    System::Dispatcher *dispatcher = &localDispatcher;

    remote_fee_address = getFeeAddress(localDispatcher, config.host, config.port, config.path, config.ssl);

    /* Our connection to Talleod */
    std::unique_ptr<CryptoNote::INode> node(new CryptoNote::NodeRpcProxy(config.host, config.port, config.path, config.ssl, logger.getLogger()));

    std::promise<std::error_code> errorPromise;
    std::future<std::error_code> error = errorPromise.get_future();
    auto callback = [&errorPromise](std::error_code e)
                    {errorPromise.set_value(e); };

    node->init(callback);

    std::future<void> initNode = std::async(std::launch::async, [&] {
        if (error.get()) {
            throw std::runtime_error("Failed to initialize node!");
        }
    });

    std::future_status status = initNode.wait_for(std::chrono::seconds(20));

    /* Connection to remote node took too long, let program continue regardless
       as they could perform functions like export_keys without being connected */
    if (status != std::future_status::ready) {
        if (config.host != "127.0.0.1") {
            std::cout << WarningMsg("Unable to connect to remote node, connection timed out.") << std::endl
                      << WarningMsg("Confirm the remote node is functioning, or try a different remote node.") << std::endl
                      << std::endl;
        } else {
            std::cout << WarningMsg("Unable to connect to node, connection timed out.") << std::endl
                      << std::endl;
        }
    }

    /* Create the wallet instance */
    CryptoNote::WalletGreen wallet(*dispatcher, currency, *node, logger.getLogger());

    /* Run the interactive wallet interface */
    run(*dispatcher, wallet, *node, config);
}

void run(System::Dispatcher& dispatcher, CryptoNote::WalletGreen &wallet, CryptoNote::INode &node, Config &config) {
    auto maybeWalletInfo = Nothing<std::shared_ptr<WalletInfo>>();
    Action action;
    std::string coinName(CryptoNote::CRYPTONOTE_NAME);

    do {
        std::cout << InformationMsg(coinName + " v" + std::string(PROJECT_VERSION) + " SimpleWallet") << std::endl;

        /* Open/import/generate the wallet */
        action = getAction(config);
        maybeWalletInfo = handleAction(wallet, action, config);

    /* Didn't manage to get the wallet info, returning to selection screen */
    } while (!maybeWalletInfo.isJust);

    auto walletInfo = maybeWalletInfo.x;

    bool alreadyShuttingDown = false;

    /* This will call shutdown when ctrl+c is hit. This is a lambda function,
       & means capture all variables by reference */
    Tools::SignalHandler::install([&] {
        /* If we're already shutting down let control flow continue as normal */
        if (shutdown(walletInfo->wallet, node, alreadyShuttingDown)) {
            exit(0);
        }
    });

    while (node.getLastKnownBlockHeight() == 0) {
        std::cout << WarningMsg("It looks like " + coinName +"d isn't open!") << std::endl << std::endl
                  << WarningMsg("Ensure " + coinName + "d is open and has finished initializing.") << std::endl
                  << WarningMsg("If it's still not working, try restarting " + coinName + "d. The daemon sometimes gets stuck.") << std::endl
                  << WarningMsg("Alternatively, perhaps " + coinName + "d can't communicate with any peers.") << std::endl
                  << std::endl
                  << WarningMsg("The wallet can't function until it can communicate with the network.") << std::endl
                  << std::endl;

        bool proceed = false;

        while (true) {
            std::cout << "[" << InformationMsg("T") << "]ry again, "
                      << "[" << InformationMsg("E") << "]xit, or "
                      << "[" << InformationMsg("C") << "]ontinue anyway?: ";

            std::string answer;
            std::getline(std::cin, answer);

            int c = std::tolower(answer[0]);

            /* Lets people spam enter in the transaction screen */
            if (c == 't' || c == '\0') {
                break;
            } else if (c == 'e' || c == std::ifstream::traits_type::eof()) {
                shutdown(walletInfo->wallet, node, alreadyShuttingDown);
                return;
            } else if (c == 'c') {
                proceed = true;
                break;
            } else {
                std::cout << WarningMsg("Bad input: ") << InformationMsg(answer) << WarningMsg(" - please enter either T, E, or C.") << std::endl;
            }
        }

        if (proceed) {
            break;
        }

        std::cout << std::endl;
    }

    /* Scan the chain for new transactions. In the case of an imported
       wallet, we need to scan the whole chain to find any transactions.
       If we opened the wallet however, we just need to scan from when we
       last had it open. If we are generating a wallet, there is no need
       to check for transactions as there is no way the wallet can have
       received any money yet. */
    if (action != Generate) {
        findNewTransactions(node, walletInfo);
    } else {
        std::cout << InformationMsg("Your wallet is syncing with the network in the background.") << std::endl
                  << InformationMsg("Until this is completed new transactions might not show up.") << std::endl
                  << InformationMsg("Use bc_height to check the progress.") << std::endl
                  << std::endl;
    }

    welcomeMsg();

    inputLoop(dispatcher, walletInfo, node);

    shutdown(walletInfo->wallet, node, alreadyShuttingDown);
}

Maybe<std::shared_ptr<WalletInfo>> handleAction(CryptoNote::WalletGreen &wallet, Action action, Config &config) {
    if (action == Generate) {
        return Just<std::shared_ptr<WalletInfo>>(generateWallet(wallet));
    } else if (action == Open) {
        return openWallet(wallet, config);
    } else if (action == Import) {
        return Just<std::shared_ptr<WalletInfo>>(importWallet(wallet));
    } else if (action == SeedImport) {
        return Just<std::shared_ptr<WalletInfo>>(mnemonicImportWallet(wallet));
    } else if (action == ViewWallet) {
        return Just<std::shared_ptr<WalletInfo>>(createViewWallet(wallet));
    } else {
        throw std::runtime_error("Unimplemented action!");
    }
}

std::shared_ptr<WalletInfo> createViewWallet(CryptoNote::WalletGreen &wallet) {
    std::string coinTicker(CryptoNote::CRYPTONOTE_TICKER);
    Crypto::SecretKey privateViewKey = getPrivateKey("Private View Key: ");

    CryptoNote::AccountPublicAddress publicKeys;
    uint64_t prefix;

    std::string address;

    while (true) {
        std::cout << "Public " << coinTicker << " address: ";

        std::getline(std::cin, address);
        boost::algorithm::trim(address);

        if (address.length() != 97) {
            std::cout << WarningMsg("Address is wrong length!") << std::endl
                      << "It should be 97 characters long, but it is " << address.length() << " characters long!" << std::endl;
        } else if (address.substr(0, 2) != "TA") {
            std::cout << WarningMsg("Invalid address! It should start with \"TA\"!") << std::endl;
        } else if (!CryptoNote::parseAccountAddressString(prefix, publicKeys, address)) {
            std::cout << WarningMsg("Failed to parse " + coinTicker + " address! Ensure you have entered it correctly.") << std::endl;
        } else {
            break;
        }
    }

    std::string walletFileName = getNewWalletFileName();
    std::string walletPass = getWalletPassword(true);

    wallet.createViewWallet(walletFileName, walletPass, address, privateViewKey);

    std::cout << std::endl
              << InformationMsg("Your view wallet ") << SuccessMsg(address) << InformationMsg(" has been successfully imported!") << std::endl
              << std::endl;

    viewWalletMsg();

    return std::make_shared<WalletInfo>(walletFileName, walletPass, address, true, wallet);
}

std::shared_ptr<WalletInfo> importWallet(CryptoNote::WalletGreen &wallet) {
    Crypto::SecretKey privateSpendKey = getPrivateKey("Private Spend Key: ");
    Crypto::SecretKey privateViewKey = getPrivateKey("Private View Key: ");
    return importFromKeys(wallet, privateSpendKey, privateViewKey);
}

std::shared_ptr<WalletInfo> mnemonicImportWallet(CryptoNote::WalletGreen &wallet) {
    std::string mnemonicPhrase;

    Crypto::SecretKey privateSpendKey;
    Crypto::SecretKey privateViewKey;

    do {
        std::cout << "Mnemonic Phrase (25 words): ";
        std::getline(std::cin, mnemonicPhrase);
        boost::algorithm::trim(mnemonicPhrase);
    } while (!crypto::ElectrumWords::is_valid_mnemonic(mnemonicPhrase, privateSpendKey));

    CryptoNote::AccountBase::generateViewFromSpend(privateSpendKey, privateViewKey);

    return importFromKeys(wallet, privateSpendKey, privateViewKey);
}

std::shared_ptr<WalletInfo> importFromKeys(CryptoNote::WalletGreen &wallet, Crypto::SecretKey privateSpendKey, Crypto::SecretKey privateViewKey) {
    std::string walletFileName = getNewWalletFileName();
    std::string walletPass = getWalletPassword(true);

    connectingMsg();

    wallet.initializeWithViewKey(walletFileName, walletPass, privateViewKey);

    std::string walletAddress = wallet.createAddress(privateSpendKey);

    std::cout << std::endl
              << InformationMsg("Your wallet ") << SuccessMsg(walletAddress) << InformationMsg(" has been successfully imported!") << std::endl
              << std::endl;

#ifdef _WIN32
    std::string consoletitle = std::string(CryptoNote::CRYPTONOTE_NAME) + " SimpleWallet v" + std::string(PROJECT_VERSION_LONG) + " - " + walletFileName;
    SetConsoleTitleA(consoletitle.c_str());
#endif

    return std::make_shared<WalletInfo>(walletFileName, walletPass, walletAddress, false, wallet);
}

std::shared_ptr<WalletInfo> generateWallet(CryptoNote::WalletGreen &wallet) {
    std::string walletFileName = getNewWalletFileName();
    std::string walletPass = getWalletPassword(true);


    CryptoNote::KeyPair spendKey;
    Crypto::SecretKey privateViewKey;

    Crypto::generate_keys(spendKey.publicKey, spendKey.secretKey);
    CryptoNote::AccountBase::generateViewFromSpend(spendKey.secretKey, privateViewKey);

    wallet.initializeWithViewKey(walletFileName, walletPass, privateViewKey);

    std::string walletAddress = wallet.createAddress(spendKey.secretKey);

    promptSaveKeys(wallet);

    std::cout << WarningMsg("If you lose these your wallet cannot be recreated!") << std::endl
              << std::endl;

#ifdef _WIN32
    std::string consoletitle = std::string(CryptoNote::CRYPTONOTE_NAME) + " SimpleWallet v" + std::string(PROJECT_VERSION_LONG) + " - " + walletFileName;
    SetConsoleTitleA(consoletitle.c_str());
#endif

    return std::make_shared<WalletInfo>(walletFileName, walletPass, walletAddress, false, wallet);
}

Maybe<std::shared_ptr<WalletInfo>> openWallet(CryptoNote::WalletGreen &wallet, Config &config) {
    std::string walletFileName = getExistingWalletFileName(config);

    bool initial = true;

    while (true) {
        std::string walletPass;

        /* Only use the command line pass once, otherwise we will infinite
           loop if it is incorrect */
        if (initial && config.passGiven) {
            walletPass = config.walletPass;
        } else {
            walletPass = getWalletPassword(false);
        }

        initial = false;

        connectingMsg();

        try {
            wallet.load(walletFileName, walletPass);

#ifdef _WIN32
            std::string consoletitle = std::string(CryptoNote::CRYPTONOTE_NAME) + " SimpleWallet v" + std::string(PROJECT_VERSION_LONG) + " - " + walletFileName;
            SetConsoleTitleA(consoletitle.c_str());
#endif

            std::string walletAddress = wallet.getAddress(0);

            Crypto::SecretKey privateSpendKey = wallet.getAddressSpendKey(0).secretKey;

            if (privateSpendKey == CryptoNote::NULL_SECRET_KEY) {
                std::cout << std::endl
                          << InformationMsg("Your view only wallet ") << SuccessMsg(walletAddress) << InformationMsg(" has been successfully opened!") << std::endl
                          << std::endl;

                viewWalletMsg();

                return Just<std::shared_ptr<WalletInfo>> (std::make_shared<WalletInfo>(walletFileName, walletPass, walletAddress, true, wallet));
            } else {
                std::cout << std::endl
                          << InformationMsg("Your wallet ") << SuccessMsg(walletAddress) << InformationMsg(" has been successfully opened!") << std::endl
                          << std::endl;

                if (wallet.getAddressCount() > 1) {
                    size_t subAddressCount = wallet.getAddressCount() - 1;
                    std::cout << InformationMsg("Wallet file contains ") << SuccessMsg(std::to_string(subAddressCount))
                              << (subAddressCount == 1 ? InformationMsg(" subwallet.") : InformationMsg(" subwallets.")) << std::endl
                              << std::endl;
                }

                return Just<std::shared_ptr<WalletInfo>> (std::make_shared<WalletInfo>(walletFileName, walletPass, walletAddress, false, wallet));
            }

            return Just<std::shared_ptr<WalletInfo>> (std::make_shared<WalletInfo>(walletFileName, walletPass, walletAddress, false, wallet));
        } catch (const std::system_error& e) {
            std::string walletSuccessBadPwdMsg = "Restored view public key doesn't correspond to secret key: The password is wrong";
            std::string walletSuccessBadPwdMsg2 = "Restored spend public key doesn't correspond to secret key: The password is wrong";
            std::string walletLegacyBadPwdMsg = ": The password is wrong";
            std::string alreadyOpenMsg = "MemoryMappedFile::open: The process cannot access the file because it is being used by another process.";
            std::string notAWalletMsg = "Unsupported wallet version: Wrong version";
            std::string errorMsg = e.what();

            /* There are three different error messages depending upon if we're
               opening a WalletGreen or a WalletLegacy wallet */
            if (errorMsg == walletSuccessBadPwdMsg || errorMsg == walletSuccessBadPwdMsg2 || errorMsg == walletLegacyBadPwdMsg) {
                std::cout << WarningMsg("Incorrect password! Try again.") << std::endl;
            }
            /* The message actually has a \r\n on the end but I'd prefer to
               keep just the raw string in the source so check that it starts
               with instead */
            else if (boost::starts_with(errorMsg, alreadyOpenMsg)) {
                std::cout << WarningMsg("Could not open wallet! It is already open in another process.") << std::endl
                          << WarningMsg("Check with a task manager that you don't have SimpleWallet open twice.") << std::endl
                          << WarningMsg("Also check you don't have another wallet program open, such as a GUI wallet or walletd.") << std::endl
                          << std::endl;

                std::cout << "Returning to selection screen..." << std::endl
                          << std::endl;

                return Nothing<std::shared_ptr<WalletInfo>>();
            } else if (errorMsg == notAWalletMsg) {
                std::cout << WarningMsg("Could not open wallet file! It doesn't appear to be a valid wallet!") << std::endl
                          << WarningMsg("Ensure you are opening a wallet file, and the file has not gotten corrupted.") << std::endl
                          << WarningMsg("Try reimporting via keys, and always close SimpleWallet with the exit command to prevent corruption.") << std::endl
                          << std::endl;

                std::cout << "Returning to selection screen..." << std::endl
                          << std::endl;

                return Nothing<std::shared_ptr<WalletInfo>>();
            } else {
                std::cout << "Unexpected error: " << errorMsg << std::endl
                          << "Please report this error message and what you did to cause it." << std::endl
                          << std::endl
                          << "Returning to selection screen..." << std::endl
                          << std::endl;

                return Nothing<std::shared_ptr<WalletInfo>>();
            }
        }
    }
}

bool verifyPrivateKey(const std::string &privateKeyString, Crypto::SecretKey &privateKey) {
    size_t privateKeyLen = 64;
    size_t size;
    Crypto::Hash privateKeyHash;
    Crypto::PublicKey publicKey;

    if (privateKeyString.length() != privateKeyLen) {
        std::cout << WarningMsg("Invalid private key, should be 64 characters! Try again.") << std::endl;
        return false;
    } else if (!Common::fromHex(privateKeyString, &privateKeyHash, sizeof(privateKeyHash), size) || size != sizeof(privateKeyHash)) {
        std::cout << WarningMsg("Invalid private key, failed to parse! Ensure you entered it correctly.") << std::endl;
        return false;
    }

    privateKey = *(struct Crypto::SecretKey *) &privateKeyHash;

    /* Just used for verification purposes before we pass it to WalletGreen */
    if (!Crypto::secret_key_to_public_key(privateKey, publicKey)) {
        std::cout << "Invalid private key, failed to parse! Ensure you entered it correctly." << std::endl;
        return false;
    }

    return true;
}

Crypto::SecretKey getPrivateKey(std::string msg) {

    std::string privateKeyString;
    Crypto::SecretKey privateKey;

    while (true) {
        std::cout << msg;

        std::getline(std::cin, privateKeyString);
        boost::algorithm::trim(privateKeyString);

        if (verifyPrivateKey(privateKeyString, privateKey)) {
            return privateKey;
        }
    }
}

std::string getExistingWalletFileName(Config &config) {
    bool initial = true;
    std::string walletName;

    while (true) {
        /* Only use wallet file once in case it is incorrect */
        if (config.walletGiven && initial) {
            walletName = config.walletFile;
        } else {
            std::cout << "What is the name of the wallet you want to open?: ";
            std::getline(std::cin, walletName);
        }

        initial = false;
        std::string walletFileName = walletName + ".wallet";

        if (walletName == "") {
            std::cout << WarningMsg("Wallet name can't be blank! Try again.") << std::endl;
        }
        /* Allow people to enter wallet name with or without file extension */
        else if (boost::filesystem::exists(walletName)) {
            return walletName;
        } else if (boost::filesystem::exists(walletFileName)) {
            return walletFileName;
        } else {
            std::cout << WarningMsg("A wallet with the filename " + walletFileName + " doesn't exist!") << std::endl
                      << "Ensure you entered your wallet name correctly." << std::endl;
        }
    }
}

std::string getNewWalletFileName() {
    std::string walletName;

    while (true) {
        std::cout << "What would you like to call your new wallet?: ";
        std::getline(std::cin, walletName);

        std::string walletFileName = walletName + ".wallet";

        if (boost::filesystem::exists(walletFileName)) {
            std::cout << WarningMsg("A wallet with the filename " + walletFileName + " already exists!") << std::endl
                      << "Try another name." << std::endl;
        } else if (walletName == "") {
            std::cout << WarningMsg("Wallet name can't be blank! Try again.") << std::endl;
        } else {
            return walletFileName;
        }
    }
}

std::string getWalletPassword(bool verifyPwd) {
    Tools::PasswordContainer pwdContainer;
    pwdContainer.read_password(verifyPwd);
    return pwdContainer.password();
}

Action getAction(Config &config) {
    if (config.walletGiven || config.passGiven) {
        return Open;
    }

    while (true) {
        std::cout << std::endl << "Welcome, please choose an option below:" << std::endl
                  << std::endl
                  << "\t[" << InformationMsg("G") << "] - " << "Generate a new wallet address" << std::endl
                  << "\t[" << InformationMsg("O") << "] - " << "Open a wallet already on your system" << std::endl
                  << "\t[" << InformationMsg("S") << "] - " << "Regenerate your wallet using a seed phrase of words" << std::endl
                  << "\t[" << InformationMsg("I") << "] - " << "Import your wallet using a View Key and Spend Key" << std::endl
                  << "\t[" << InformationMsg("V") << "] - " << "Import a view only wallet (Unable to send transactions)" << std::endl
                  << std::endl
                  << "or, press CTRL+C to exit: ";

        std::string answer;
        std::getline(std::cin, answer);

        char c = answer[0];
        c = std::tolower(c);

        if (c == 'o') {
            return Open;
        } else if (c == 'g') {
            return Generate;
        } else if (c == 'i') {
            return Import;
        } else if (c == 's') {
            return SeedImport;
        } else if (c == 'v') {
            return ViewWallet;
        } else {
            std::cout << "Unknown command: " << WarningMsg(answer) << std::endl;
        }
    }
}

void promptSaveKeys(CryptoNote::WalletGreen &wallet) {
    std::cout << "Welcome to your new wallet, here is your payment address:" << std::endl
              << InformationMsg(wallet.getAddress(0)) << std::endl
              << std::endl
              << "Please " << SuccessMsg("copy your secret keys and mnemonic seed") << " and store them in a secure location!" << std::endl;

    printPrivateKeys(wallet, false);

    std::cout << std::endl;
}

void exportKeys(std::shared_ptr<WalletInfo> &walletInfo) {
    if (walletInfo->walletPass != "") {
         confirmPassword(walletInfo->walletPass);
    }
    printPrivateKeys(walletInfo->wallet, walletInfo->viewWallet);
}

void printPrivateKeys(CryptoNote::WalletGreen &wallet, bool viewWallet) {
    Crypto::SecretKey privateViewKey = wallet.getViewKey().secretKey;

    if (viewWallet) {
        std::cout << SuccessMsg("Private view key:")
                  << std::endl
                  << SuccessMsg(Common::podToHex(privateViewKey))
                  << std::endl;
        return;
    }

    Crypto::PublicKey publicViewKey = wallet.getViewKey().publicKey;

    for (size_t i = 0; i < wallet.getAddressCount(); i++) {
        Crypto::SecretKey privateSpendKey = wallet.getAddressSpendKey(i).secretKey;
        Crypto::PublicKey publicSpendKey = wallet.getAddressSpendKey(i).publicKey;

        Crypto::SecretKey derivedPrivateViewKey;

        CryptoNote::AccountBase::generateViewFromSpend(privateSpendKey, derivedPrivateViewKey);

        bool deterministicPrivateKeys = derivedPrivateViewKey == privateViewKey;

        if (i > 0) {
            std::cout << std::endl;
        }
        if (wallet.getAddressCount() > 1) {
            std::cout << InformationMsg("Address:") << std::endl
                      << wallet.getAddress(i) << std::endl
                      << std::endl;
        }
        std::cout << InformationMsg("Private spend key:") << std::endl
                  << Common::podToHex(privateSpendKey) << std::endl
                  << std::endl;
        if (i == 0) {
            // Private view key is shared between subaddresses, only print it once as it's only required when recovering with GUI wallet
            std::cout << InformationMsg("Private view key:") << std::endl
                      << Common::podToHex(privateViewKey) << std::endl
                      << std::endl;
        }
        std::cout << SuccessMsg("GUI import key:") << std::endl
                  << Common::podToHex(publicSpendKey) <<std::endl
                  << Common::podToHex(publicViewKey) <<std::endl
                  << Common::podToHex(privateSpendKey) <<std::endl
                  << Common::podToHex(privateViewKey) << std::endl;

        if (deterministicPrivateKeys) {
            std::string mnemonicSeed;

            crypto::ElectrumWords::bytes_to_words(privateSpendKey, mnemonicSeed, "English");

            std::cout << std::endl
                      << SuccessMsg("Mnemonic seed:") << std::endl
                      << SuccessMsg(mnemonicSeed) << std::endl;
        }
    }
}

void welcomeMsg() {
    std::cout << "Use the " << SuggestionMsg("help") << " command to see the list of available commands." << std::endl
              << "Use " << SuggestionMsg("exit") << " when closing to ensure your wallet file doesn't get corrupted." << std::endl
              << std::endl;
}

std::string getInputAndDoWorkWhileIdle(std::shared_ptr<WalletInfo> &walletInfo) {
    auto lastUpdated = std::chrono::system_clock::now();

    std::future<std::string> inputGetter = std::async(std::launch::async, [] {
            std::string command;
            std::getline(std::cin, command);
            boost::algorithm::trim(command);
            return command;
    });

    while (true) {
        /* Check if the user has inputted something yet (Wait for zero seconds
           to instantly return) */
        std::future_status status = inputGetter.wait_for(std::chrono::seconds(0));

        /* User has inputted, get what they inputted and return it */
        if (status == std::future_status::ready) {
            return inputGetter.get();
        }

        auto currentTime = std::chrono::system_clock::now();

        /* Otherwise check if we need to update the wallet cache */
        if ((currentTime - lastUpdated) > std::chrono::seconds(5)) {
            lastUpdated = currentTime;
            checkForNewTransactions(walletInfo);
            if (backgroundOptimize) {
                checkForUnoptimizedOutputs(walletInfo);
            }
        }

        /* Sleep for enough for it to not be noticeable when the user enters
           something, but enough that we're not starving the CPU */
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void inputLoop(System::Dispatcher& dispatcher, std::shared_ptr<WalletInfo> &walletInfo, CryptoNote::INode &node) {
    while (true) {
        std::cout << getPrompt(walletInfo);

        std::string command = getInputAndDoWorkWhileIdle(walletInfo);

        /* Split into args to support legacy transfer command, for example transfer 5 TAxyzbf... 100,
           sends 100 TLO to TAxyzbf... with a mixin of 5 */
        std::vector<std::string> words;
        words = boost::split(words, command, ::isspace);

        if (command == "") {
            // no-op
        } else if (command == "export_keys") {
            exportKeys(walletInfo);
        } else if (command == "help") {
            help(walletInfo->viewWallet);
        } else if (command == "balance") {
            balance(node, walletInfo->wallet, walletInfo->viewWallet);
        } else if (command == "balances") {
            balances(node, walletInfo->wallet, walletInfo->viewWallet);
        } else if (command == "address") {
            std::cout << SuccessMsg(walletInfo->wallet.getAddress(subWallet)) << std::endl;
        } else if (words[0] == "address") {
            try {
                size_t idx = std::stoull(words[1]);
                if (idx < walletInfo->wallet.getAddressCount()) {
                    std::cout << InformationMsg("Subwallet " + std::to_string(idx) + ": ") << SuccessMsg(walletInfo->wallet.getAddress(idx)) << std::endl;
                } else {
                    std::cout << WarningMsg("Invalid subwallet index!") << std::endl;
                }
            }
            catch (const std::invalid_argument&) {
                std::cout << WarningMsg("Invalid subwallet index!") << std::endl;
            }
            catch (const std::out_of_range&) {
                std::cout << WarningMsg("Invalid subwallet index!") << std::endl;
            }
        } else if (command == "incoming_transfers") {
            listTransfers(true, false, walletInfo->wallet, node);
        } else if (command == "exit") {
            return;
        } else if (command == "save") {
            hidecursor();
            std::cout << InformationMsg("Saving...") << std::flush;
            time_t startTime = time(NULL);
            walletInfo->wallet.save();
            time_t endTime = time(NULL);
            time_t elapsed = endTime - startTime;
            Common::Console::clearLine();
            if (elapsed < 1) {
                std::cout << InformationMsg("\rSaved.") << std::endl;
            } else {
                std::cout << InformationMsg("\rSaved in " + std::to_string(elapsed) + " second" + (elapsed != 1 ? "s" : "") + ".") << std::endl;
            }
            showcursor();
        } else if (command == "bc_height") {
            blockchainHeight(node, walletInfo->wallet);
        } else if (command == "reset") {
            reset(node, walletInfo);
        } else if (words[0] == "change_password") {
            words.erase(words.begin());
            changePassword(walletInfo, words);
        } else if (command == "outputs") {
            estimateFusion(walletInfo);
        } else if (!walletInfo->viewWallet) {
            if (command == "add_address") {
                addAddress(walletInfo->wallet);
            } else if (command == "delete_address") {
                deleteAddress(walletInfo->wallet);
            } else if (words[0] == "delete_address") {
                words.erase(words.begin());
                deleteAddress(walletInfo->wallet, words);
            } else if (command == "list_addresses") {
                listAddresses(walletInfo->wallet);
            } else if (command == "recover_address") {
                recoverAddress(walletInfo, node);
            } else if (words[0] == "recover_address") {
                words.erase(words.begin());
                recoverAddress(walletInfo, node, words);
            } else if (command == "repair") {
                repair(walletInfo->wallet);
            } else if (command == "select_address") {
                selectAddress(walletInfo->wallet);
            } else if (words[0] == "select_address") {
                words.erase(words.begin());
                selectAddress(walletInfo->wallet, words);
            } else if (command == "outgoing_transfers") {
                listTransfers(false, true, walletInfo->wallet, node);
            } else if (command == "list_outputs") {
                listOutputs(walletInfo->wallet, node);
            } else if (words[0] == "list_transfer") {
                words.erase(words.begin());
                listTransfer(words, walletInfo->wallet, node);
            } else if (command == "list_transfers") {
                listTransfers(true, true, walletInfo->wallet, node);
            } else if (command == "count_transfers") {
                countTransfers(true, true, walletInfo->wallet, node);
            } else if (command == "transfer") {
                transfer(dispatcher, walletInfo);
            } else if (words[0] == "transfer") {
                /* remove the first item from words - this is the "transfer"
                   command, leaving us just the transfer arguments. */
                words.erase(words.begin());
                transfer(dispatcher, walletInfo, words);
            } else if (command == "quick_optimize") {
                quickOptimize(walletInfo->wallet);
            } else if (command == "full_optimize") {
                fullOptimize(walletInfo->wallet);
            } else if (command == "consolidate") {
                consolidate(walletInfo->wallet);
            } else {
                std::cout << "Unknown command: " << WarningMsg(command) << ", use " << SuggestionMsg("help") << " command to list all possible commands." << std::endl;
            }
        } else {
            std::cout << "Unknown command: " << WarningMsg(command) << ", use " << SuggestionMsg("help") << " command to list all possible commands." << std::endl
                      << "Please note some commands such as transfer are unavailable, as you are using a view only wallet." << std::endl;
        }
    }
}

void help(bool viewWallet) {
    std::string coinTicker(CryptoNote::CRYPTONOTE_TICKER);

    if (viewWallet) {
        std::cout << InformationMsg("Please note you are using a view only wallet and cannot transfer " + coinTicker + ".") << std::endl;
    }
    std::cout << "Available commands:" << std::endl
              << SuccessMsg("help", 25) << "List this help message" << std::endl
              << SuccessMsg("address", 25) << "Displays your payment address" << std::endl
              << SuccessMsg("balance", 25) << "Display how much " << coinTicker << " you have" << std::endl
              << SuccessMsg("balances", 25) << "Display how much " << coinTicker << " is in all subwallets" << std::endl
              << SuccessMsg("bc_height", 25) << "Show the blockchain height" << std::endl
              << SuccessMsg("change_password", 25) << "Change password of current wallet file" << std::endl
              << SuccessMsg("export_keys", 25) << "Export your private keys" << std::endl;
    if (!viewWallet) {
        std::cout << SuccessMsg("add_address", 25) << "Add new subwallet" << std::endl
                  << SuccessMsg("delete_address", 25) << "Delete subwallet" << std::endl
                  << SuccessMsg("list_addresses", 25) << "List subwallets" << std::endl
                  << SuccessMsg("recover_address", 25) << "Recover subwallet using private spend key" << std::endl
                  << SuccessMsg("select_address", 25) << "Select current subwallet" << std::endl
                  << SuccessMsg("transfer", 25) << "Send " << coinTicker << " to someone" << std::endl
                  << SuccessMsg("list_outputs", 25) << "Show unspent outputs" << std::endl
                  << SuccessMsg("list_transfer", 25) << "Show transfer" << std::endl
                  << SuccessMsg("list_transfers", 25) << "Show all transfers" << std::endl
                  << SuccessMsg("count_transfers", 25) << "Show number of transfers" << std::endl
                  << SuccessMsg("quick_optimize", 25) << "Quickly optimize your wallet to send large amounts" << std::endl
                  << SuccessMsg("full_optimize", 25) << "Fully optimize your wallet to send large amounts" << std::endl
                  << SuccessMsg("consolidate", 25) << "Optimize all subwallets and transfer to current subwallet" << std::endl
                  << SuccessMsg("outgoing_transfers", 25) << "Show outgoing transfers" << std::endl
                  << SuccessMsg("repair", 25) << "Repair wallet integrity" << std::endl;
                  ;
    }
    std::cout << SuccessMsg("incoming_transfers", 25) << "Show incoming transfers" << std::endl
              << SuccessMsg("outputs", 25) << "Show number of optimizable and all outputs" << std::endl
              << SuccessMsg("reset", 25) << "Discard cached data and recheck for transactions" << std::endl
              << SuccessMsg("save", 25) << "Save your wallet state" << std::endl
              << SuccessMsg("exit", 25) << "Exit and save your wallet" << std::endl;
}

void balance(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet, bool viewWallet) {
    std::string address = wallet.getAddress(subWallet);
    uint64_t unconfirmedBalance = wallet.getPendingBalance(address);
    uint64_t confirmedBalance = wallet.getActualBalance(address);
    uint64_t totalBalance = unconfirmedBalance + confirmedBalance;

    uint32_t localHeight = node.getLastLocalBlockHeight();
    uint32_t remoteHeight = node.getLastKnownBlockHeight();
    uint32_t walletHeight = wallet.getBlockCount();

    size_t totalLen = formatAmount(totalBalance).length(); // total balance is always the widest string

    std::cout << std::right << std::setw(30) << "Available balance: " << std::right << std::setw(totalLen) << SuccessMsg(formatAmount(confirmedBalance)) << std::endl
              << std::right << std::setw(30) << "Locked (unconfirmed) balance: " << std::right << std::setw(totalLen) << WarningMsg(formatAmount(unconfirmedBalance)) << std::endl
              << std::string(30+totalLen, '-') << std::endl
              << std::right << std::setw(30) << "Total balance: " << std::right << std::setw(totalLen) << InformationMsg(formatAmount(totalBalance)) << std::endl;

    if (viewWallet) {
        std::cout << std::endl
                  << InformationMsg("Please note that view only wallets can only track incoming transactions, and so your wallet balance may appear inflated.") << std::endl;
    }

    if (localHeight < remoteHeight) {
        std::cout << std::endl
                  << InformationMsg("Your daemon is not fully synced with the network!") << std::endl
                  << "Your balance may be incorrect until you are fully synced!" << std::endl;
    } else if (walletHeight + 1000 < remoteHeight) { /* Small buffer because wallet height doesn't update instantly like node height does */
        std::cout << std::endl
                  << InformationMsg("The blockchain is still being scanned for your transactions.") << std::endl
                  << "Balances might be incorrect whilst this is ongoing." << std::endl;
    }
}

void balances(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet, bool viewWallet) {
    size_t numWallets = wallet.getAddressCount();
    size_t addressLen = wallet.getAddress(0).length();
    std::vector<std::string> addresses;
    std::vector<uint64_t> unconfirmedBalances;
    std::vector<uint64_t> confirmedBalances;
    std::vector<uint64_t> totalBalances;
    uint64_t unconfirmedBalancesTotal = 0;
    uint64_t confirmedBalancesTotal = 0;
    uint64_t totalBalancesTotal = 0;
    size_t unconfirmedBalancesLen, confirmedBalancesLen, totalBalancesLen;
    for (size_t i = 0; i < numWallets; i++) {
        std::string address = wallet.getAddress(i);
        uint64_t unconfirmedBalance = wallet.getPendingBalance(address);
        uint64_t confirmedBalance = wallet.getActualBalance(address);
        uint64_t totalBalance = unconfirmedBalance + confirmedBalance;

        addresses.push_back(address);
        unconfirmedBalances.push_back(unconfirmedBalance);
        confirmedBalances.push_back(confirmedBalance);
        totalBalances.push_back(totalBalance);

        unconfirmedBalancesTotal += unconfirmedBalance;
        confirmedBalancesTotal += confirmedBalance;
        totalBalancesTotal += totalBalance;
    }

    uint32_t localHeight = node.getLastLocalBlockHeight();
    uint32_t remoteHeight = node.getLastKnownBlockHeight();
    uint32_t walletHeight = wallet.getBlockCount();

    unconfirmedBalancesLen = std::max(UINT64_C(6), formatAmount(unconfirmedBalancesTotal).length());
    confirmedBalancesLen = std::max(UINT64_C(9), formatAmount(confirmedBalancesTotal).length());
    totalBalancesLen = std::max(UINT64_C(5), formatAmount(totalBalancesTotal).length());

    std::cout << std::left << std::setw(addressLen) << "Address"
              << std::right << std::setw(confirmedBalancesLen + 1) << "Available"
              << std::right << std::setw(unconfirmedBalancesLen + 1) << "Locked"
              << std::right << std::setw(totalBalancesLen + 1) << "Total"
              << std::endl;
    std::cout << Common::repeatChar(addressLen + confirmedBalancesLen + unconfirmedBalancesLen + totalBalancesLen + 3, '=') << std::endl;

    for (size_t i = 0; i < numWallets; i++) {
        std::cout << addresses[i]
                  << std::right << std::setw(confirmedBalancesLen + 1) << SuccessMsg(formatAmount(confirmedBalances[i]))
                  << std::right << std::setw(unconfirmedBalancesLen + 1) << WarningMsg(formatAmount(unconfirmedBalances[i]))
                  << std::right << std::setw(totalBalancesLen + 1) << InformationMsg(formatAmount(totalBalances[i]))
                  << std::endl;
    }

    if (numWallets > 1) {
            std::cout << Common::repeatChar(addressLen + confirmedBalancesLen + unconfirmedBalancesLen + totalBalancesLen + 3, '-') << std::endl;
            std::cout << std::setw(addressLen) << "Total:"
                      << std::right << std::setw(confirmedBalancesLen + 1) << SuccessMsg(formatAmount(confirmedBalancesTotal))
                      << std::right << std::setw(unconfirmedBalancesLen + 1) << WarningMsg(formatAmount(unconfirmedBalancesTotal))
                      << std::right << std::setw(totalBalancesLen + 1) << InformationMsg(formatAmount(totalBalancesTotal))
                      << std::endl;
    }

    if (viewWallet) {
        std::cout << std::endl
                  << InformationMsg("Please note that view only wallets can only track incoming transactions, and so your wallet balance may appear inflated.") << std::endl;
    }

    if (localHeight < remoteHeight) {
        std::cout << std::endl
                  << InformationMsg("Your daemon is not fully synced with the network!") << std::endl
                  << "Your balance may be incorrect until you are fully synced!" << std::endl;
    } else if (walletHeight + 1000 < remoteHeight) { /* Small buffer because wallet height doesn't update instantly like node height does */
        std::cout << std::endl
                  << InformationMsg("The blockchain is still being scanned for your transactions.") << std::endl
                  << "Balances might be incorrect whilst this is ongoing." << std::endl;
    }
}

void blockchainHeight(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet) {
    uint32_t localHeight = node.getLastLocalBlockHeight();
    uint32_t remoteHeight = node.getLastKnownBlockHeight();
    uint32_t walletHeight = wallet.getBlockCount();

    size_t totalLen = std::max({std::to_string(localHeight).length(), std::to_string(remoteHeight).length(), std::to_string(walletHeight).length()});

    /* This is the height that the wallet has been scanned to. The blockchain
       can be fully updated, but we have to walk the chain to find our
       transactions, and this number indicates that progress. */
    std::cout << std::right << std::setw(27) << "Wallet blockchain height: ";

    /* Small buffer because wallet height doesn't update instantly like node
       height does */
    if (walletHeight + 1000 > remoteHeight) {
        std::cout << std::right << std::setw(totalLen) << SuccessMsg(std::to_string(walletHeight));
    } else {
        std::cout << std::right << std::setw(totalLen) << WarningMsg(std::to_string(walletHeight));
    }

    std::cout << std::endl << std::right << std::setw(27) << "Local blockchain height: ";

    if (localHeight == remoteHeight) {
        std::cout << std::right << std::setw(totalLen) << SuccessMsg(std::to_string(localHeight));
    } else {
        std::cout << std::right << std::setw(totalLen) << WarningMsg(std::to_string(localHeight));
    }

    std::cout << std::endl
              << std::right << std::setw(27) << "Network blockchain height: "
              << std::right << std::setw(totalLen) << SuccessMsg(std::to_string(remoteHeight)) << std::endl;

    if (localHeight == 0 && remoteHeight == 0) {
        std::cout << WarningMsg("Uh oh, it looks like you don't have " + std::string(CryptoNote::CRYPTONOTE_NAME) + "d open!") << std::endl;
    } else if (walletHeight + 1000 < remoteHeight && localHeight == remoteHeight) {
        std::cout << InformationMsg("You are synced with the network, but the blockchain is still being scanned for your transactions.") << std::endl
                  << "Balances might be incorrect whilst this is ongoing." << std::endl;
    } else if (localHeight == remoteHeight) {
        std::cout << SuccessMsg("Yay! You are synced!") << std::endl;
    } else {
        std::cout << WarningMsg("Be patient, you are still syncing with the network!") << std::endl;
    }
}

bool shutdown(CryptoNote::WalletGreen &wallet, CryptoNote::INode &node, bool &alreadyShuttingDown) {
    if (alreadyShuttingDown) {
        std::cout << "Patience... we're already shutting down!" << std::endl;
        return false;
    } else {
        alreadyShuttingDown = true;
        std::cout << InformationMsg("Saving wallet and shutting down, please wait...") << std::endl;
    }

    bool finishedShutdown = false;

    boost::thread timelyShutdown([&finishedShutdown] {
        /* Has shutdown finished? */
        while (!finishedShutdown) {

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    wallet.save();
    wallet.shutdown();
    node.shutdown();

    finishedShutdown = true;

    /* Wait for shutdown watcher to finish */
    timelyShutdown.join();

    std::cout << "Bye." << std::endl;

    return true;
}

CryptoNote::BlockDetails getBlock(uint32_t blockHeight, CryptoNote::INode &node) {
    CryptoNote::BlockDetails block;

    /* No connection to Talleod */
    if (node.getLastKnownBlockHeight() == 0) {
        return block;
    }

    std::promise<std::error_code> errorPromise;

    auto e = errorPromise.get_future();

    auto callback = [&errorPromise](std::error_code e) {
        errorPromise.set_value(e);
    };

    node.getBlock(blockHeight, block, callback);

    if (e.get()) {
        /* Prevent the compiler optimizing it out... */
        std::cout << "";
    }

    return block;
}

std::string getBlockTime(CryptoNote::BlockDetails b) {
    if (b.timestamp == 0) {
        return "";
    }

    std::time_t time = b.timestamp;
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), "%F %R", std::localtime(&time));
    return std::string(buffer);
}

int64_t filterAmounts(const CryptoNote::WalletTransaction &t, CryptoNote::WalletGreen &wallet) {
    std::string address = wallet.getAddress(subWallet);
    int64_t total = 0;
    CryptoNote::WalletTransactionWithTransfers tt = wallet.getTransaction(t.hash);
    size_t numTransfers = tt.transfers.size();
    for (size_t j = 0; j < numTransfers; j++) {
        CryptoNote::WalletTransfer wt = tt.transfers[j];
        if (wt.address == address) {
            total += wt.amount;
        }
    }
    return total;
}

void filterFusionAmounts(const CryptoNote::WalletTransaction &t, CryptoNote::WalletGreen &wallet, int64_t& amountIn, int64_t& amountOut) {
    std::string address = wallet.getAddress(subWallet);
    amountIn = 0;
    amountOut = 0;
    if (t.fee != 0) {
        return;
    }
    CryptoNote::WalletTransactionWithTransfers tt = wallet.getTransaction(t.hash);
    size_t numTransfers = tt.transfers.size();
    for (size_t j = 0; j < numTransfers; j++) {
        CryptoNote::WalletTransfer wt = tt.transfers[j];
        if (wt.address == address) {
            if (wt.amount < 0) {
                amountOut += wt.amount;
            } else if (wt.amount > 0) {
                amountIn += wt.amount;
            }
        }
    }
}

void printOutgoingAddresses(CryptoNote::WalletGreen &wallet, const CryptoNote::WalletTransaction& wtx, int width) {
    std::vector<std::string> addresses;
    auto wtwt = wallet.getTransaction(wtx.hash);
    for (size_t i = 0; i < wtwt.transfers.size(); i++) {
        auto wt = wtwt.transfers[i];
        if (!wt.address.empty() && wt.amount < 0 && std::find(addresses.begin(), addresses.end(), wt.address) == addresses.end()) {
            addresses.push_back(wt.address);
        }
    }
    size_t numAddresses = addresses.size();
    if (numAddresses > 0) {
        std::cout << std::left << std::setw(width) << WarningMsg(numAddresses == 1 ? "Address:" : "Addresses: ") << WarningMsg(addresses[0]) << std::endl;
        for (size_t j = 1; j < numAddresses; j++) {
            std::cout << Common::repeatChar(width, ' ') << WarningMsg(addresses[j]) << std::endl;
        }
    }
}

void printOutgoingAddresses(std::shared_ptr<WalletInfo> &walletInfo, const CryptoNote::WalletTransaction& wtx, int width) {
    printOutgoingAddresses(walletInfo->wallet, wtx, width);
}

void printOutgoingTransfer(const CryptoNote::WalletTransaction &t, CryptoNote::INode &node, CryptoNote::WalletGreen &wallet, bool allWallets) {
    std::string blockTime = getBlockTime(getBlock(t.blockHeight, node));
    int64_t amount = allWallets ? t.totalAmount : filterAmounts(t, wallet);
    if (amount == 0) return;

    size_t totalLen = formatAmount(-amount).length();

    std::cout << std::endl
              << WarningMsg("Outgoing transfer:") << std::endl;

    if (allWallets && wallet.getAddressCount() > 1) {
        printOutgoingAddresses(wallet, t, 13);
    }

    /* Couldn't get timestamp, maybe old node or Talleod closed */
    if (blockTime != "") {
        std::cout << std::left << std::setw(13) << WarningMsg("Time: ") << std::setw(0) << WarningMsg(blockTime) << std::endl;
    }
    std::cout << std::left << std::setw(13) << WarningMsg("Hash: ") << std::setw(64) << WarningMsg(Common::podToHex(t.hash)) << std::endl
              << std::left << std::setw(13) << WarningMsg("Spent: ") << std::right << std::setw(totalLen) << WarningMsg(formatAmount(-amount - t.fee)) << std::endl
              << std::left << std::setw(13) << WarningMsg("Fee: ") << std::right << std::setw(totalLen) << WarningMsg(formatAmount(t.fee)) << std::endl
              << std::left << std::setw(13) << WarningMsg("Total Spent: ") << std::right << std::setw(totalLen) << WarningMsg(formatAmount(-amount)) << std::endl;

    Crypto::Hash paymentId;
    std::vector<uint8_t> vec(t.extra.begin(), t.extra.end());
    if (CryptoNote::getPaymentIdFromTxExtra(vec, paymentId)) {
        std::cout << std::left << std::setw(13) << SuccessMsg("Payment ID: ") << std::setw(64) << SuccessMsg(Common::podToHex(paymentId)) << std::endl;
    }

    std::cout << std::endl;
}

void printIncomingAddresses(CryptoNote::WalletGreen &wallet, const CryptoNote::WalletTransaction& wtx, int width) {
    std::vector<std::string> addresses;
    auto wtwt = wallet.getTransaction(wtx.hash);
    for (size_t i = 0; i < wtwt.transfers.size(); i++) {
        auto wt = wtwt.transfers[i];
        if (!wt.address.empty() && wt.amount > 0 && std::find(addresses.begin(), addresses.end(), wt.address) == addresses.end()) {
            addresses.push_back(wt.address);
        }
    }
    size_t numAddresses = addresses.size();
    if (numAddresses > 0) {
        std::cout << std::left << std::setw(width) << SuccessMsg(numAddresses == 1 ? "Address:" : "Addresses: ") << SuccessMsg(addresses[0]) << std::endl;
        for (size_t j = 1; j < numAddresses; j++) {
            std::cout << Common::repeatChar(width, ' ') << SuccessMsg(addresses[j]) << std::endl;
        }
    }
}

void printIncomingAddresses(std::shared_ptr<WalletInfo> &walletInfo, const CryptoNote::WalletTransaction& wtx, int width) {
    printIncomingAddresses(walletInfo->wallet, wtx, width);
}

void printIncomingTransfer(const CryptoNote::WalletTransaction &t, CryptoNote::INode &node, CryptoNote::WalletGreen &wallet, bool allWallets) {
    std::string blockTime = getBlockTime(getBlock(t.blockHeight, node));
    int64_t amount = allWallets ? t.totalAmount : filterAmounts(t, wallet);
    if (amount == 0) return;

    std::cout << std::endl
              << InformationMsg("Incoming transfer:") << std::endl;

    if (allWallets && wallet.getAddressCount() > 1) {
        printIncomingAddresses(wallet, t, 13);
    }

    /* Couldn't get timestamp, maybe old node or Talleod closed */
    if (blockTime != "") {
        std::cout << std::left << std::setw(13) << SuccessMsg("Time: ") << std::setw(0) << SuccessMsg(blockTime) << std::endl;
    }
    std::cout << std::left << std::setw(13) << SuccessMsg("Hash: ") << std::setw(64) << SuccessMsg(Common::podToHex(t.hash)) << std::endl
              << std::left << std::setw(13) << SuccessMsg("Amount: ") << std::setw(0) << SuccessMsg(formatAmount(amount)) << std::endl;

    Crypto::Hash paymentId;
    std::vector<uint8_t> vec(t.extra.begin(), t.extra.end());
    if (CryptoNote::getPaymentIdFromTxExtra(vec, paymentId)) {
        std::cout << std::left << std::setw(13) << SuccessMsg("Payment ID: ") << std::setw(64) << SuccessMsg(Common::podToHex(paymentId)) << std::endl;
    }

    std::cout << std::endl;
}

void listOutputs(CryptoNote::WalletGreen &wallet, CryptoNote::INode &node) {
    auto outs = wallet.getUnspentOutputs(wallet.getAddress(subWallet)).outs;
    size_t numOutputs = outs.size();
    if (numOutputs > 0) {
        std::sort(outs.begin(), outs.end(), [](const CryptoNote::TransactionOutputInformation& a, const CryptoNote::TransactionOutputInformation& b) {
            return a.amount < b.amount;
        });
        size_t aWidth = formatAmount(outs.back().amount).length();
        std::cout << InformationMsg("Transaction hash", 65) << std::right << std::setw(aWidth) << InformationMsg("Amount") << std::endl;
        for (size_t i = 0; i < numOutputs; i++) {
            std::cout << Common::podToHex(outs[i].transactionHash) << " " << std::right << std::setw(aWidth) << formatAmount(outs[i].amount) << std::endl;
        }
    } else {
        std::cout << WarningMsg("No unspent outputs!") << std::endl;
    }
}

void addAddress(CryptoNote::WalletGreen &wallet) {
   std::string address = wallet.createAddress();
   std::cout << InformationMsg("Created subwallet with address ") << SuccessMsg(address) << InformationMsg(".") << std::endl;
   return;
}

void listAddresses(CryptoNote::WalletGreen &wallet) {
    std::cout << InformationMsg("List of subwallets:") << std::endl
              << InformationMsg("-------------------") << std::endl;

    for (size_t i = 0; i < wallet.getAddressCount(); i++) {
        std::cout << InformationMsg(std::to_string(i) + ") ") << SuccessMsg(wallet.getAddress(i)) << std::endl;
    }
}

void recoverAddress(std::shared_ptr<WalletInfo> &walletInfo, CryptoNote::INode &node) {
    Crypto::SecretKey privateSpendKey = getPrivateKey("Private Spend Key: ");
    std::string address = walletInfo->wallet.createAddress(privateSpendKey);
    std::cout << InformationMsg("Recovering subwallet with address ") << SuccessMsg(address) << InformationMsg("... Rescanning for transactions might take a few minutes.") << std::endl;
    std::cout << InformationMsg("Use the ") << SuggestionMsg("bc_height") << InformationMsg(" command to see the progress.") << std::endl;
}

void repair(CryptoNote::WalletGreen &wallet) {
    wallet.repair();
}

void recoverAddress(std::shared_ptr<WalletInfo> &walletInfo, CryptoNote::INode &node, std::vector<std::string> args) {
    if (args.size() == 0) {
        std::cout << WarningMsg("You must specify private spend key of subwallet to recover!") << std::endl;
    }
    if (args.size() > 1) {
        std::cout << WarningMsg("Too many parameters, specify only private spend key of subwallet to recover!") << std::endl;
    }
    std::string privateKeyString = args[0];
    Crypto::SecretKey privateKey;

    boost::algorithm::trim(privateKeyString);

    if (verifyPrivateKey(privateKeyString, privateKey)) {
        std::string address = walletInfo->wallet.createAddress(privateKey);
        std::cout << InformationMsg("Recovering subwallet with address ") << SuccessMsg(address) << InformationMsg("... Rescanning for transactions might take a few minutes.") << std::endl;
        std::cout << InformationMsg("Use the ") << SuggestionMsg("bc_height") << InformationMsg(" command to see the progress.") << std::endl;
    }
}

size_t getSubWallet(CryptoNote::WalletGreen &wallet, bool del) {
    std::string reply;
    size_t index = 0;
    listAddresses(wallet);
    while (true) {
        std::cout << (del ? InformationMsg("Which subwallet do you want to delete: ") :
                            InformationMsg("Which subwallet do you want to select: "));
        std::getline(std::cin, reply);
        if (reply.length() == 97 && reply.substr(0, 2) == "TA") {
            for (size_t i = 0; i < wallet.getAddressCount(); i++) {
                if (wallet.getAddress(i) == reply) return i;
            }
        }
        try {
            index = (size_t) std::stoull(reply);
            if (index >= wallet.getAddressCount()) {
                continue;
            }
        } catch (...) {
            continue;
        }
        break;
    }
    return index;
}

size_t findAddressIndex(CryptoNote::WalletGreen &wallet, const std::string &address) {
    size_t index;
    if (address.length() == 97 && address.substr(0, 2) == "TA") {
        for (size_t i = 0; i < wallet.getAddressCount(); i++) {
            if (wallet.getAddress(i) == address) {
                return i;
            }
        }
        std::cout << WarningMsg("Invalid address or address not found in wallet file!") << std::endl;
    } else {
        try {
            index = (size_t) std::stoull(address);
            if (index < wallet.getAddressCount()) {
                return index;
            }
            std::cout << WarningMsg("Invalid subwallet index!") << std::endl;
        } catch (...) {
           std::cout << WarningMsg("Invalid address!") << std::endl;
        }
    }
    return invalidIndex;
}

void deleteAddress(CryptoNote::WalletGreen &wallet) {
    size_t index = getSubWallet(wallet, true);
    if (index != 0) {
        std::string address = wallet.getAddress(index);
        wallet.deleteAddress(address);
        std::cout << InformationMsg("Deleted subwallet with address ") << SuccessMsg(address);
        if (subWallet == index) {
            subWallet--;
            std::cout << InformationMsg(", new current subwallet is address ") << SuccessMsg(wallet.getAddress(subWallet));
        } else if (index < subWallet) {
            subWallet--;
        }
        std::cout << InformationMsg(".") << std::endl;
    } else {
        std::cout << WarningMsg("Can't delete primary address!");
    }
}

void deleteAddress(CryptoNote::WalletGreen &wallet, std::vector<std::string> args) {
    if (args.size() == 0) {
        std::cout << WarningMsg("You must specify wallet address to delete!") << std::endl;
        return;
    }
    if (args.size() > 1) {
        std::cout << WarningMsg("Too many parameters, please only specify wallet address to delete!") << std::endl;
        return;
    }
    size_t index = findAddressIndex(wallet, args[0]);
    if (index == invalidIndex) {
        return;
    }
    if (index != 0) {
        std::string address = wallet.getAddress(index);
        wallet.deleteAddress(address);
        std::cout << InformationMsg("Deleted subwallet with address ") << SuccessMsg(address);
        if (subWallet == index) {
            subWallet--;
            std::cout << InformationMsg(", new current subwallet is address ") << SuccessMsg(wallet.getAddress(subWallet));
        } else if (index < subWallet) {
            subWallet--;
        }
        std::cout << InformationMsg(".") << std::endl;
    } else {
        std::cout << WarningMsg("Can't delete primary address!");
    }
}

void selectAddress(CryptoNote::WalletGreen &wallet) {
    size_t index = getSubWallet(wallet, false);
    if (index != subWallet) {
         subWallet = index;
         std::cout << InformationMsg("Current subwallet is address ") << SuccessMsg(wallet.getAddress(subWallet)) << InformationMsg(".") << std::endl;
    }
}

void selectAddress(CryptoNote::WalletGreen &wallet, std::vector<std::string> args) {
    if (args.size() == 0) {
        std::cout << WarningMsg("You must specify wallet address to select!") << std::endl;
        return;
    }
    if (args.size() > 1) {
        std::cout << WarningMsg("Too many parameters, please only specify wallet address to select!") << std::endl;
        return;
    }
    size_t index = findAddressIndex(wallet, args[0]);
    if (index == invalidIndex) {
        return;
    }
    if (index != subWallet) {
         subWallet = index;
         std::cout << InformationMsg("Current subwallet is address ") << SuccessMsg(wallet.getAddress(subWallet)) << InformationMsg(".") << std::endl;
    }
}

std::vector<CryptoNote::WalletTransaction> filterTransactions(CryptoNote::WalletGreen &wallet) {
    std::vector<CryptoNote::WalletTransaction> transactions;
    size_t numTransactions = wallet.getTransactionCount();
    std::string address = wallet.getAddress(subWallet);
    for (size_t i = 0; i < numTransactions; i++) {
        CryptoNote::WalletTransaction t = wallet.getTransaction(i);
        CryptoNote::WalletTransactionWithTransfers tt = wallet.getTransaction(t.hash);
        size_t numTransfers = tt.transfers.size();
        for (size_t j = 0; j < numTransfers; j++) {
            CryptoNote::WalletTransfer wt = tt.transfers[j];
            if (wt.address == address) {
                transactions.push_back(t);
                break;
            }
        }
    }
    return transactions;
}

void listTransfer(std::vector<std::string> args, CryptoNote::WalletGreen &wallet, CryptoNote::INode &node) {
    if (args.size() == 0) {
        std::cout << WarningMsg("You must specify transaction hash!") << std::endl;
        return;
    }
    if (args.size() > 1) {
        std::cout << WarningMsg("Too many parameters, please only specify transaction hash!") << std::endl;
        return;
    }
    Crypto::Hash txhash;
    if (!Common::podFromHex(args[0], txhash)) {
        std::cout << WarningMsg("Invalid transaction hash!") << std::endl;
        return;
    }
    size_t numTransactions = wallet.getTransactionCount();
    for (size_t i = 0; i < numTransactions; i++) {
        CryptoNote::WalletTransaction t = wallet.getTransaction(i);
        if (t.hash == txhash) {
             int64_t amount = filterAmounts(t, wallet);

             if (amount < 0) {
                 printOutgoingTransfer(t, node, wallet, false);
             } else if (amount > 0) {
                 printIncomingTransfer(t, node, wallet, false);
             }
             return;
        }
    }
    std::cout << WarningMsg("Transaction not found!") << std::endl;
}

void listTransfers(bool incoming, bool outgoing, CryptoNote::WalletGreen &wallet, CryptoNote::INode &node) {
    auto transactions = filterTransactions(wallet);
    size_t numTransactions = transactions.size();
    int64_t totalSpent = 0;
    int64_t totalReceived = 0;

    for (size_t i = 0; i < numTransactions; i++) {
        CryptoNote::WalletTransaction t = transactions[i];
        int64_t amount = filterAmounts(t, wallet);

        if (amount < 0 && outgoing) {
            printOutgoingTransfer(t, node, wallet, false);
            totalSpent += -amount;
        } else if (amount > 0 && incoming) {
            printIncomingTransfer(t, node, wallet, false);
            totalReceived += amount;
        }
    }

    if (incoming) {
        std::cout << InformationMsg("Total received: ") << SuccessMsg(formatAmount(totalReceived)) << std::endl;
    }

    if (outgoing) {
        std::cout << InformationMsg("Total spent: ") << WarningMsg(formatAmount(totalSpent)) << std::endl;
    }
}

void countTransfers(bool incoming, bool outgoing, CryptoNote::WalletGreen &wallet, CryptoNote::INode &node) {
    auto transactions = filterTransactions(wallet);
    size_t numTransactions = transactions.size();
    uint64_t totalIncoming = 0;
    uint64_t totalOutgoing = 0;
    uint64_t totalFusion = 0;

    for (size_t i = 0; i < numTransactions; i++) {
        CryptoNote::WalletTransaction t = transactions[i];
        int64_t amount = filterAmounts(t, wallet);

        if (t.fee == 0 && t.totalAmount == 0) {
            int64_t amountIn;
            int64_t amountOut;
            filterFusionAmounts(t, wallet, amountIn, amountOut);
            if (amountIn != 0 || amountOut != 0) {
                totalFusion++;
            }
        } else if (amount < 0 && outgoing) {
            totalOutgoing++;
        } else if (amount > 0 && incoming) {
            totalIncoming++;
        }
    }

    size_t totalLen = std::to_string(totalFusion).length();
    uint64_t totalCount = totalFusion;
    if (incoming) {
        totalLen = std::max(totalLen, std::to_string(totalIncoming).length());
        totalCount += totalIncoming;
    }

    if (outgoing) {
        totalLen = std::max(totalLen, std::to_string(totalOutgoing).length());
        totalCount += totalOutgoing;
    }

    totalLen = std::max(totalLen, std::to_string(totalCount).length());

    if (incoming) {
        std::cout << std::right << std::setw(20) << InformationMsg("Incoming transfers: ") << std::right << std::setw(totalLen) << SuccessMsg(std::to_string(totalIncoming)) << std::endl;
    }

    if (outgoing) {
        std::cout << std::right << std::setw(20) << InformationMsg("Outgoing transfers: ") << std::right << std::setw(totalLen) << WarningMsg(std::to_string(totalOutgoing)) << std::endl;
    }

    std::cout << std::right << std::setw(20) << InformationMsg("Fusion transfers: ") << std::right << std::setw(totalLen) << InformationMsg(std::to_string(totalFusion)) << std::endl;
    std::cout << Common::repeatChar(20 + totalLen, '-') << std::endl;
    std::cout << std::right << std::setw(20) << InformationMsg("Total transfers: ") << std::right << std::setw(totalLen) << InformationMsg(std::to_string(totalCount)) << std::endl;
}

void checkForNewTransactions(std::shared_ptr<WalletInfo> &walletInfo) {
    hidecursor();
    walletInfo->wallet.updateInternalCache();

    size_t newTransactionCount = walletInfo->wallet.getTransactionCount();

    if (newTransactionCount != walletInfo->knownTransactionCount) {
        for (size_t i = walletInfo->knownTransactionCount; i < newTransactionCount; i++) {
            CryptoNote::WalletTransaction t = walletInfo->wallet.getTransaction(i);

            /* Don't print outgoing or fusion transfers */
            if (t.totalAmount > 0) {
                Common::Console::clearLine();
                std::cout << "\r"
                          << InformationMsg("New incoming transaction!") << std::endl;
                if (walletInfo->wallet.getAddressCount() > 1) {
                    printIncomingAddresses(walletInfo, t, 13);
                }
                std::cout << std::left << std::setw(13) << SuccessMsg("Hash: ") << std::setw(64) << SuccessMsg(Common::podToHex(t.hash)) << std::endl
                          << std::left << std::setw(13) << SuccessMsg("Amount: ") << std::setw(0) << SuccessMsg(formatAmount(t.totalAmount)) << std::endl;

                Crypto::Hash paymentId;
                std::vector<uint8_t> vec(t.extra.begin(), t.extra.end());
                if (CryptoNote::getPaymentIdFromTxExtra(vec, paymentId)) {
                    std::cout << std::left << std::setw(13) << SuccessMsg("Payment ID: ") << std::setw(64) << SuccessMsg(Common::podToHex(paymentId)) << std::endl;
                }
                std::cout << std::endl;
                std::cout << getPrompt(walletInfo) << std::flush;
            }
        }

        walletInfo->knownTransactionCount = newTransactionCount;
    }
    showcursor();
}

void reset(CryptoNote::INode &node, std::shared_ptr<WalletInfo> &walletInfo) {
    std::cout << InformationMsg("Resetting wallet...") << std::endl;

    walletInfo->knownTransactionCount = 0;

    /* Wallet is now uninitialized. You must reinit with load, initWithKeys, or whatever.
       This function wipes the cache, then saves the wallet. */
    walletInfo->wallet.clearCacheAndShutdown();

    /* Now, we reopen the wallet. It now has no cached tx's, and balance */
    walletInfo->wallet.load(walletInfo->walletFileName, walletInfo->walletPass);

    /* Now we rescan the chain to re-discover our balance and transactions */
    findNewTransactions(node, walletInfo);
}

void changePassword(std::shared_ptr<WalletInfo> &walletInfo, std::vector<std::string> args) {
    std::string oldPassword, newPassword;
    if (args.size() > 2) {
        std::cout << WarningMsg("Usage: change_password <old_password> <new_password>") << std::endl;
        return;
    }
    if (args.size() == 0) {
        if (walletInfo->walletPass != "") {
            std::string tmpPassword = walletInfo->walletPass;
            Tools::PasswordContainer pwdContainer(std::move(tmpPassword));
            if (!pwdContainer.read_and_validate("Enter old password: ")) {
                std::cout << WarningMsg("Incorrect password!") << std::endl;
                return;
            }
            oldPassword = pwdContainer.password();
        }
    } else {
        if (args[0] != walletInfo->walletPass) {
            std::cout << WarningMsg("Old password doesn't match!") << std::endl;
            return;
        }
        oldPassword = args[0];
    }
    if (args.size() < 2) {
        Tools::PasswordContainer pwdContainer;
        if (!pwdContainer.read_password(true, "Enter new password: ")) {
            std::cout << WarningMsg("Aborted!") << std::endl;
            return;
        }
        newPassword = pwdContainer.password();
    } else {
        newPassword = args[1];
    }
    try {
        walletInfo->wallet.changePassword(oldPassword, newPassword);
        walletInfo->wallet.save();
        walletInfo->walletPass = newPassword;
        std::cout << SuccessMsg("Password changed.") << std::endl;
   } catch (std::exception&) {
        std::cout << WarningMsg("Password change failed.") << std::endl;
   }
}

void estimateFusion(std::shared_ptr<WalletInfo> &walletInfo) {
    std::vector<std::string> addresses;
    std::string address = walletInfo->wallet.getAddress(subWallet);
    addresses.push_back(address);
    walletInfo->wallet.updateInternalCache();
    auto result = walletInfo->wallet.estimate(getTotalActualBalance(walletInfo->wallet, addresses), addresses);
    size_t totalLen = std::to_string(result.totalOutputCount).length(); // Total output count is always the widest string
    std::cout << std::setw(21) << "Optimizable outputs: " << std::right << std::setw(totalLen) << InformationMsg(std::to_string(result.fusionReadyCount)) << std::endl
              << std::setw(21) << "Total outputs: " << std::right << std::setw(totalLen) << InformationMsg(std::to_string(result.totalOutputCount)) << std::endl;
}

void findNewTransactions(CryptoNote::INode &node, std::shared_ptr<WalletInfo> &walletInfo) {
    uint32_t localHeight = node.getLastLocalBlockHeight();
    uint32_t walletHeight = walletInfo->wallet.getBlockCount();
    uint32_t remoteHeight = node.getLastKnownBlockHeight();

    size_t transactionCount = walletInfo->wallet.getTransactionCount();

    int stuckCounter = 0;

    if (localHeight != remoteHeight) {
        std::cout << "Your " << CryptoNote::CRYPTONOTE_NAME << "d isn't fully synced yet!" << std::endl
                  << "Until you are fully synced, you won't be able to send transactions," << std::endl
                  << "and your balance may be missing or incorrect!" << std::endl
                  << std::endl;
    }

    /* If we open a legacy wallet then it will load the transactions but not
       have the walletHeight == transaction height. Lets just throw away the
       transactions and rescan. */
    if (walletHeight == 1 && transactionCount != 0) {
        std::cout << "Upgrading your wallet from an older version of the software..." << std::endl
                  << "Unfortunately, we have to rescan the chain to find your transactions." << std::endl;
        transactionCount = 0;
        walletInfo->wallet.clearCaches(true, false);
    }

    if (walletHeight == 1) {
        std::cout << "Scanning through the blockchain to find transactions that belong to you." << std::endl
                  << "Please wait, this will take some time." << std::endl
                  << std::endl;
    } else {
        std::cout << "Scanning through the blockchain to find any new transactions you received" << std::endl
                  << "whilst your wallet wasn't open." << std::endl
                  << "Please wait, this may take some time." << std::endl
                  << std::endl;
    }

    hidecursor();

    while (walletHeight < localHeight) {
        int counter = 1;

        /* This MUST be called on the main thread! */
        walletInfo->wallet.updateInternalCache();

        localHeight = node.getLastLocalBlockHeight();
        remoteHeight = node.getLastKnownBlockHeight();
        Common::Console::clearLine();
        std::cout << "\r" << SuccessMsg(std::to_string(walletHeight))
                  << " of " << InformationMsg(std::to_string(localHeight))
                  << std::flush;

        uint32_t tmpWalletHeight = walletInfo->wallet.getBlockCount();

        int waitSeconds = 1;

        /* Save periodically so if someone closes before completion they don't
           lose all their progress */
        if (counter % 60 == 0) {
            walletInfo->wallet.save();
        }

        if (tmpWalletHeight == walletHeight) {
            stuckCounter++;
            waitSeconds = 3;

            if (stuckCounter > 20) {
                std::string warning =
                    "Syncing may be stuck. Try restarting " + std::string(CryptoNote::CRYPTONOTE_NAME) + "d.\n"
                    "If this persists, visit https://bitcointalk.org/index.php?topic=5195073 for support.";
                std::cout << WarningMsg(warning) << std::endl;
            } else if (stuckCounter > 19) {
                /*
                   Calling save has the side-effect of starting and stopping blockchainSynchronizer, which seems
                   to sometimes force the sync to resume properly. So we'll try this before warning the user.
                */
                std::cout << InformationMsg("Saving wallet...") << std::endl;
                walletInfo->wallet.save();
                waitSeconds = 5;
            }
        } else {
            stuckCounter = 0;
            walletHeight = tmpWalletHeight;

            size_t tmpTransactionCount = walletInfo->wallet.getTransactionCount();

            if (tmpTransactionCount != transactionCount) {
                for (size_t i = transactionCount; i < tmpTransactionCount; i++) {
                    CryptoNote::WalletTransaction t = walletInfo->wallet.getTransaction(i);

                    /* Don't print out fusion transactions */
                    if (t.totalAmount != 0) {
                        std::cout << "\r"
                                  << InformationMsg("New transaction found!") << std::endl;

                        if (t.totalAmount < 0) {
                            printOutgoingTransfer(t, node, walletInfo->wallet, true);
                        } else {
                            printIncomingTransfer(t, node, walletInfo->wallet, true);
                        }
                    }
                }

                transactionCount = tmpTransactionCount;
            }
        }

        counter++;

        std::this_thread::sleep_for(std::chrono::seconds(waitSeconds));
    }

    std::cout << "\r"
              << SuccessMsg("Finished scanning blockchain!") << std::endl
              << std::endl;

    showcursor();

    /* In case the user force closes, we don't want them to have to rescan the whole chain. */
    walletInfo->wallet.save();

    walletInfo->knownTransactionCount = transactionCount;
}

ColouredMsg getPrompt(std::shared_ptr<WalletInfo> &walletInfo) {
    const int promptLength = 20;
    const std::string extension = ".wallet";

    std::string walletName = walletInfo->walletFileName;

    /* Filename ends in .wallet, remove extension */
    if (std::equal(extension.rbegin(), extension.rend(), walletInfo->walletFileName.rbegin())) {
        size_t extPos = walletInfo->walletFileName.find_last_of('.');

        walletName = walletInfo->walletFileName.substr(0, extPos);
    }

    std::string shortName = walletName;
    size_t pos;

    if ((pos = shortName.rfind("\\")) != std::string::npos) {
      shortName = shortName.substr(pos + 1, promptLength);
    } else if ((pos = shortName.rfind("/")) != std::string::npos) {
      shortName = shortName.substr(pos + 1, promptLength);
    } else if (shortName.length() > promptLength) {
      shortName = shortName.substr(0, promptLength);
    }
    if (walletInfo->wallet.getAddressCount() > 1) {
      shortName += " " + std::to_string(subWallet) + "/" + std::to_string(walletInfo->wallet.getAddressCount() - 1);
    }

    return InformationMsg("[" + std::string(CryptoNote::CRYPTONOTE_TICKER) + " " + shortName + "]: ");
}

void connectingMsg() {
    std::cout << std::endl
              << "Making initial contact with " << CryptoNote::CRYPTONOTE_NAME << "d." << std::endl
              << "Please wait, this sometimes can take a long time..." << std::endl
              << std::endl;
}

void viewWalletMsg() {
    std::cout << InformationMsg("Please remember that when using a view wallet you can only view incoming transactions!") << std::endl
              << "This means if you received 100 " << CryptoNote::CRYPTONOTE_TICKER << " and then sent 50 " << CryptoNote::CRYPTONOTE_TICKER << ", "
              << "your balance would appear to still be 100 " << CryptoNote::CRYPTONOTE_TICKER << "." << std::endl
              << "To effectively use a view wallet, you should only deposit to this wallet." << std::endl
              << "If you have since needed to withdraw, send your remaining balance to a new wallet, and import this as a new view wallet so your balance can be correctly observed." << std::endl
              << std::endl;
}

//----------------------------------------------------------------------------------------------------
bool processServerFeeAddressResponse(const std::string& response, std::string& fee_address) {
    try {
        std::stringstream stream(response);
        Common::JsonValue json;
        stream >> json;

        auto rootIt = json.getObject().find("fee_address");
        if (rootIt == json.getObject().end()) {
            return false;
        }

        fee_address = rootIt->second.getString();
    } catch (std::exception&) {
        return false;
    }

    return true;
}

//----------------------------------------------------------------------------------------------------
std::string getFeeAddress(System::Dispatcher& dispatcher, std::string daemon_host, uint16_t daemon_port, std::string daemon_path, bool use_ssl) {
    CryptoNote::HttpClient httpClient(dispatcher, daemon_host, daemon_port, use_ssl);
    CryptoNote::HttpRequest req;
    CryptoNote::HttpResponse res;

    req.setUrl(daemon_path + "feeaddress");

    try {
        httpClient.request(req, res);
    } catch (const std::exception& e) {
        std::string errorMsg = e.what();
        std::cout << WarningMsg("Error connecting to the remote node: " + errorMsg) << std::endl;
    }

    if (res.getStatus() != CryptoNote::HttpResponse::STATUS_200) {
        std::cout << WarningMsg("Remote node returned code " + std::to_string(res.getStatus())) << std::endl;
    }

    std::string address;
    if (!processServerFeeAddressResponse(res.getBody(), address)) {
        std::cout << WarningMsg("Failed to parse remote node response") << std::endl;
    }

    return address;
}
