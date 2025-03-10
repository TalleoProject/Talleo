/*
Copyright (C) 2018, The TurtleCoin developers
Copyright (C) 2018, The PinkstarcoinV2 developers
Copyright (C) 2018, The Bittorium developers
Copyright (C) 2018, The Karbo developers
Copyright (C) 2020-2024, The Talleo developers

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

#ifdef _WIN32
/* Prevents windows.h redefining min/max which breaks compilation */
#define NOMINMAX
#include <windows.h>
#endif

#include <cctype>
#include <future>

#include "INode.h"
#include "version.h"
#include "CryptoNote.h"

#include <Common/ConsoleHandler.h>
#include <Common/PasswordContainer.h>
#include <Common/SignalHandler.h>

#include <CryptoNoteCore/Account.h>
#include <CryptoNoteCore/CryptoNoteBasicImpl.h>
#include <CryptoNoteCore/Currency.h>

#include <Logging/FileLogger.h>
#include <Logging/LoggerManager.h>

#include <Mnemonics/electrum-words.h>

#include <NodeRpcProxy/NodeRpcProxy.h>

#include <SimpleWallet/Transfer.h>
#include <SimpleWallet/ParseArguments.h>

#include <System/Dispatcher.h>

#include <Wallet/WalletGreen.h>

#include <boost/thread/thread.hpp>

enum Action {Open, Generate, Import, SeedImport, ViewWallet};

Action getAction(Config &config);

void logIncorrectMnemonicWords(std::vector<std::string> words);

void promptSaveKeys(CryptoNote::WalletGreen &wallet);

void printPrivateKeys(CryptoNote::WalletGreen &wallet, bool viewWallet);

void balance(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet, bool viewWallet);

void balances(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet, bool viewWallet);

void welcomeMsg();

void help(bool viewWallet);

void inputLoop(System::Dispatcher& dispatcher, std::shared_ptr<WalletInfo> &walletInfo, CryptoNote::INode &node);

void exportKeys(std::shared_ptr<WalletInfo> &walletInfo);

void run(System::Dispatcher& dispatcher, CryptoNote::WalletGreen &wallet, CryptoNote::INode &node, Config &config);

void blockchainHeight(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet);

void listOutputs(CryptoNote::WalletGreen &wallet, CryptoNote::INode &node);

void addAddress(CryptoNote::WalletGreen &wallet);

void deleteAddress(CryptoNote::WalletGreen &wallet);

void deleteAddress(CryptoNote::WalletGreen &wallet, std::vector<std::string> args);

void listAddresses(CryptoNote::WalletGreen &wallet);

void recoverAddress(std::shared_ptr<WalletInfo> &walletInfo, CryptoNote::INode &node);

void recoverAddress(std::shared_ptr<WalletInfo> &walletInfo, CryptoNote::INode &node, std::vector<std::string> args);

void selectAddress(CryptoNote::WalletGreen &wallet);

void selectAddress(CryptoNote::WalletGreen &wallet, std::vector<std::string> args);

void listTransfer(std::vector<std::string> args, CryptoNote::WalletGreen &wallet, CryptoNote::INode &node);

void listTransfers(bool incoming, bool outgoing, CryptoNote::WalletGreen &wallet, CryptoNote::INode &node);

void countTransfers(bool incoming, bool outgoing, CryptoNote::WalletGreen &wallet, CryptoNote::INode &node);

void estimateFusion(std::shared_ptr<WalletInfo> &walletInfo);

void findNewTransactions(CryptoNote::INode &node, std::shared_ptr<WalletInfo> &walletInfo);

void repair(CryptoNote::WalletGreen &wallet);

void reset(CryptoNote::INode &node, std::shared_ptr<WalletInfo> &walletInfo);

void changePassword(std::shared_ptr<WalletInfo> &walletInfo, std::vector<std::string> args);

void printOutgoingTransfer(const CryptoNote::WalletTransaction &t, CryptoNote::INode &node, CryptoNote::WalletGreen &wallet, bool allAddresses);

void printIncomingTransfer(const CryptoNote::WalletTransaction &t, CryptoNote::INode &node, CryptoNote::WalletGreen &wallet, bool allAddresses);

void checkForNewTransactions(std::shared_ptr<WalletInfo> &walletInfo);

void checkForUnoptimizedOutputs(std::shared_ptr<WalletInfo> &walletInfo);

void confirmPassword(std::string);

void connectingMsg();

void viewWalletMsg();

bool isValidMnemonic(std::string &mnemonic_phrase, Crypto::SecretKey &private_spend_key);

bool shutdown(CryptoNote::WalletGreen &wallet, CryptoNote::INode &node, bool &alreadyShuttingDown);

std::string getInputAndDoWorkWhileIdle(std::shared_ptr<WalletInfo> &walletInfo);

std::string getNewWalletFileName();

std::string getExistingWalletFileName(Config &config);

std::string getWalletPassword(bool verifyPwd);

std::string getBlockTime(CryptoNote::BlockDetails b);

std::shared_ptr<WalletInfo> importFromKeys(CryptoNote::WalletGreen &wallet, Crypto::SecretKey privateSpendKey, Crypto::SecretKey privateViewKey);

Maybe<std::shared_ptr<WalletInfo>> openWallet(CryptoNote::WalletGreen &wallet, Config &config);

std::shared_ptr<WalletInfo> importWallet(CryptoNote::WalletGreen &wallet);

std::shared_ptr<WalletInfo> createViewWallet(CryptoNote::WalletGreen &wallet);

std::shared_ptr<WalletInfo> mnemonicImportWallet(CryptoNote::WalletGreen &wallet);

std::shared_ptr<WalletInfo> generateWallet(CryptoNote::WalletGreen &wallet);

Maybe<std::shared_ptr<WalletInfo>> handleAction(CryptoNote::WalletGreen &wallet, Action action, Config &config);

Crypto::SecretKey getPrivateKey(std::string outputMsg);

ColouredMsg getPrompt(std::shared_ptr<WalletInfo> &walletInfo);

CryptoNote::BlockDetails getBlock(uint32_t blockHeight, CryptoNote::INode &node);

std::string getFeeAddress(System::Dispatcher& dispatcher, std::string daemon_host, uint16_t daemon_port, std::string daemon_path, bool use_ssl);
