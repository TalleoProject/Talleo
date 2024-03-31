/*
Copyright (C) 2018, The TurtleCoin developers
Copyright (C) 2018, The PinkstarcoinV2 developers
Copyright (C) 2018, The Bittorium developers
Copyright (C) 2021-2024, The Talleo developers

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

#include <string>

#include "CryptoNoteConfig.h"
#include "IWallet.h"

#include <CryptoNoteCore/TransactionExtra.h>
#include <CryptoNoteCore/CryptoNoteBasicImpl.h>

#include <SimpleWallet/Tools.h>

#include <Wallet/WalletGreen.h>

struct WalletInfo {
    WalletInfo(std::string walletFileName,
               std::string walletPass,
               std::string walletAddress,
               bool viewWallet,
               CryptoNote::WalletGreen &wallet) :
               walletFileName(walletFileName),
               walletPass(walletPass),
               walletAddress(walletAddress),
               viewWallet(viewWallet),
               wallet(wallet) {}

    size_t knownTransactionCount = 0;

    std::string walletFileName;
    std::string walletPass;
    std::string walletAddress;

    bool viewWallet;

    CryptoNote::WalletGreen &wallet;
};

void transfer(System::Dispatcher& dispatcher, std::shared_ptr<WalletInfo> walletInfo);

void transfer(System::Dispatcher& dispatcher, std::shared_ptr<WalletInfo> walletInfo,
              std::vector<std::string> args);

void doTransfer(System::Dispatcher& dispatcher, uint16_t mixin, const std::vector<std::string> &sourceAddresses,
                std::string address, uint64_t amount, uint64_t fee, const std::string &extra,
                std::shared_ptr<WalletInfo> walletInfo);

void fusionTX(CryptoNote::WalletGreen &wallet,
              CryptoNote::TransactionParameters p);

void sendMultipleTransactions(System::Dispatcher& dispatcher, CryptoNote::WalletGreen &wallet,
                              std::vector<CryptoNote::TransactionParameters>
                              transfers);

void splitTx(CryptoNote::WalletGreen &wallet,
             CryptoNote::TransactionParameters p);

void quickOptimize(CryptoNote::WalletGreen &wallet);

void fullOptimize(CryptoNote::WalletGreen &wallet);

void consolidate(CryptoNote::WalletGreen &wallet);

bool confirmTransaction(CryptoNote::TransactionParameters t,
                        std::shared_ptr<WalletInfo> walletInfo);

bool optimize(CryptoNote::WalletGreen &wallet, const std::vector<std::string> &addresses, uint64_t threshold);

bool optimize(CryptoNote::WalletGreen &wallet, const std::vector<std::string> &sourceAddresses,
              const std::string &destinationAddress, uint64_t threshold);

bool parseAmount(std::string amountString);

bool parseMixin(std::string mixinString);

bool parseAddress(std::string address);

bool parseFee(std::string feeString);

Maybe<std::string> getPaymentID();

Maybe<std::string> getDestinationAddress(System::Dispatcher& dispatcher);

Maybe<uint64_t> getFee();

Maybe<uint64_t> getTransferAmount();

Maybe<uint16_t> getMixin();

size_t makeFusionTransaction(CryptoNote::WalletGreen &wallet, const std::vector<std::string> &sourceAddresses,
                             const std::string &destinationAddress, uint64_t threshold);

std::string resolveAddress(System::Dispatcher& dispatcher, const std::string& email);
