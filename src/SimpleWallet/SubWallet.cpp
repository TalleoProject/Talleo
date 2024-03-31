/*
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

#include "SubWallet.h"

uint64_t getTotalActualBalance(CryptoNote::WalletGreen &wallet) {
    uint64_t balance = 0;
    size_t numWallets = wallet.getAddressCount();
    for (size_t i = 0; i < numWallets; i++) {
        std::string address = wallet.getAddress(i);
        balance += wallet.getActualBalance(address);
    }
    return balance;
}

uint64_t getTotalActualBalance(CryptoNote::WalletGreen &wallet, const std::vector<std::string> &addresses) {
    uint64_t balance = 0;
    for (auto address : addresses) {
        balance += wallet.getActualBalance(address);
    }
    return balance;
}

uint64_t getTotalPendingBalance(CryptoNote::WalletGreen &wallet) {
    uint64_t balance = 0;
    size_t numWallets = wallet.getAddressCount();
    for (size_t i = 0; i < numWallets; i++) {
        std::string address = wallet.getAddress(i);
        balance += wallet.getPendingBalance(address);
    }
    return balance;
}

uint64_t getTotalPendingBalance(CryptoNote::WalletGreen &wallet, const std::vector<std::string> &addresses) {
    uint64_t balance = 0;
    for (auto address: addresses) {
        balance += wallet.getPendingBalance(address);
    }
    return balance;
}
