// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2023, The Talleo developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#pragma once
#include <cstdint>
#include <list>

namespace CryptoNote {

typedef std::list<std::pair<IBlockchainCache *, uint32_t>> altChainList;

class ICoreInformation {
public:
#if defined(WIN32)
  virtual ~ICoreInformation() noexcept(false) {}
#else
  virtual ~ICoreInformation() {}
#endif

  virtual size_t getPoolTransactionCount() const = 0;
  virtual size_t getBlockchainTransactionCount() const = 0;
  virtual altChainList getAlternateChains() const = 0;
  virtual size_t getAlternativeBlockCount() const = 0;
  virtual uint64_t getTotalGeneratedAmount() const = 0;
  virtual std::vector<BlockTemplate> getAlternativeBlocks() const = 0;
  virtual bool hasPoolTransaction(const Crypto::Hash& transactionHash) const = 0;
  virtual bool getPoolTransaction(const Crypto::Hash& transactionHash, Transaction& transaction) const = 0;
  virtual std::vector<Transaction> getPoolTransactions() const = 0;
};

}
