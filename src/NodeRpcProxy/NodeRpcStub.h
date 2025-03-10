// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2022, The Talleo developers
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

#include "INode.h"

namespace CryptoNote {

	class NodeRpcStub : public INode {
	public:
		virtual ~NodeRpcStub();
		virtual bool addObserver(INodeObserver* observer) override;
		virtual bool removeObserver(INodeObserver* observer) override;

		virtual void init(const Callback& callback) override;
		virtual bool shutdown() override;

		virtual size_t getPeerCount() const override;
		virtual uint32_t getLastLocalBlockHeight() const override;
		virtual uint32_t getLastKnownBlockHeight() const override;
		virtual uint32_t getLocalBlockCount() const override;
		virtual uint32_t getKnownBlockCount() const override;
		virtual uint64_t getLastLocalBlockTimestamp() const override;
		virtual std::string getLastFeeAddress() const override;
		virtual std::string getLastCollateralHash() const override;

		virtual void getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount, std::vector<Crypto::Hash>& blockHashes, const Callback& callback) override;

		virtual void getTransactionHashesByPaymentId(const Crypto::Hash& paymentId, std::vector<Crypto::Hash>& transactionHashes, const Callback& callback) override;

		virtual BlockHeaderInfo getLastLocalBlockHeaderInfo() const override;

		virtual void relayTransaction(const Transaction& transaction, const Callback& callback) override;
		virtual void getRandomOutsByAmounts(std::vector<uint64_t>&& amounts, uint16_t outsCount,
			std::vector<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount>& result, const Callback& callback) override;
		virtual void getNewBlocks(std::vector<Crypto::Hash>&& knownBlockIds, std::vector<RawBlock>& newBlocks, uint32_t& startHeight, const Callback& callback) override;
		virtual void getTransactionOutsGlobalIndices(const Crypto::Hash& transactionHash, std::vector<uint32_t>& outsGlobalIndices, const Callback& callback) override;

		virtual void queryBlocks(std::vector<Crypto::Hash>&& knownBlockIds, uint64_t timestamp, std::vector<BlockShortEntry>& newBlocks,
			uint32_t& startHeight, const Callback& callback) override;

		virtual void getPoolSymmetricDifference(std::vector<Crypto::Hash>&& knownPoolTxIds, Crypto::Hash knownBlockId, bool& isBcActual,
			std::vector<std::unique_ptr<ITransactionReader>>& newTxs, std::vector<Crypto::Hash>& deletedTxIds, const Callback& callback) override;

		virtual void getBlocks(const std::vector<uint32_t>& blockHeights, std::vector<std::vector<BlockDetails>>& blocks, const Callback& callback) override;

		virtual void getBlocks(const std::vector<Crypto::Hash>& blockHashes, std::vector<BlockDetails>& blocks, const Callback& callback) override;

		virtual void getBlock(const uint32_t blockHeight, BlockDetails &block, const Callback& callback) override;

		virtual void getTransactions(const std::vector<Crypto::Hash>& transactionHashes, std::vector<TransactionDetails>& transactions, const Callback& callback) override;

		virtual void getFeeAddress(std::string& feeAddress, const Callback& callback) override;

		virtual void getCollateralHash(std::string& collateralHash, const Callback& callback) override;

		virtual void isSynchronized(bool& syncStatus, const Callback& callback) override;

		virtual void setRootCert(const std::string &path) override;
		virtual void disableVerify() override;

	};

};