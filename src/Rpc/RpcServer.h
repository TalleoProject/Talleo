// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2018, The Bittorium developers
// Copyright (c) 2020-2025, The Talleo developers
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

#include "HttpServer.h"

#include <functional>
#include <unordered_map>

#include <Logging/LoggerRef.h>
#include "Common/Math.h"
#include "CoreRpcServerCommandsDefinitions.h"
#include "JsonRpc.h"

namespace CryptoNote {

class Core;
class NodeServer;
struct ICryptoNoteProtocolHandler;

class RpcServer : public HttpServer {
public:
  RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, Core& c, NodeServer& p2p, ICryptoNoteProtocolHandler& protocol);

  typedef std::function<bool(RpcServer*, const HttpRequest& request, HttpResponse& response)> HandlerFunction;
  bool enableCors(const std::vector<std::string>  domains);
  std::vector<std::string> getCorsDomains();

  bool setFeeAddress(const std::string& fee_address, const AccountPublicAddress& fee_acc);
  bool setViewKey(const std::string& view_key);
  bool setCollateralHash(const std::string& collateral_hash);
  bool masternode_check_incoming_tx(const BinaryArray& tx_blob);

  bool onGetBlockHeadersRange(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, JsonRpc::JsonRpcError& error_resp);
  bool onGetAlternateChains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res);

private:

  template <class Handler>
  struct RpcHandler {
    const Handler handler;
    const bool allowBusyCore;
  };

  typedef void (RpcServer::*HandlerPtr)(const HttpRequest& request, HttpResponse& response);
  static std::unordered_map<std::string, RpcHandler<HandlerFunction>> s_handlers;

  virtual void processRequest(const HttpRequest& request, HttpResponse& response) override;
  bool processJsonRpcRequest(const HttpRequest& request, HttpResponse& response);
  bool isCoreReady();
  bool verifyCollateral();

  // binary handlers
  bool onGetBlocksBin(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res);
  bool onQueryBlocksBin(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res);
  bool onQueryBlocksLiteBin(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res);
  bool onGetIndexesBin(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res);
  bool onGetRandomOutsBin(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res);
  bool onGetPoolChangesBin(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& res);
  bool onGetPoolChangesLiteBin(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& res);
  bool onGetBlocksDetailsByHashesBin(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::response& res);
  bool onGetBlockDetailsByHeightBin(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response& res);
  bool onGetBlocksHashesByTimestampsBin(const COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::request& req, COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::response& res);
  bool onGetTransactionDetailsByHashesBin(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES::response& res);
  bool onGetTransactionHashesByPaymentIdBin(const COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response& res);

  // json handlers
  bool onGetInfo(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res);
  bool onGetHeight(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res);
  bool onGetTransactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res);
  bool onSendRawTx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res);
  bool onStopDaemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res);
  bool onGetPeers(const COMMAND_RPC_GET_PEERS::request& req, COMMAND_RPC_GET_PEERS::response& res);
  bool onGetPeersGray(const COMMAND_RPC_GET_PEERSGRAY::request& req, COMMAND_RPC_GET_PEERSGRAY::response& res);
  bool onGetIssued(const COMMAND_RPC_GET_ISSUED_COINS::request& req, COMMAND_RPC_GET_ISSUED_COINS::response& res);
  bool onGetTotal(const COMMAND_RPC_GET_TOTAL_COINS::request& req, COMMAND_RPC_GET_TOTAL_COINS::response& res);
  bool onGetFeeAddress(const COMMAND_RPC_GET_FEE_ADDRESS::request& req, COMMAND_RPC_GET_FEE_ADDRESS::response& res);
  bool onGetTransactionOutAmountsForAccount(const COMMAND_RPC_GET_TRANSACTION_OUT_AMOUNTS_FOR_ACCOUNT::request& req, COMMAND_RPC_GET_TRANSACTION_OUT_AMOUNTS_FOR_ACCOUNT::response& res);
  bool onGetCollateralHash(const COMMAND_RPC_GET_COLLATERAL_HASH::request& req, COMMAND_RPC_GET_COLLATERAL_HASH::response& res);

  // json rpc
  bool onGetBlockCount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res);
  bool onGetBlockHash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res);
  bool onGetBlockTemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res);
  bool onGetCurrencyId(const COMMAND_RPC_GET_CURRENCY_ID::request& req, COMMAND_RPC_GET_CURRENCY_ID::response& res);
  bool onSubmitBlock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res);
  bool onGetLastBlockHeader(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res);
  bool onGetBlockHashesByPaymentId(const COMMAND_RPC_GET_BLOCK_HASHES_BY_PAYMENT_ID_JSON::request& req, COMMAND_RPC_GET_BLOCK_HASHES_BY_PAYMENT_ID_JSON::response& res);
  bool onGetBlockHashesByTransactionHashes(const COMMAND_RPC_GET_BLOCK_HASHES_BY_TRANSACTION_HASHES::request& req, COMMAND_RPC_GET_BLOCK_HASHES_BY_TRANSACTION_HASHES::response& res);
  bool onGetBlockHeaderByHash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res);
  bool onGetBlockHeaderByHeight(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res);
  bool onGetBlockIndexesByTransactionHashes(const COMMAND_RPC_GET_BLOCK_INDEXES_BY_TRANSACTION_HASHES::request& req, COMMAND_RPC_GET_BLOCK_INDEXES_BY_TRANSACTION_HASHES::response& res);
  bool onGetBlocksDetailsByHashes(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES_JSON::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES_JSON::response& res);
  bool onGetTransactionDetailsByHashes(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES_JSON::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASHES_JSON::response& res);
  bool onGetTransactionHashesByPaymentId(const COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID_JSON::request& req, COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID_JSON::response& res);

  void fillBlockHeaderResponse(const BlockTemplate& blk, bool orphan_status, uint32_t index, const Crypto::Hash& hash, block_header_response& responce);
  RawBlockLegacy prepareRawBlockLegacy(BinaryArray&& blockBlob);

  bool f_on_blocks_list_json(const F_COMMAND_RPC_GET_BLOCKS_LIST::request& req, F_COMMAND_RPC_GET_BLOCKS_LIST::response& res);
  bool f_on_block_json(const F_COMMAND_RPC_GET_BLOCK_DETAILS::request& req, F_COMMAND_RPC_GET_BLOCK_DETAILS::response& res);
  bool f_on_transaction_json(const F_COMMAND_RPC_GET_TRANSACTION_DETAILS::request& req, F_COMMAND_RPC_GET_TRANSACTION_DETAILS::response& res);
  bool f_on_pool_transaction_json(const F_COMMAND_RPC_GET_TRANSACTION_DETAILS::request& req, F_COMMAND_RPC_GET_TRANSACTION_DETAILS::response& res);
  bool f_on_transactions_pool_json(const F_COMMAND_RPC_GET_POOL::request& req, F_COMMAND_RPC_GET_POOL::response& res);
  bool f_getMixin(const Transaction& transaction, uint64_t& mixin);

  bool populateTransactionDetails(const Crypto::Hash& Hash, F_COMMAND_RPC_GET_TRANSACTION_DETAILS::response& res);

  Logging::LoggerRef logger;
  Core& m_core;
  NodeServer& m_p2p;
  ICryptoNoteProtocolHandler& m_protocol;
  std::vector<std::string> m_cors_domains;
  std::string m_fee_address;
  Crypto::SecretKey m_view_key = NULL_SECRET_KEY;
  Crypto::Hash m_collateral_hash = NULL_HASH;
  AccountPublicAddress m_fee_acc;
};

}
