// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2022, Karbo developers
// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019, The Cash2 developers
// Copyright (c) 2021-2023, The Talleo developers
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

#include "WalletService.h"


#include <future>
#include <assert.h>
#include <sstream>
#include <unordered_set>

#include <boost/filesystem/operations.hpp>

#include <System/Timer.h>
#include <System/InterruptedException.h>
#include "Common/Util.h"

#include "crypto/crypto.h"
#include "CryptoNote.h"
#include "version.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/Account.h"

#include <System/EventLock.h>
#include <System/RemoteContext.h>

#include "PaymentServiceJsonRpcMessages.h"
#include "NodeFactory.h"

#include "Wallet/WalletGreen.h"
#include "Wallet/LegacyKeysImporter.h"
#include "Wallet/WalletErrors.h"
#include "Wallet/WalletUtils.h"
#include "WalletServiceErrorCategory.h"

#include "Mnemonics/electrum-words.h"

namespace PaymentService {

namespace {

bool checkPaymentId(const std::string& paymentId) {
  if (paymentId.size() != 64) {
    return false;
  }

  return std::all_of(paymentId.begin(), paymentId.end(), [] (const char c) {
    if (c >= '0' && c <= '9') {
      return true;
    }

    if (c >= 'a' && c <= 'f') {
      return true;
    }

    if (c >= 'A' && c <= 'F') {
      return true;
    }

    return false;
  });
}

Crypto::Hash parsePaymentId(const std::string& paymentIdStr) {
  if (!checkPaymentId(paymentIdStr)) {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_PAYMENT_ID_FORMAT));
  }

  Crypto::Hash paymentId;
  bool r = Common::podFromHex(paymentIdStr, paymentId);
  if (r) {}
  assert(r);

  return paymentId;
}

bool getPaymentIdFromExtra(const std::string& binaryString, Crypto::Hash& paymentId) {
  return CryptoNote::getPaymentIdFromTxExtra(Common::asBinaryArray(binaryString), paymentId);
}

std::string getPaymentIdStringFromExtra(const std::string& binaryString) {
  Crypto::Hash paymentId;

  try {
    if (!getPaymentIdFromExtra(binaryString, paymentId)) {
      return std::string();
    }
  } catch (std::exception&) {
    return std::string();
  }

  return Common::podToHex(paymentId);
}

}

struct TransactionsInBlockInfoFilter {
  TransactionsInBlockInfoFilter(const std::vector<std::string>& addressesVec, const std::string& paymentIdStr) {
    addresses.insert(addressesVec.begin(), addressesVec.end());

    if (!paymentIdStr.empty()) {
      paymentId = parsePaymentId(paymentIdStr);
      havePaymentId = true;
    } else {
      havePaymentId = false;
    }
  }

  bool checkTransaction(const CryptoNote::WalletTransactionWithTransfers& transaction) const {
    if (havePaymentId) {
      Crypto::Hash transactionPaymentId;
      if (!getPaymentIdFromExtra(transaction.transaction.extra, transactionPaymentId)) {
        return false;
      }

      if (paymentId != transactionPaymentId) {
        return false;
      }
    }

    if (addresses.empty()) {
      return true;
    }

    bool haveAddress = false;
    for (const CryptoNote::WalletTransfer& transfer: transaction.transfers) {
      if (addresses.find(transfer.address) != addresses.end()) {
        haveAddress = true;
        break;
      }
    }

    return haveAddress;
  }

  std::unordered_set<std::string> addresses;
  bool havePaymentId = false;
  Crypto::Hash paymentId;
};

namespace {

void addPaymentIdToExtra(const std::string& paymentId, std::string& extra) {
  std::vector<uint8_t> extraVector;
  if (!CryptoNote::createTxExtraWithPaymentId(paymentId, extraVector)) {
    throw std::system_error(make_error_code(CryptoNote::error::BAD_PAYMENT_ID));
  }

  std::copy(extraVector.begin(), extraVector.end(), std::back_inserter(extra));
}

void validatePaymentId(const std::string& paymentId, Logging::LoggerRef logger) {
  if (!checkPaymentId(paymentId)) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Can't validate payment id: " << paymentId;
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_PAYMENT_ID_FORMAT));
  }
}

Crypto::Hash parseHash(const std::string& hashString, Logging::LoggerRef logger) {
  Crypto::Hash hash;

  if (!Common::podFromHex(hashString, hash)) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Can't parse hash string " << hashString;
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_HASH_FORMAT));
  }

  return hash;
}

std::vector<CryptoNote::TransactionsInBlockInfo> filterTransactions(
  const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks,
  const TransactionsInBlockInfoFilter& filter) {

  std::vector<CryptoNote::TransactionsInBlockInfo> result;

  for (const auto& block: blocks) {
    CryptoNote::TransactionsInBlockInfo item;
    item.blockHash = block.blockHash;

    for (const auto& transaction: block.transactions) {
      if (transaction.transaction.state != CryptoNote::WalletTransactionState::DELETED && filter.checkTransaction(transaction)) {
        item.transactions.push_back(transaction);
      }
    }

    if (!item.transactions.empty()) {
      result.push_back(std::move(item));
    }
  }

  return result;
}

PaymentService::TransactionRpcInfo convertTransactionWithTransfersToTransactionRpcInfo(
  const CryptoNote::WalletTransactionWithTransfers& transactionWithTransfers) {

  PaymentService::TransactionRpcInfo transactionInfo;

  transactionInfo.state = static_cast<uint8_t>(transactionWithTransfers.transaction.state);
  transactionInfo.transactionHash = Common::podToHex(transactionWithTransfers.transaction.hash);
  transactionInfo.blockIndex = transactionWithTransfers.transaction.blockHeight;
  transactionInfo.timestamp = transactionWithTransfers.transaction.timestamp;
  transactionInfo.isBase = transactionWithTransfers.transaction.isBase;
  transactionInfo.unlockTime = transactionWithTransfers.transaction.unlockTime;
  transactionInfo.amount = transactionWithTransfers.transaction.totalAmount;
  transactionInfo.fee = transactionWithTransfers.transaction.fee;
  transactionInfo.extra = Common::toHex(transactionWithTransfers.transaction.extra.data(), transactionWithTransfers.transaction.extra.size());
  transactionInfo.paymentId = getPaymentIdStringFromExtra(transactionWithTransfers.transaction.extra);

  for (const CryptoNote::WalletTransfer& transfer: transactionWithTransfers.transfers) {
    PaymentService::TransferRpcInfo rpcTransfer;
    rpcTransfer.address = transfer.address;
    rpcTransfer.amount = transfer.amount;
    rpcTransfer.type = static_cast<uint8_t>(transfer.type);

    transactionInfo.transfers.push_back(std::move(rpcTransfer));
  }

  return transactionInfo;
}

std::vector<PaymentService::TransactionsInBlockRpcInfo> convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(
  const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks) {

  std::vector<PaymentService::TransactionsInBlockRpcInfo> rpcBlocks;
  rpcBlocks.reserve(blocks.size());
  for (const auto& block: blocks) {
    PaymentService::TransactionsInBlockRpcInfo rpcBlock;
    rpcBlock.blockHash = Common::podToHex(block.blockHash);

    for (const CryptoNote::WalletTransactionWithTransfers& transactionWithTransfers: block.transactions) {
      PaymentService::TransactionRpcInfo transactionInfo = convertTransactionWithTransfersToTransactionRpcInfo(transactionWithTransfers);
      rpcBlock.transactions.push_back(std::move(transactionInfo));
    }

    rpcBlocks.push_back(std::move(rpcBlock));
  }

  return rpcBlocks;
}

std::vector<PaymentService::TransactionHashesInBlockRpcInfo> convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(
    const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks) {

  std::vector<PaymentService::TransactionHashesInBlockRpcInfo> transactionHashes;
  transactionHashes.reserve(blocks.size());
  for (const CryptoNote::TransactionsInBlockInfo& block: blocks) {
    PaymentService::TransactionHashesInBlockRpcInfo item;
    item.blockHash = Common::podToHex(block.blockHash);

    for (const CryptoNote::WalletTransactionWithTransfers& transaction: block.transactions) {
      item.transactionHashes.emplace_back(Common::podToHex(transaction.transaction.hash));
    }

    transactionHashes.push_back(std::move(item));
  }

  return transactionHashes;
}

void validateAddresses(const std::vector<std::string>& addresses, const CryptoNote::Currency& currency, Logging::LoggerRef logger) {
  for (const auto& address: addresses) {
    if (!CryptoNote::validateAddress(address, currency)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Can't validate address " << address;
      throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
    }
  }
}

std::string getValidatedTransactionExtraString(const std::string& extraString) {
  std::vector<uint8_t> binary;
  if (!Common::fromHex(extraString, binary)) {
    throw std::system_error(make_error_code(CryptoNote::error::BAD_TRANSACTION_EXTRA));
  }

  return Common::asString(binary);
}

std::vector<std::string> collectDestinationAddresses(const std::vector<PaymentService::WalletRpcOrder>& orders) {
  std::vector<std::string> result;

  result.reserve(orders.size());
  for (const auto& order: orders) {
    result.push_back(order.address);
  }

  return result;
}

std::vector<CryptoNote::WalletOrder> convertWalletRpcOrdersToWalletOrders(const std::vector<PaymentService::WalletRpcOrder>& orders) {
  std::vector<CryptoNote::WalletOrder> result;
  result.reserve(orders.size());

  for (const auto& order: orders) {
    result.emplace_back(CryptoNote::WalletOrder {order.address, order.amount});
  }

  return result;
}

}

void generateNewWallet(const CryptoNote::Currency& currency, const WalletConfiguration& conf, Logging::ILogger& logger, System::Dispatcher& dispatcher, CryptoNote::INode& node) {
  Logging::LoggerRef log(logger, "generateNewWallet");

  CryptoNote::IWallet* wallet = new CryptoNote::WalletGreen(dispatcher, currency, node, logger);
  std::unique_ptr<CryptoNote::IWallet> walletGuard(wallet);

  std::string address;
  if (conf.secretSpendKey.empty() && conf.secretViewKey.empty() && conf.mnemonicSeed.empty())
  {
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "Generating new wallet";

    Crypto::SecretKey private_view_key;
    CryptoNote::KeyPair spendKey;

    Crypto::generate_keys(spendKey.publicKey, spendKey.secretKey);
    CryptoNote::AccountBase::generateViewFromSpend(spendKey.secretKey, private_view_key);

    wallet->initializeWithViewKey(conf.walletFile, conf.walletPassword, private_view_key);
    address = wallet->createAddress(spendKey.secretKey);

	  log(Logging::INFO, Logging::BRIGHT_WHITE) << "New wallet is generated. Address: " << address;
  }
  else if (!conf.mnemonicSeed.empty())
  {
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "Attempting to import wallet from mnemonic seed";

    Crypto::SecretKey private_spend_key;
    Crypto::SecretKey private_view_key;

    if (!crypto::ElectrumWords::is_valid_mnemonic(conf.mnemonicSeed, private_spend_key))
    {
      return;
    }

    CryptoNote::AccountBase::generateViewFromSpend(private_spend_key, private_view_key);
    wallet->initializeWithViewKey(conf.walletFile, conf.walletPassword, private_view_key);
    address = wallet->createAddress(private_spend_key);
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "Imported wallet successfully.";
  }
  else
  {
	  if (conf.secretSpendKey.empty() || conf.secretViewKey.empty())
	  {
		  log(Logging::ERROR, Logging::BRIGHT_RED) << "Need both secret spend key and secret view key.";
		  return;
	  }
    else
	  {
		  log(Logging::INFO, Logging::BRIGHT_WHITE) << "Attemping to import wallet from keys";
		  Crypto::Hash private_spend_key_hash;
		  Crypto::Hash private_view_key_hash;
		  size_t size;
		  if (!Common::fromHex(conf.secretSpendKey, &private_spend_key_hash, sizeof(private_spend_key_hash), size) || size != sizeof(private_spend_key_hash)) {
			  log(Logging::ERROR, Logging::BRIGHT_RED) << "Invalid spend key";
			  return;
		  }
		  if (!Common::fromHex(conf.secretViewKey, &private_view_key_hash, sizeof(private_view_key_hash), size) || size != sizeof(private_spend_key_hash)) {
			  log(Logging::ERROR, Logging::BRIGHT_RED) << "Invalid view key";
			  return;
		  }
		  Crypto::SecretKey private_spend_key = *(struct Crypto::SecretKey *) &private_spend_key_hash;
		  Crypto::SecretKey private_view_key = *(struct Crypto::SecretKey *) &private_view_key_hash;

		  wallet->initializeWithViewKey(conf.walletFile, conf.walletPassword, private_view_key);
		  address = wallet->createAddress(private_spend_key);
		  log(Logging::INFO, Logging::BRIGHT_WHITE) << "Imported wallet successfully.";
	  }
  }

  wallet->save(CryptoNote::WalletSaveLevel::SAVE_KEYS_ONLY);
  log(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet is saved";
}

WalletService::WalletService(const CryptoNote::Currency& currency, System::Dispatcher& sys, CryptoNote::INode& node,
  CryptoNote::IWallet& wallet, CryptoNote::IFusionManager& fusionManager, const WalletConfiguration& conf, Logging::ILogger& logger) :
    currency(currency),
    wallet(wallet),
    fusionManager(fusionManager),
    node(node),
    config(conf),
    inited(false),
    logger(logger, "WalletService"),
    dispatcher(sys),
    readyEvent(dispatcher),
    refreshContext(dispatcher)
{
  readyEvent.set();
}

WalletService::~WalletService() {
  if (inited) {
    wallet.stop();
    refreshContext.wait();
    wallet.shutdown();
  }
}

void WalletService::init() {
  loadWallet();
  loadTransactionIdIndex();

  refreshContext.spawn([this] { refresh(); });

  inited = true;
}

void WalletService::saveWallet() {
  wallet.save();
  logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet is saved";
}

void WalletService::loadWallet() {
  logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Loading wallet";
  wallet.load(config.walletFile, config.walletPassword);
  logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet loading is finished.";
}

void WalletService::loadTransactionIdIndex() {
  transactionIdIndex.clear();

  for (size_t i = 0; i < wallet.getTransactionCount(); ++i) {
    transactionIdIndex.emplace(Common::podToHex(wallet.getTransaction(i).hash), i);
  }
}

std::error_code WalletService::saveWalletNoThrow() {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Saving wallet...";

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Save impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    saveWallet();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while saving wallet: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while saving wallet: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::exportWallet(const std::string& fileName) {
  try {
    System::EventLock lk(readyEvent);

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Export impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    boost::filesystem::path walletPath(config.walletFile);
    boost::filesystem::path exportPath = walletPath.parent_path() / fileName;

    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Exporting wallet to " << exportPath.string();
    wallet.exportWallet(exportPath.string());
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while exporting wallet: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while exporting wallet: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::repairWallet() {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Repairing wallet";

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Repair impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    repair();
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet has been repaired";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while repairing wallet: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while repairing wallet: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();

}

std::error_code WalletService::resetWallet() {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Reseting wallet";

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Reset impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    reset();
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet has been reset";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while reseting wallet: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while reseting wallet: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::changePassword(const std::string &oldPassword, const std::string &newPassword, std::string &status) {
  try {
    System::EventLock lk(readyEvent);

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Password change impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    wallet.changePassword(oldPassword, newPassword);
    wallet.save(); // Save wallet file to actually update the password in wallet file
    status = "OK";
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet password was changed successfully";
    return std::error_code();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while changing password: " << x.what();
    status = x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Error while changing password: " << x.what();
    status = x.what();
    return make_error_code(CryptoNote::error::WRONG_PASSWORD);
  }
}

std::error_code WalletService::replaceWithNewWallet(const std::string& viewSecretKeyText) {
  try {
    System::EventLock lk(readyEvent);

    Crypto::SecretKey viewSecretKey;
    if (!Common::podFromHex(viewSecretKeyText, viewSecretKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Cannot restore view secret key: " << viewSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    Crypto::PublicKey viewPublicKey;
    if (!Crypto::secret_key_to_public_key(viewSecretKey, viewPublicKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Cannot derive view public key, wrong secret key: " << viewSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    replaceWithNewWallet(viewSecretKey);
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "The container has been replaced";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while replacing container: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while replacing container: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::createAddress(const std::string& spendSecretKeyText, std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating address";

    Crypto::SecretKey secretKey;
    if (!Common::podFromHex(spendSecretKeyText, secretKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Wrong key format: " << spendSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    address = wallet.createAddress(secretKey);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created address " << address;

  return std::error_code();
}

std::error_code WalletService::createAddressList(const std::vector<std::string>& spendSecretKeysText, std::vector<std::string>& addresses) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating " << spendSecretKeysText.size() << " addresses...";

    std::vector<Crypto::SecretKey> secretKeys;
    std::unordered_set<std::string> unique;
    secretKeys.reserve(spendSecretKeysText.size());
    unique.reserve(spendSecretKeysText.size());
    for (auto& keyText : spendSecretKeysText) {
      auto insertResult = unique.insert(keyText);
      if (!insertResult.second) {
        logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Not unique key";
        return make_error_code(CryptoNote::error::WalletServiceErrorCode::DUPLICATE_KEY);
      }

      Crypto::SecretKey key;
      if (!Common::podFromHex(keyText, key)) {
        logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Wrong key format: " << keyText;
        return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
      }

      secretKeys.push_back(std::move(key));
    }

    addresses = wallet.createAddressList(secretKeys);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating addresses: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created " << addresses.size() << " addresses";

  return std::error_code();
}

std::error_code WalletService::createAddress(std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating address";

    address = wallet.createAddress();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created address " << address;

  return std::error_code();
}

std::error_code WalletService::createTrackingAddress(const std::string& spendPublicKeyText, std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating tracking address";

    Crypto::PublicKey publicKey;
    if (!Common::podFromHex(spendPublicKeyText, publicKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Wrong key format: " << spendPublicKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    address = wallet.createAddress(publicKey);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating tracking address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created address " << address;
  return std::error_code();
}

std::error_code WalletService::deleteAddress(const std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Delete address request came";
    wallet.deleteAddress(address);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while deleting address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Address " << address << " successfully deleted";
  return std::error_code();
}

std::error_code WalletService::hasAddress(const std::string& address, std::string& status) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Has address request came";
    if (!wallet.hasAddress(address)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Address " << address << " doesn't exist in container";
      status = "ERROR";
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND);
    }
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while checking if address exists in container: " << x.what();
    status = x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Address " << address << " exists in container";
  status = "OK";
  return std::error_code();
}

std::error_code WalletService::getAddressCount(size_t& addressCount, std::string& status) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Get address count request came";
    addressCount = wallet.getAddressCount();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting address count: " << x.what();
    status = x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Container has " << std::to_string(addressCount) << " addresses";
  status = "OK";
  return std::error_code();
}

std::error_code WalletService::getSpendkeys(const std::string& address, std::string& publicSpendKeyText, std::string& secretSpendKeyText) {
  try {
    System::EventLock lk(readyEvent);

    CryptoNote::KeyPair key = wallet.getAddressSpendKey(address);

    publicSpendKeyText = Common::podToHex(key.publicKey);
    secretSpendKeyText = Common::podToHex(key.secretKey);

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting spend key: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getBalance(const std::string& address, uint64_t& availableBalance, uint64_t& lockedAmount) {
  try {
    System::EventLock lk(readyEvent);
    logger(Logging::DEBUGGING) << "Getting balance for address " << address;

    availableBalance = wallet.getActualBalance(address);
    lockedAmount = wallet.getPendingBalance(address);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting balance: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << address << " actual balance: " << availableBalance << ", pending: " << lockedAmount;
  return std::error_code();
}

std::error_code WalletService::getBalance(uint64_t& availableBalance, uint64_t& lockedAmount) {
  try {
    System::EventLock lk(readyEvent);
    logger(Logging::DEBUGGING) << "Getting wallet balance";

    availableBalance = wallet.getActualBalance();
    lockedAmount = wallet.getPendingBalance();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting balance: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Wallet actual balance: " << availableBalance << ", pending: " << lockedAmount;
  return std::error_code();
}

std::error_code WalletService::getBlockHashes(uint32_t firstBlockIndex, uint32_t blockCount, std::vector<std::string>& blockHashes) {
  try {
    System::EventLock lk(readyEvent);
    std::vector<Crypto::Hash> hashes = wallet.getBlockHashes(firstBlockIndex, blockCount);

    blockHashes.reserve(hashes.size());
    for (const auto& hash: hashes) {
      blockHashes.push_back(Common::podToHex(hash));
    }
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting block hashes: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getViewKey(std::string& viewSecretKey) {
  try {
    System::EventLock lk(readyEvent);
    CryptoNote::KeyPair viewKey = wallet.getViewKey();
    viewSecretKey = Common::podToHex(viewKey.secretKey);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting view key: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getViewKeys(std::string& viewPublicKey, std::string& viewSecretKey) {
  try {
    System::EventLock lk(readyEvent);
    CryptoNote::KeyPair viewKey = wallet.getViewKey();
    viewPublicKey = Common::podToHex(viewKey.publicKey);
    viewSecretKey = Common::podToHex(viewKey.secretKey);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting view keys: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getMnemonicSeed(const std::string& address, std::string& mnemonicSeed) {
  try {
    System::EventLock lk(readyEvent);
    CryptoNote::KeyPair key = wallet.getAddressSpendKey(address);
    CryptoNote::KeyPair viewKey = wallet.getViewKey();

    Crypto::SecretKey deterministic_private_view_key;

    CryptoNote::AccountBase::generateViewFromSpend(key.secretKey, deterministic_private_view_key);

    bool deterministic_private_keys = deterministic_private_view_key == viewKey.secretKey;

    if (deterministic_private_keys) {
      crypto::ElectrumWords::bytes_to_words(key.secretKey, mnemonicSeed, "English");
    } else {
      /* Have to be able to derive view key from spend key to create a mnemonic
         seed, due to being able to generate multiple addresses we can't do
         this in walletd as the default */
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Your private keys are not deterministic and so a mnemonic seed cannot be generated!";
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::KEYS_NOT_DETERMINISTIC);
    }
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting mnemonic seed: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getTransactionHashes(const std::vector<std::string>& addresses, const std::string& blockHashString,
  uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes) {
  try {
    System::EventLock lk(readyEvent);
    validateAddresses(addresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);
    Crypto::Hash blockHash = parseHash(blockHashString, logger);

    transactionHashes = getRpcTransactionHashes(blockHash, blockCount, transactionFilter);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactionHashes(const std::vector<std::string>& addresses, uint32_t firstBlockIndex,
  uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes) {
  try {
    System::EventLock lk(readyEvent);
    validateAddresses(addresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);
    transactionHashes = getRpcTransactionHashes(firstBlockIndex, blockCount, transactionFilter);

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactionCount(const std::vector<std::string>& addresses, const std::string& blockHashString,
  uint32_t blockCount, const std::string& paymentId, size_t& transactionCount) {
  try {
    System::EventLock lk(readyEvent);
    validateAddresses(addresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);
    Crypto::Hash blockHash = parseHash(blockHashString, logger);

    transactionCount = getRpcTransactionCount(blockHash, blockCount, transactionFilter);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction count: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction count: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactionCount(const std::vector<std::string>& addresses, uint32_t firstBlockIndex,
  uint32_t blockCount, const std::string& paymentId, size_t& transactionCount) {
  try {
    System::EventLock lk(readyEvent);
    validateAddresses(addresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);
    transactionCount = getRpcTransactionCount(firstBlockIndex, blockCount, transactionFilter);

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction count: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction count: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactions(const std::vector<std::string>& addresses, const std::string& blockHashString,
  uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactions) {
  try {
    System::EventLock lk(readyEvent);
    validateAddresses(addresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);

    Crypto::Hash blockHash = parseHash(blockHashString, logger);

    transactions = getRpcTransactions(blockHash, blockCount, transactionFilter);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactions(const std::vector<std::string>& addresses, uint32_t firstBlockIndex,
  uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactions) {
  try {
    System::EventLock lk(readyEvent);
    validateAddresses(addresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(addresses, paymentId);

    transactions = getRpcTransactions(firstBlockIndex, blockCount, transactionFilter);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransaction(const std::string& transactionHash, TransactionRpcInfo& transaction) {
  try {
    System::EventLock lk(readyEvent);
    Crypto::Hash hash = parseHash(transactionHash, logger);

    CryptoNote::WalletTransactionWithTransfers transactionWithTransfers = wallet.getTransaction(hash);

    if (transactionWithTransfers.transaction.state == CryptoNote::WalletTransactionState::DELETED) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Transaction " << transactionHash << " is deleted";
      return make_error_code(CryptoNote::error::OBJECT_NOT_FOUND);
    }

    transaction = convertTransactionWithTransfersToTransactionRpcInfo(transactionWithTransfers);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getAddresses(std::vector<std::string>& addresses) {
  try {
    System::EventLock lk(readyEvent);

    addresses.clear();
    addresses.reserve(wallet.getAddressCount());

    for (size_t i = 0; i < wallet.getAddressCount(); ++i) {
      addresses.push_back(wallet.getAddress(i));
    }
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Can't get addresses: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::sendTransaction(const SendTransaction::Request& request, std::string& transactionHash) {
  try {
    System::EventLock lk(readyEvent);

    validateAddresses(request.sourceAddresses, currency, logger);
    validateAddresses(collectDestinationAddresses(request.transfers), currency, logger);
    if (!request.changeAddress.empty()) {
      validateAddresses({ request.changeAddress }, currency, logger);
    }

    CryptoNote::TransactionParameters sendParams;
    if (!request.paymentId.empty()) {
      addPaymentIdToExtra(request.paymentId, sendParams.extra);
    } else {
      sendParams.extra = getValidatedTransactionExtraString(request.extra);
    }

    sendParams.sourceAddresses = request.sourceAddresses;
    sendParams.destinations = convertWalletRpcOrdersToWalletOrders(request.transfers);
    sendParams.fee = request.fee;
    sendParams.mixIn = request.anonymity;
    sendParams.unlockTimestamp = request.unlockTime;
    sendParams.changeDestination = request.changeAddress;

    size_t transactionId = wallet.transfer(sendParams);
    transactionHash = Common::podToHex(wallet.getTransaction(transactionId).hash);

    logger(Logging::DEBUGGING) << "Transaction " << transactionHash << " has been sent";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while sending transaction: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while sending transaction: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::createDelayedTransaction(const CreateDelayedTransaction::Request& request, std::string& transactionHash) {
  try {
    System::EventLock lk(readyEvent);

    validateAddresses(request.addresses, currency, logger);
    validateAddresses(collectDestinationAddresses(request.transfers), currency, logger);
    if (!request.changeAddress.empty()) {
      validateAddresses({ request.changeAddress }, currency, logger);
    }

    CryptoNote::TransactionParameters sendParams;
    if (!request.paymentId.empty()) {
      addPaymentIdToExtra(request.paymentId, sendParams.extra);
    } else {
      sendParams.extra = Common::asString(Common::fromHex(request.extra));
    }

    sendParams.sourceAddresses = request.addresses;
    sendParams.destinations = convertWalletRpcOrdersToWalletOrders(request.transfers);
    sendParams.fee = request.fee;
    sendParams.mixIn = request.anonymity;
    sendParams.unlockTimestamp = request.unlockTime;
    sendParams.changeDestination = request.changeAddress;

    size_t transactionId = wallet.makeTransaction(sendParams);
    transactionHash = Common::podToHex(wallet.getTransaction(transactionId).hash);

    logger(Logging::DEBUGGING) << "Delayed transaction " << transactionHash << " has been created";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating delayed transaction: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating delayed transaction: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getDelayedTransactionHashes(std::vector<std::string>& transactionHashes) {
  try {
    System::EventLock lk(readyEvent);

    std::vector<size_t> transactionIds = wallet.getDelayedTransactionIds();
    transactionHashes.reserve(transactionIds.size());

    for (auto id: transactionIds) {
      transactionHashes.emplace_back(Common::podToHex(wallet.getTransaction(id).hash));
    }

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting delayed transaction hashes: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting delayed transaction hashes: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::deleteDelayedTransaction(const std::string& transactionHash) {
  try {
    System::EventLock lk(readyEvent);

    parseHash(transactionHash, logger); //validate transactionHash parameter

    auto idIt = transactionIdIndex.find(transactionHash);
    if (idIt == transactionIdIndex.end()) {
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND);
    }

    size_t transactionId = idIt->second;
    wallet.rollbackUncommitedTransaction(transactionId);

    logger(Logging::DEBUGGING) << "Delayed transaction " << transactionHash << " has been canceled";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while deleting delayed transaction hashes: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while deleting delayed transaction hashes: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::sendDelayedTransaction(const std::string& transactionHash) {
  try {
    System::EventLock lk(readyEvent);

    parseHash(transactionHash, logger); //validate transactionHash parameter

    auto idIt = transactionIdIndex.find(transactionHash);
    if (idIt == transactionIdIndex.end()) {
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND);
    }

    size_t transactionId = idIt->second;
    wallet.commitTransaction(transactionId);

    logger(Logging::DEBUGGING) << "Delayed transaction " << transactionHash << " has been sent";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while sending delayed transaction hashes: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while sending delayed transaction hashes: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getUnconfirmedTransactionHashes(const std::vector<std::string>& addresses, std::vector<std::string>& transactionHashes) {
  try {
    System::EventLock lk(readyEvent);

    validateAddresses(addresses, currency, logger);

    std::vector<CryptoNote::WalletTransactionWithTransfers> transactions = wallet.getUnconfirmedTransactions();

    TransactionsInBlockInfoFilter transactionFilter(addresses, "");

    for (const auto& transaction: transactions) {
      if (transactionFilter.checkTransaction(transaction)) {
        transactionHashes.emplace_back(Common::podToHex(transaction.transaction.hash));
      }
    }
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting unconfirmed transaction hashes: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting unconfirmed transaction hashes: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getStatus(uint32_t& blockCount, uint32_t& knownBlockCount, std::string& lastBlockHash, uint32_t& peerCount) {
  try {
    System::EventLock lk(readyEvent);

    System::RemoteContext<std::pair<uint32_t, uint32_t>> remoteContext(dispatcher, [this] () {
      std::pair<uint32_t, uint32_t> res;
      res.first = node.getKnownBlockCount();
      res.second = static_cast<uint32_t>(node.getPeerCount());

      return res;
    });

    auto remoteResult = remoteContext.get();
    knownBlockCount = remoteResult.first;
    peerCount = remoteResult.second;

    blockCount = wallet.getBlockCount();

    auto lastHashes = wallet.getBlockHashes(blockCount - 1, 1);
    lastBlockHash = Common::podToHex(lastHashes.back());
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting status: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting status: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getVersion(std::string& versionString, uint64_t& versionNumber) {
  versionString = PROJECT_VERSION "." PROJECT_VERSION_BUILD_NO;
  const uint64_t verMajor = APP_VER_MAJOR;
  const uint64_t verMinor = APP_VER_MINOR;
  const uint64_t verRev = APP_VER_REV;
  const uint64_t verBuild = APP_VER_BUILD;
  versionNumber = (verMajor << 32) | (verMinor << 24) | (verRev << 16) | verBuild;
  return std::error_code();
}

std::error_code WalletService::sendFusionTransaction(uint64_t threshold, uint32_t anonymity, const std::vector<std::string>& addresses,
  const std::string& destinationAddress, std::string& transactionHash) {

  try {
    System::EventLock lk(readyEvent);

    validateAddresses(addresses, currency, logger);
    if (!destinationAddress.empty()) {
      validateAddresses({ destinationAddress }, currency, logger);
    }

    size_t transactionId = fusionManager.createFusionTransaction(threshold, anonymity, addresses, destinationAddress);
    if (transactionId == CryptoNote::WALLET_INVALID_TRANSACTION_ID) {
      logger(Logging::WARNING) << "Unable to create fusion transaction";
      return make_error_code(CryptoNote::error::TX_TRANSFER_IMPOSSIBLE);
    }
    transactionHash = Common::podToHex(wallet.getTransaction(transactionId).hash);

    logger(Logging::DEBUGGING) << "Fusion transaction " << transactionHash << " has been sent";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while sending fusion transaction: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while sending fusion transaction: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::estimateFusion(uint64_t threshold, const std::vector<std::string>& addresses,
  uint32_t& fusionReadyCount, uint32_t& totalOutputCount) {

  try {
    System::EventLock lk(readyEvent);

    validateAddresses(addresses, currency, logger);

    auto estimateResult = fusionManager.estimate(threshold, addresses);
    fusionReadyCount = static_cast<uint32_t>(estimateResult.fusionReadyCount);
    totalOutputCount = static_cast<uint32_t>(estimateResult.totalOutputCount);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to estimate number of fusion outputs: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to estimate number of fusion outputs: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

void WalletService::refresh() {
  try {
    logger(Logging::DEBUGGING) << "Refresh is started";
    for (;;) {
      auto event = wallet.getEvent();
      if (event.type == CryptoNote::TRANSACTION_CREATED) {
        size_t transactionId = event.transactionCreated.transactionIndex;
        transactionIdIndex.emplace(Common::podToHex(wallet.getTransaction(transactionId).hash), transactionId);
      }
    }
  } catch (std::system_error& e) {
    logger(Logging::DEBUGGING) << "refresh is stopped: " << e.what();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "exception thrown in refresh(): " << e.what();
  }
}

void WalletService::repair() {
  wallet.repair();
}

void WalletService::reset() {
  wallet.save(CryptoNote::WalletSaveLevel::SAVE_KEYS_ONLY);
  wallet.stop();
  wallet.shutdown();
  inited = false;
  refreshContext.wait();

  wallet.start();
  init();
}

void WalletService::replaceWithNewWallet(const Crypto::SecretKey& viewSecretKey) {
  wallet.stop();
  wallet.shutdown();
  inited = false;
  refreshContext.wait();

  transactionIdIndex.clear();

  for (size_t i = 0; ; ++i) {
    std::string backup = config.walletFile + ".backup";
    if (i != 0) {
      backup += "." + std::to_string(i);
    }

    if (!boost::filesystem::exists(backup)) {
      boost::filesystem::rename(config.walletFile, backup);
      logger(Logging::DEBUGGING) << "Wallet file '" << config.walletFile  << "' backed up to '" << backup << '\'';
      break;
    }
  }

  wallet.start();
  wallet.initializeWithViewKey(config.walletFile, config.walletPassword, viewSecretKey);
  inited = true;
}

std::vector<CryptoNote::TransactionsInBlockInfo> WalletService::getTransactions(const Crypto::Hash& blockHash, size_t blockCount) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> result = wallet.getTransactions(blockHash, blockCount);
  if (result.empty()) {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND));
  }

  return result;
}

std::vector<CryptoNote::TransactionsInBlockInfo> WalletService::getTransactions(uint32_t firstBlockIndex, size_t blockCount) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> result = wallet.getTransactions(firstBlockIndex, blockCount);
  if (result.empty()) {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND));
  }

  return result;
}

std::vector<TransactionHashesInBlockRpcInfo> WalletService::getRpcTransactionHashes(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(blockHash, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  return convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionHashesInBlockRpcInfo> WalletService::getRpcTransactionHashes(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(firstBlockIndex, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  return convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionsInBlockRpcInfo> WalletService::getRpcTransactions(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(blockHash, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  return convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionsInBlockRpcInfo> WalletService::getRpcTransactions(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(firstBlockIndex, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  return convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(filteredTransactions);
}

size_t WalletService::getRpcTransactionCount(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(blockHash, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  size_t txs = 0;
  for (auto it = filteredTransactions.begin(); it != filteredTransactions.end(); it++) {
    txs += it->transactions.size();
  }
  return txs;
}

size_t WalletService::getRpcTransactionCount(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(firstBlockIndex, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  size_t txs = 0;
  for (auto it = filteredTransactions.begin(); it != filteredTransactions.end(); it++) {
    txs += it->transactions.size();
  }
  return txs;
}

} //namespace PaymentService
