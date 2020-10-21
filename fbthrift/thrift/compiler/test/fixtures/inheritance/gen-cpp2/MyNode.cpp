/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#include "MyNode.h"

#include "MyNode.tcc"

#include <thrift/lib/cpp2/protocol/Protocol.h>
#include <thrift/lib/cpp2/protocol/BinaryProtocol.h>
#include <thrift/lib/cpp2/protocol/CompactProtocol.h>
namespace cpp2 {

std::unique_ptr<apache::thrift::AsyncProcessor> MyNodeSvIf::getProcessor() {
  return folly::make_unique<MyNodeAsyncProcessor>(this);
}

void MyNodeSvIf::do_mid() {
  throw apache::thrift::TApplicationException("Function do_mid is unimplemented");
}

folly::Future<folly::Unit> MyNodeSvIf::future_do_mid() {
  return apache::thrift::detail::si::future([&] { return do_mid(); });
}

void MyNodeSvIf::async_tm_do_mid(std::unique_ptr<apache::thrift::HandlerCallback<void>> callback) {
  apache::thrift::detail::si::async_tm(this, std::move(callback), [&] { return future_do_mid(); });
}

void MyNodeSvNull::do_mid() {}

const char* MyNodeAsyncProcessor::getServiceName() {
  return "MyNode";
}

folly::Optional<std::string> MyNodeAsyncProcessor::getCacheKey(folly::IOBuf* buf, apache::thrift::protocol::PROTOCOL_TYPES protType) {
  return apache::thrift::detail::ap::get_cache_key(buf, protType, cacheKeyMap_);
}

void MyNodeAsyncProcessor::process(std::unique_ptr<apache::thrift::ResponseChannel::Request> req, std::unique_ptr<folly::IOBuf> buf, apache::thrift::protocol::PROTOCOL_TYPES protType, apache::thrift::Cpp2RequestContext* context, apache::thrift::async::TEventBase* eb, apache::thrift::concurrency::ThreadManager* tm) {
  apache::thrift::detail::ap::process(this, std::move(req), std::move(buf), protType, context, eb, tm);
}

bool MyNodeAsyncProcessor::isOnewayMethod(const folly::IOBuf* buf, const apache::thrift::transport::THeader* header) {
  return apache::thrift::detail::ap::is_oneway_method(buf, header, onewayMethods_);
}

std::unordered_set<std::string> MyNodeAsyncProcessor::onewayMethods_ {};
std::unordered_map<std::string, int16_t> MyNodeAsyncProcessor::cacheKeyMap_ {};
const MyNodeAsyncProcessor::BinaryProtocolProcessMap& MyNodeAsyncProcessor::getBinaryProtocolProcessMap() {
  return binaryProcessMap_;
}

MyNodeAsyncProcessor::BinaryProtocolProcessMap MyNodeAsyncProcessor::binaryProcessMap_ {
  {"do_mid", &MyNodeAsyncProcessor::_processInThread_do_mid<apache::thrift::BinaryProtocolReader, apache::thrift::BinaryProtocolWriter>}
};
const MyNodeAsyncProcessor::CompactProtocolProcessMap& MyNodeAsyncProcessor::getCompactProtocolProcessMap() {
  return compactProcessMap_;
}

MyNodeAsyncProcessor::CompactProtocolProcessMap MyNodeAsyncProcessor::compactProcessMap_ {
  {"do_mid", &MyNodeAsyncProcessor::_processInThread_do_mid<apache::thrift::CompactProtocolReader, apache::thrift::CompactProtocolWriter>}
};

} // cpp2
namespace apache { namespace thrift {

}} // apache::thrift