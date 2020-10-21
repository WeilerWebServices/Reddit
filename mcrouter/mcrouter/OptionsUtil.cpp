/*
 *  Copyright (c) 2015, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include "OptionsUtil.h"

#include <boost/filesystem/path.hpp>
#include <folly/Format.h>
#include <folly/Range.h>

#include "mcrouter/options.h"

namespace fs = boost::filesystem;

namespace facebook { namespace memcache { namespace mcrouter {

namespace {

std::string getDebugFifoFullPath(const McrouterOptions& opts,
                                 folly::StringPiece fifoName) {
  assert(!opts.debug_fifo_root.empty());
  auto directory = fs::path(opts.debug_fifo_root);
  auto file = fs::path(folly::sformat("{}.{}.{}", getStatPrefix(opts),
                                      fifoName, "debugfifo"));
  return (directory / file).string();
}

} // anonymous namespace

std::string getStatPrefix(const McrouterOptions& opts) {
  return folly::sformat(
    "libmcrouter.{}.{}",
    opts.service_name,
    opts.router_name);
}

std::string getClientDebugFifoFullPath(const McrouterOptions& opts) {
  return getDebugFifoFullPath(opts, "client");
}

std::string getServerDebugFifoFullPath(const McrouterOptions& opts) {
  return getDebugFifoFullPath(opts, "server");
}

}}} // facebook::memcache::mcrouter
