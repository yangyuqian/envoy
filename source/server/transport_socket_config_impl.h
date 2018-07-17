#pragma once

#include "envoy/server/transport_socket_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Implementation of TransportSocketFactoryContext.
 */
class TransportSocketFactoryContextImpl : public TransportSocketFactoryContext {
public:
  TransportSocketFactoryContextImpl(Ssl::ContextManager& context_manager, Stats::Scope& stats_scope,
                                    Upstream::ClusterManager& cm, Init::Manager& init_manager)
      : context_manager_(context_manager), stats_scope_(stats_scope), cluster_manager_(cm),
        init_manager_(init_manager) {}

  Ssl::ContextManager& sslContextManager() override { return context_manager_; }

  Stats::Scope& statsScope() const override { return stats_scope_; }

  Init::Manager& initManager() override { return init_manager_; }

  Upstream::ClusterManager& clusterManager() override { return cluster_manager_; }

private:
  Ssl::ContextManager& context_manager_;
  Stats::Scope& stats_scope_;
  Upstream::ClusterManager& cluster_manager_;
  Init::Manager& init_manager_;
};

} // namespace Configuration
} // namespace Server
} // namespace Envoy