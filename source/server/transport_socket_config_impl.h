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
  TransportSocketFactoryContextImpl(Ssl::ContextManager& context_manager,
                                    Stats::Scope& stats_scope,
                                    Secret::SecretManager& secret_manager,
                                    Init::Manager& init_manager)
      : context_manager_(context_manager), stats_scope_(stats_scope),
        secret_manager_(secret_manager), init_manager_(init_manager) {}

  Ssl::ContextManager& sslContextManager() override { return context_manager_; }

  Stats::Scope& statsScope() const override { return stats_scope_; }

  Secret::SecretManager& secretManager() override { return secret_manager_; }

  Init::Manager& initManager() override { return init_manager_; }

 private:
  Ssl::ContextManager& context_manager_;
  Stats::Scope& stats_scope_;
  Secret::SecretManager& secret_manager_;
  Init::Manager& init_manager_;
};

} // namespace Configuration
} // namespace Server
} // namespace Envoy