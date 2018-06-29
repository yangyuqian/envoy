#pragma once

#include <string>

#include "envoy/ssl/tls_certificate_config.h"

namespace Envoy {
namespace Secret {

/**
 * An interface to fetch dynamic secret.
 */
class DynamicSecretProvider {
public:
  virtual ~DynamicSecretProvider() {}

  /**
   * @return the TlsCertificate secret. Returns nullptr if the secret is not found.
   */
  virtual const Ssl::TlsCertificateConfig* secret() const PURE;
};

typedef std::shared_ptr<DynamicSecretProvider> DynamicSecretProviderSharedPtr;

} // namespace Secret
} // namespace Envoy