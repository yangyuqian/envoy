#pragma once

#include "envoy/ssl/tls_certificate_config.h"

namespace Envoy {
namespace Secret {

/**
 * An interface to fetch dynamic secret.
 *
 * TODO(JimmyCYJ): Support other types of secrets.
 */
class DynamicTlsCertificateSecretProvider {
public:
  virtual ~DynamicTlsCertificateSecretProvider() {}

  /**
   * @return the TlsCertificate secret. Returns nullptr if the secret is not found.
   */
  virtual const Ssl::TlsCertificateConfig* secret() const PURE;
};

typedef std::shared_ptr<DynamicTlsCertificateSecretProvider>
    DynamicTlsCertificateSecretProviderSharedPtr;

} // namespace Secret
} // namespace Envoy