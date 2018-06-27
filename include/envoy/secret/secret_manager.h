#pragma once

#include <string>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/ssl/tls_certificate_config.h"

namespace Envoy {
namespace Secret {

/**
 * A provider for dynamic secret.
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

/**
 * A manager for static secrets.
 */
class SecretManager {
public:
  virtual ~SecretManager() {}

  /**
   * @param config_source_hash a hash string of normalized config source for static secret.
   * @param secret a protobuf message of envoy::api::v2::auth::Secret.
   * @throw an EnvoyException if the secret is invalid or not supported.
   */
  virtual void addStaticSecret(const envoy::api::v2::auth::Secret& secret) PURE;

  /**
   * @param name a name of the Ssl::TlsCertificateConfig.
   * @return the TlsCertificate secret. Returns nullptr if the secret is not found.
   */
  virtual const Ssl::TlsCertificateConfig*
  findStaticTlsCertificate(const std::string& name) const PURE;

  /**
   * Create a secret provider that stores dynamic secret.
   * config source.
   *
   * @param config_source a protobuf message object contains SDS config source.
   * @param config_name a name that uniquely refers to the SDS config source
   * @return the dynamic secret provider.
   */
  virtual DynamicSecretProviderSharedPtr
  createDynamicSecretProvider(const envoy::api::v2::core::ConfigSource& config_source,
                              std::string config_name) PURE;
};

} // namespace Secret
} // namespace Envoy
