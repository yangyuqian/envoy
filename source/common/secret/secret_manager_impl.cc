#include "common/secret/secret_manager_impl.h"

#include "envoy/common/exception.h"

#include "common/protobuf/utility.h"
#include "common/ssl/tls_certificate_config_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addStaticSecret(const envoy::api::v2::auth::Secret& secret) {
  switch (secret.type_case()) {
  case envoy::api::v2::auth::Secret::TypeCase::kTlsCertificate: {
    static_tls_certificate_secrets_[secret.name()] =
        std::make_unique<Ssl::TlsCertificateConfigImpl>(secret.tls_certificate());
    break;
  }
  default:
    throw EnvoyException("Secret type not implemented");
  }
}

const Ssl::TlsCertificateConfig*
SecretManagerImpl::findStaticTlsCertificate(const std::string& name) const {
  auto secret = static_tls_certificate_secrets_.find(name);
  return (secret != static_tls_certificate_secrets_.end()) ? secret->second.get() : nullptr;
}

DynamicTlsCertificateSecretProviderSharedPtr
SecretManagerImpl::findOrCreateDynamicTlsCertificateSecretProvider(
    const envoy::api::v2::core::ConfigSource& sds_config_source, const std::string& config_name,
    Init::Manager& init_manager) {
  auto hash = MessageUtil::hash(sds_config_source);
  std::string map_key = std::to_string(hash) + config_name;

  auto dynamic_secret_provider = dynamic_secret_providers_[map_key].lock();
  if (!dynamic_secret_provider) {
    dynamic_secret_provider =
        std::make_shared<SdsApi>(server_, init_manager, sds_config_source, config_name);
    dynamic_secret_providers_[map_key] = dynamic_secret_provider;
  }

  for (auto it = dynamic_secret_providers_.begin(); it != dynamic_secret_providers_.end(); ) {
    if (!it->second.lock()) {
      it = dynamic_secret_providers_.erase(it);
    } else {
      ++it;
    }
  }

  return dynamic_secret_provider;
}

} // namespace Secret
} // namespace Envoy