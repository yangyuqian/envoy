#include "common/secret/secret_manager_impl.h"

#include "envoy/common/exception.h"

#include "common/secret/secret_manager_util.h"
#include "common/ssl/tls_certificate_config_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addStaticSecret(const envoy::api::v2::auth::Secret& secret) {
  switch (secret.type_case()) {
  case envoy::api::v2::auth::Secret::TypeCase::kTlsCertificate: {
    std::unique_lock<std::shared_timed_mutex> lhs(tls_certificate_secrets_mutex_);
    tls_certificate_secrets_[secret.name()] =
        std::make_unique<Ssl::TlsCertificateConfigImpl>(secret.tls_certificate());
  } break;
  default:
    throw EnvoyException("Secret type not implemented");
  }
}

const Ssl::TlsCertificateConfig*
SecretManagerImpl::findStaticTlsCertificate(const std::string& name) const {
  std::shared_lock<std::shared_timed_mutex> lhs(tls_certificate_secrets_mutex_);

  auto secret = tls_certificate_secrets_.find(name);
  return (secret != tls_certificate_secrets_.end()) ? secret->second.get() : nullptr;
}

DynamicSecretProviderSharedPtr SecretManagerImpl::createDynamicSecretProvider(
    const envoy::api::v2::core::ConfigSource& sds_config_source, std::string config_name) {
  std::unique_lock<std::shared_timed_mutex> lhs(sds_api_mutex_);

  auto hash = SecretManagerUtil::configSourceHash(sds_config_source);
  std::string sds_apis_key = hash + config_name;
  auto sds_api = sds_apis_[sds_apis_key].lock();
  if (!sds_api) {
    sds_api = std::make_shared<SdsApi>(server_, sds_config_source, hash, config_name);
    sds_apis_[sds_apis_key] = sds_api;
  }

  return sds_api;
}

} // namespace Secret
} // namespace Envoy