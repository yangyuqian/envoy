#include "common/secret/secret_manager_impl.h"

#include <algorithm>

#include "envoy/common/exception.h"

#include "common/secret/secret_manager_util.h"
#include "common/ssl/tls_certificate_config_impl.h"

namespace Envoy {
namespace Secret {

void SecretManagerImpl::addOrUpdateSecret(const std::string& config_source_hash,
                                          const envoy::api::v2::auth::Secret& secret) {
  switch (secret.type_case()) {
  case envoy::api::v2::auth::Secret::TypeCase::kTlsCertificate: {
    std::unique_lock<std::shared_timed_mutex> lhs(tls_certificate_secrets_mutex_);
    tls_certificate_secrets_[config_source_hash][secret.name()] =
        std::make_unique<Ssl::TlsCertificateConfigImpl>(secret.tls_certificate());
    ;

    if (config_source_hash.empty()) {
      return;
    }

    const auto tls_certificate_secret =
        tls_certificate_secrets_[config_source_hash][secret.name()].get();
    std::string secret_name = secret.name();
    server_.dispatcher().post([this, config_source_hash, secret_name, tls_certificate_secret]() {
      std::unique_lock<std::shared_timed_mutex> lhs(tls_certificate_secret_update_callbacks_mutex_);
      auto config_source_it = tls_certificate_secret_update_callbacks_.find(config_source_hash);
      if (config_source_it != tls_certificate_secret_update_callbacks_.end()) {
        auto callback_it = config_source_it->second.find(secret_name);
        if (callback_it != config_source_it->second.end()) {
          if (callback_it->second.first == nullptr ||
              !callback_it->second.first->equalTo(*tls_certificate_secret)) {
            for (auto& callback : callback_it->second.second) {
              callback->onAddOrUpdateSecret();
            }
            callback_it->second.first = tls_certificate_secret;
          }
        }
      }
    });
  } break;
  default:
    throw EnvoyException("Secret type not implemented");
  }
}

const Ssl::TlsCertificateConfig*
SecretManagerImpl::findTlsCertificate(const std::string& config_source_hash,
                                      const std::string& name) const {
  std::shared_lock<std::shared_timed_mutex> lhs(tls_certificate_secrets_mutex_);

  auto config_source_it = tls_certificate_secrets_.find(config_source_hash);
  if (config_source_it == tls_certificate_secrets_.end()) {
    return nullptr;
  }

  auto secret = config_source_it->second.find(name);
  return (secret != config_source_it->second.end()) ? secret->second.get() : nullptr;
}

std::string SecretManagerImpl::addOrUpdateSdsService(
    const envoy::api::v2::core::ConfigSource& sds_config_source, std::string config_name) {
  std::unique_lock<std::shared_timed_mutex> lhs(sds_api_mutex_);

  auto hash = SecretManagerUtil::configSourceHash(sds_config_source);
  std::string sds_apis_key = hash + config_name;
  if (sds_apis_.find(sds_apis_key) != sds_apis_.end()) {
    return hash;
  }

  sds_apis_[sds_apis_key] = std::make_unique<SdsApi>(server_, sds_config_source, hash, config_name);

  return hash;
}

void SecretManagerImpl::registerTlsCertificateConfigCallbacks(const std::string& config_source_hash,
                                                              const std::string& secret_name,
                                                              SecretCallbacks* callback) {
  auto secret = findTlsCertificate(config_source_hash, secret_name);

  std::unique_lock<std::shared_timed_mutex> lhs(tls_certificate_secret_update_callbacks_mutex_);

  auto config_source_it = tls_certificate_secret_update_callbacks_.find(config_source_hash);
  if (config_source_it == tls_certificate_secret_update_callbacks_.end()) {
    tls_certificate_secret_update_callbacks_[config_source_hash][secret_name] = {secret,
                                                                                 {callback}};
    return;
  }

  auto name_it = config_source_it->second.find(secret_name);
  if (name_it == config_source_it->second.end()) {
    config_source_it->second[secret_name] = {secret, {callback}};
    return;
  }

  name_it->second.second.push_back(callback);
}

void SecretManagerImpl::unRegisterTlsCertificateConfigCallbacks(
    const std::string& config_source_hash, const std::string& secret_name,
    SecretCallbacks& callback) {
  std::unique_lock<std::shared_timed_mutex> lhs(tls_certificate_secret_update_callbacks_mutex_);

  auto config_source_it = tls_certificate_secret_update_callbacks_.find(config_source_hash);
  if (config_source_it != tls_certificate_secret_update_callbacks_.end()) {
    auto name_it = config_source_it->second.find(secret_name);
    if (name_it != config_source_it->second.end()) {
      auto callback_it =
          std::find(name_it->second.second.begin(), name_it->second.second.end(), &callback);
      if (callback_it != name_it->second.second.end()) {
        name_it->second.second.erase(callback_it);
      }
    }
  }
}

} // namespace Secret
} // namespace Envoy
