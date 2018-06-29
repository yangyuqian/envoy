#pragma once

#include "envoy/secret/secret_manager.h"
#include "envoy/ssl/tls_certificate_config.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Secret {

class MockSecretManager : public SecretManager {
public:
  MockSecretManager();
  ~MockSecretManager();

  MOCK_METHOD1(addStaticSecret, void(const envoy::api::v2::auth::Secret& secret));
  MOCK_CONST_METHOD1(findStaticTlsCertificate, Ssl::TlsCertificateConfig*(const std::string& name));
  MOCK_METHOD2(
      findOrCreateDynamicSecretProvider,
      DynamicSecretProviderSharedPtr(const envoy::api::v2::core::ConfigSource& config_source,
                                     std::string config_name));
};

class MockDynamicSecretProvider : public DynamicSecretProvider {
public:
  MockDynamicSecretProvider();
  ~MockDynamicSecretProvider();

  MOCK_CONST_METHOD0(secret, const Ssl::TlsCertificateConfig*());
};

} // namespace Secret
} // namespace Envoy
