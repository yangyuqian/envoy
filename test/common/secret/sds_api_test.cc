#include <memory>

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/common/exception.h"

#include "common/secret/sds_api.h"

#include "test/mocks/grpc/mocks.h"
#include "test/mocks/server/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::Invoke;
using ::testing::Return;
using ::testing::_;

namespace Envoy {
namespace Secret {
namespace {

class SdsApiTest : public testing::Test {
public:
};

TEST_F(SdsApiTest, BasicTest) {
  ::testing::InSequence s;
  NiceMock<Server::MockInstance> server;
  Upstream::ClusterManager::ClusterInfoMap cluster_map;
  Upstream::MockCluster cluster;
  cluster_map.emplace("foo_cluster", cluster);
  EXPECT_CALL(server.init_manager_, registerTarget(_));

  envoy::api::v2::core::ConfigSource config_source;
  config_source.mutable_api_config_source()->set_api_type(
      envoy::api::v2::core::ApiConfigSource::GRPC);
  auto grpc_service = config_source.mutable_api_config_source()->add_grpc_services();
  grpc_service->mutable_envoy_grpc()->set_cluster_name("foo_cluster");
  SdsApi sds_api(server, config_source, "abc.com");

  EXPECT_CALL(server.cluster_manager_, clusters()).WillOnce(Return(cluster_map));
  Grpc::MockAsyncClient* grpc_client{new Grpc::MockAsyncClient};
  Grpc::MockAsyncClientFactory* factory{new Grpc::MockAsyncClientFactory};
  EXPECT_CALL(server.cluster_manager_, grpcAsyncClientManager())
      .WillRepeatedly(ReturnRef(server.cluster_manager_.async_client_manager_));
  EXPECT_CALL(server.cluster_manager_.async_client_manager_, factoryForGrpcService(_, _, _))
      .WillOnce(Invoke([factory](const envoy::api::v2::core::GrpcService&, Stats::Scope&, bool) {
        return Grpc::AsyncClientFactoryPtr{factory};
      }));
  EXPECT_CALL(*factory, create()).WillOnce(Invoke([grpc_client] {
    return Grpc::AsyncClientPtr{grpc_client};
  }));
  server.init_manager_.initialize();
}

TEST_F(SdsApiTest, SecretUpdateSuccess) {
  Server::MockInstance server;
  envoy::api::v2::core::ConfigSource config_source;
  EXPECT_CALL(server, initManager());
  SdsApi sds_api(server, config_source, "abc.com");

  std::string yaml =
      R"EOF(
  name: "abc.com"
  tls_certificate:
    certificate_chain:
      filename: "{{ test_rundir }}/test/common/ssl/test_data/selfsigned_cert.pem"
    private_key:
      filename: "{{ test_rundir }}/test/common/ssl/test_data/selfsigned_key.pem"
    )EOF";

  Protobuf::RepeatedPtrField<envoy::api::v2::auth::Secret> secret_resources;
  auto secret_config = secret_resources.Add();
  MessageUtil::loadFromYaml(TestEnvironment::substitute(yaml), *secret_config);
  sds_api.onConfigUpdate(secret_resources, "");

  const std::string cert_pem = "{{ test_rundir }}/test/common/ssl/test_data/selfsigned_cert.pem";
  EXPECT_EQ(TestEnvironment::readFileToStringForTest(TestEnvironment::substitute(cert_pem)),
            sds_api.secret()->certificateChain());

  const std::string key_pem = "{{ test_rundir }}/test/common/ssl/test_data/selfsigned_key.pem";
  EXPECT_EQ(TestEnvironment::readFileToStringForTest(TestEnvironment::substitute(key_pem)),
            sds_api.secret()->privateKey());
}

TEST_F(SdsApiTest, EmptyResource) {
  Server::MockInstance server;
  envoy::api::v2::core::ConfigSource config_source;
  EXPECT_CALL(server, initManager());
  SdsApi sds_api(server, config_source, "abc.com");

  Protobuf::RepeatedPtrField<envoy::api::v2::auth::Secret> secret_resources;
  sds_api.onConfigUpdate(secret_resources, "");
  EXPECT_EQ(nullptr, sds_api.secret());
}

TEST_F(SdsApiTest, SecretUpdateWrongSize) {
  Server::MockInstance server;
  envoy::api::v2::core::ConfigSource config_source;
  EXPECT_CALL(server, initManager());
  SdsApi sds_api(server, config_source, "abc.com");

  std::string yaml =
      R"EOF(
    name: "abc.com"
    tls_certificate:
      certificate_chain:
        filename: "{{ test_rundir }}/test/common/ssl/test_data/selfsigned_cert.pem"
      private_key:
        filename: "{{ test_rundir }}/test/common/ssl/test_data/selfsigned_key.pem"
      )EOF";

  Protobuf::RepeatedPtrField<envoy::api::v2::auth::Secret> secret_resources;
  auto secret_config_1 = secret_resources.Add();
  MessageUtil::loadFromYaml(TestEnvironment::substitute(yaml), *secret_config_1);
  auto secret_config_2 = secret_resources.Add();
  MessageUtil::loadFromYaml(TestEnvironment::substitute(yaml), *secret_config_2);

  EXPECT_THROW_WITH_MESSAGE(sds_api.onConfigUpdate(secret_resources, ""), EnvoyException,
                            "Unexpected SDS secrets length: 2");
}

TEST_F(SdsApiTest, SecretUpdateWrongSecretName) {
  Server::MockInstance server;
  envoy::api::v2::core::ConfigSource config_source;
  EXPECT_CALL(server, initManager());
  SdsApi sds_api(server, config_source, "abc.com");

  std::string yaml =
      R"EOF(
      name: "wrong.name.com"
      tls_certificate:
        certificate_chain:
          filename: "{{ test_rundir }}/test/common/ssl/test_data/selfsigned_cert.pem"
        private_key:
          filename: "{{ test_rundir }}/test/common/ssl/test_data/selfsigned_key.pem"
        )EOF";

  Protobuf::RepeatedPtrField<envoy::api::v2::auth::Secret> secret_resources;
  auto secret_config = secret_resources.Add();
  MessageUtil::loadFromYaml(TestEnvironment::substitute(yaml), *secret_config);

  EXPECT_THROW_WITH_MESSAGE(sds_api.onConfigUpdate(secret_resources, ""), EnvoyException,
                            "Unexpected SDS secret (expecting abc.com): wrong.name.com");
}

} // namespace
} // namespace Secret
} // namespace Envoy