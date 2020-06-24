package org.thingsboard.lwm2m.client;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;

@Slf4j
@Component("LwM2MClientContext")
public class LwM2MClientContext {

    @Getter
    @Value("${lwm2m.server.bind_address:localhost}")
    private String serverHost;

    @Getter
    @Value("${lwm2m.server.bind_port:5685}")
    private Integer serverPort;

    @Getter
    @Value("${lwm2m.server.short_id:123}")
    private Integer serverShortId;

    @Getter
    @Value("${lwm2m.server.secure.bind_address:localhost}")
    private String serverSecureHost;

    @Getter
    @Value("${lwm2m.server.secure.bind_port:5686}")
    private Integer serverSecurePort;

    @Getter
    @Value("${lwm2m.server.secure.rpk_public_x:}")
    private String serverRPkPublic_x;

    @Getter
    @Value("${lwm2m.server.secure.rpk_public_y:}")
    private String serverRPkPublic_y;

    @Getter
    @Value("${lwm2m.server.secure.key_store_type:}")
    private String serverKeyStoreType;

    @Getter
    @Value("${lwm2m.server.secure.key_store_path_file:}")
    private String serverKeyStorePathFile;

   @Getter
    @Value("${lwm2m.server.secure.key_store_path_resource:}")
    private String serverKeyStorePathResource;

    @Getter
    @Value("${lwm2m.server.secure.key_store_pwd:}")
    private String serverKeyStorePwd;

    @Getter
    @Value("${lwm2m.server.secure.alias:}")
    private String serverAlias;

    @Getter
    @Value("${lwm2m.bootstrap.enable:false}")
    private Boolean bootstrapEnable;

    @Getter
    @Value("${lwm2m.bootstrap.bind_address:localhost}")
    private String bootstrapHost;

    @Getter
    @Value("${lwm2m.bootstrap.bind_port:5685}")
    private Integer bootstrapPort;

    @Getter
    @Value("${lwm2m.bootstrap.short_id:456}")
    private Integer bootstrapShortId;

    @Getter
    @Value("${lwm2m.server.bootstrap.bind_address:localhost}")
    private String bootstrapSecureHost;

    @Getter
    @Value("${lwm2m.bootstrap.secure.bind_port:5686}")
    private Integer bootstrapSecurePort;

    @Getter
    @Value("${lwm2m.bootstrap.secure.rpk_public_x:}")
    private String bootstrapRPkPublic_x;

    @Getter
    @Value("${lwm2m.bootstrap.secure.rpk_public_y:}")
    private String bootstrapRPkPublic_y;

    @Getter
    @Value("${lwm2m.bootstrap.secure.alias:}")
    private String bootstrapAlias;

    @Getter
    @Value("${lwm2m.client.create_psk_rpk_key:}")
    private Boolean createPskRpk_key;

    @Getter
    @Value("${lwm2m.client.endpoint:}")
    private String endpoint;

    @Getter
    @Value("${lwm2m.client.sub_endpoint:}")
    private String subEndpoint;

    @Getter
    @Value("${lwm2m.client.bind_address:}")
    private String clientHost;

    @Getter
    @Value("${lwm2m.client.bind_port:0}")
    private Integer clientPort;

    @Getter
    @Value("${lwm2m.client.model_folder_path:}")
    private String folderPathModel;

    @Getter
    @Value("${lwm2m.client.support_deprecated_ciphers:}")
    private Boolean oldCiphers;

    @Getter
    @Value("${lwm2m.client.lifetime:}")
    private Integer lifetime;

    @Getter
    @Value("${lwm2m.client.communication_period:}")
    private Integer communicationPeriod;

    @Getter
    @Value("${lwm2m.client.reconnect_on_update:}")
    private Boolean reconnectOnUpdate;

    @Getter
    @Value("${lwm2m.client.force_full_handshake:}")
    private Boolean forceFullHandshake;

   @Getter
    @Value("${lwm2m.client.support_old_format:}")
    private Boolean supportOldFormat;

   @Getter
    @Value("${lwm2m.client.add_attributes:}")
    private String addAttributes;

   @Getter
    @Value("${lwm2m.client.pos:}")
    private String locationPos;

   @Getter
    @Value("${lwm2m.client.scale_factor:}")
    private Float locationScaleFactor;

    @Getter
    @Value("${lwm2m.client.secure.dtls_mode:}")
    private Integer dtlsMode;

    @Getter
    @Value("${lwm2m.client.secure.psk_identity:}")
    private String pskIdentity;

    @Getter
    @Value("${lwm2m.client.secure.psk_identity_sub:}")
    private String pskIdentitySub;

    @Getter
    @Value("${lwm2m.client.secure.psk_key:}")
    private String pskKey;

    @Getter
    @Value("${lwm2m.client.secure.rpk_public_x:}")
    private String clientRPkPublic_x;

    @Getter
    @Value("${lwm2m.client.secure.rpk_public_y:}")
    private String clientRPkPublic_y;

    @Getter
    @Value("${lwm2m.client.secure.rpk_private_s:}")
    private String clientRPkPrivate_s;

    @Getter
    @Value("${lwm2m.client.secure.key_store_type:}")
    private String clientKeyStoreType;

    @Getter
    @Value("${lwm2m.client.secure.key_store_path_file:}")
    private String clientKeyStorePathFile;

    @Getter
    @Value("${lwm2m.client.secure.key_store_path_resource:}")
    private String clientKeyStorePathResource;

    @Getter
    @Value("${lwm2m.client.secure.key_store_pwd:}")
    private String clientKeyStorePwd;

    @Getter
    @Value("${lwm2m.client.secure.alias:}")
    private String clientAlias;


}
