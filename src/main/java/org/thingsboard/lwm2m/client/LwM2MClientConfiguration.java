package org.thingsboard.lwm2m.client;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.*;
import org.eclipse.leshan.client.californium.LeshanClient;
import org.eclipse.leshan.client.californium.LeshanClientBuilder;
import org.eclipse.leshan.client.engine.DefaultRegistrationEngineFactory;
import org.eclipse.leshan.client.resource.LwM2mObjectEnabler;
import org.eclipse.leshan.client.resource.ObjectsInitializer;
import org.eclipse.leshan.core.californium.DefaultEndpointFactory;
import org.eclipse.leshan.core.model.LwM2mModel;
import org.eclipse.leshan.core.model.ObjectLoader;
import org.eclipse.leshan.core.model.ObjectModel;
import org.eclipse.leshan.core.model.StaticModel;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mNodeDecoder;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mNodeEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.thingsboard.lwm2m.client.objects.LwM2MLocationParams;
import org.thingsboard.lwm2m.client.objects.LwM2mDevice;
import org.thingsboard.lwm2m.client.objects.LwM2mLocation;
import org.thingsboard.lwm2m.client.objects.LwM2mTemperatureSensor;
import org.thingsboard.lwm2m.secure.LwM2MSecurityStore;

import java.io.File;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.eclipse.leshan.core.LwM2mId.*;
import static org.eclipse.leshan.core.LwM2mId.LOCATION;
import static org.thingsboard.lwm2m.client.LwM2MClientHandler.MODEL_DEFAULT_RESOURCE_PATH;
import static org.thingsboard.lwm2m.client.LwM2MClientHandler.modelPaths;

@Slf4j
@Configuration("LwM2MClientConfiguration")
@ComponentScan({"org.thingsboard.lwm2m"})
public class LwM2MClientConfiguration {

    private static final int OBJECT_ID_TEMPERATURE_SENSOR = 3303;

    @Autowired
    private LwM2MClientContext context;

    @Autowired
    private LwM2MLocationParams locationParams;

    @Bean
    public LeshanClient getLeshanClient() throws URISyntaxException {
        /** Create client */
        log.info("Starting LwM2M client... PostConstruct");
        /** Initialize model */
        List<ObjectModel> models = ObjectLoader.loadDefault();
        List<ObjectModel> listModels = ObjectLoader.loadDdfResources(MODEL_DEFAULT_RESOURCE_PATH, modelPaths);
        models.addAll(listModels);
        if (!context.getFolderPathModel().isEmpty()) {
            models.addAll(ObjectLoader.loadObjectsFromDir(new File(context.getFolderPathModel())));
        }
        /** Initialize object list */
        final LwM2mModel model = new StaticModel(models);
        final ObjectsInitializer initializer = new ObjectsInitializer(model);

        /** Endpoint */
        String subEndpoint = !context.getSubEndpoint().isEmpty() ? context.getSubEndpoint() : LwM2MSecurityMode.fromSecurityMode(context.getDtlsMode()).subEndpoint;
        String endpoint = !context.getEndpoint().isEmpty() ? context.getEndpoint() + "_" + subEndpoint : "client_default";
        log.info("Start LwM2M client... PostConstruct [{}]", endpoint);

        /** Initialize security object */
        new LwM2MSecurityStore(context, initializer, endpoint);

        /** Initialize other objects */
        initializer.setInstancesForObject(DEVICE, new LwM2mDevice());
        initializer.setInstancesForObject(LOCATION, new LwM2mLocation(locationParams.getLatitude(), locationParams.getLongitude(), locationParams.getScaleFactor()));
        initializer.setInstancesForObject(OBJECT_ID_TEMPERATURE_SENSOR, new LwM2mTemperatureSensor());
        List<LwM2mObjectEnabler> enablers = initializer.createAll();

        /** Create CoAP Config */
        NetworkConfig coapConfig;
        File configFile = new File(NetworkConfig.DEFAULT_FILE_NAME);
        if (configFile.isFile()) {
            coapConfig = new NetworkConfig();
            coapConfig.load(configFile);
        } else {
            coapConfig = LeshanClientBuilder.createDefaultNetworkConfig();
            coapConfig.store(configFile);
        }

        /** Create DTLS Config */
        DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
        dtlsConfig.setRecommendedCipherSuitesOnly(!context.getOldCiphers());

        /** Configure Registration Engine */
        DefaultRegistrationEngineFactory engineFactory = new DefaultRegistrationEngineFactory();
        engineFactory.setCommunicationPeriod((context.getCommunicationPeriod() == null) ? null : context.getCommunicationPeriod() * 1000);
        engineFactory.setReconnectOnUpdate(context.getReconnectOnUpdate());
        engineFactory.setResumeOnConnect(!context.getForceFullHandshake());

        /** Configure EndpointFactory */
        DefaultEndpointFactory endpointFactory = new DefaultEndpointFactory(endpoint) {
            @Override
            protected Connector createSecuredConnector(DtlsConnectorConfig dtlsConfig) {

                return new DTLSConnector(dtlsConfig) {
                    @Override
                    protected void onInitializeHandshaker(Handshaker handshaker) {
                        handshaker.addSessionListener(new SessionAdapter() {

                            @Override
                            public void handshakeStarted(Handshaker handshaker) throws HandshakeException {
                                if (handshaker instanceof ServerHandshaker) {
                                    log.info("DTLS Full Handshake initiated by server : STARTED ...");
                                } else if (handshaker instanceof ResumingServerHandshaker) {
                                    log.info("DTLS abbreviated Handshake initiated by server : STARTED ...");
                                } else if (handshaker instanceof ClientHandshaker) {
                                    log.info("DTLS Full Handshake initiated by client : STARTED ...");
                                } else if (handshaker instanceof ResumingClientHandshaker) {
                                    log.info("DTLS abbreviated Handshake initiated by client : STARTED ...");
                                }
                            }

                            @Override
                            public void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession)
                                    throws HandshakeException {
                                if (handshaker instanceof ServerHandshaker) {
                                    log.info("DTLS Full Handshake initiated by server : SUCCEED");
                                } else if (handshaker instanceof ResumingServerHandshaker) {
                                    log.info("DTLS abbreviated Handshake initiated by server : SUCCEED");
                                } else if (handshaker instanceof ClientHandshaker) {
                                    log.info("DTLS Full Handshake initiated by client : SUCCEED");
                                } else if (handshaker instanceof ResumingClientHandshaker) {
                                    log.info("DTLS abbreviated Handshake initiated by client : SUCCEED");
                                }
                            }

                            @Override
                            public void handshakeFailed(Handshaker handshaker, Throwable error) {
                                /** get cause */
                                String cause;
                                if (error != null) {
                                    if (error.getMessage() != null) {
                                        cause = error.getMessage();
                                    } else {
                                        cause = error.getClass().getName();
                                    }
                                } else {
                                    cause = "unknown cause";
                                }

                                if (handshaker instanceof ServerHandshaker) {
                                    log.info("DTLS Full Handshake initiated by server : FAILED [{}]", cause);
                                } else if (handshaker instanceof ResumingServerHandshaker) {
                                    log.info("DTLS abbreviated Handshake initiated by server : FAILED [{}]", cause);
                                } else if (handshaker instanceof ClientHandshaker) {
                                    log.info("DTLS Full Handshake initiated by client : FAILED [{}]", cause);
                                } else if (handshaker instanceof ResumingClientHandshaker) {
                                    log.info("DTLS abbreviated Handshake initiated by client : FAILED [{}]", cause);
                                }
                            }
                        });
                    }
                };
            }
        };

        /** Create client */
        LeshanClientBuilder builder = new LeshanClientBuilder(endpoint);
        builder.setLocalAddress((context.getClientHost().isEmpty()) ? null : context.getClientHost(), context.getClientPort());
        builder.setObjects(enablers);
        builder.setCoapConfig(coapConfig);
        builder.setDtlsConfig(dtlsConfig);
        builder.setRegistrationEngineFactory(engineFactory);
        builder.setEndpointFactory(endpointFactory);
        if (context.getSupportOldFormat()) {
            builder.setDecoder(new DefaultLwM2mNodeDecoder(true));
            builder.setEncoder(new DefaultLwM2mNodeEncoder(true));
        }
        builder.setAdditionalAttributes(context.getAddAttributes().isEmpty() ? null : getAddAttrs(context.getAddAttributes()));
        return builder.build();
    }

   private Map<String, String> getAddAttrs(String addAttrs) {
        Map<String, String> additionalAttributes = new HashMap<>();
        Pattern p1 = Pattern.compile("(.*):\"(.*)\"");
        Pattern p2 = Pattern.compile("(.*):(.*)");
        String[] values = addAttrs.split(";");
        for (String v : values) {
            Matcher m = p1.matcher(v);
            if (m.matches()) {
                String attrName = m.group(1);
                String attrValue = m.group(2);
                additionalAttributes.put(attrName, attrValue);
            } else {
                m = p2.matcher(v);
                if (m.matches()) {
                    String attrName = m.group(1);
                    String attrValue = m.group(2);
                    additionalAttributes.put(attrName, attrValue);
                } else {
                    log.error("Invalid syntax for additional attributes : [{}]", v);
                    return null;
                }
            }
        }
        return additionalAttributes;    }
}
