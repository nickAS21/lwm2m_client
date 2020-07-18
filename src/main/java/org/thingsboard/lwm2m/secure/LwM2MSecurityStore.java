package org.thingsboard.lwm2m.secure;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.leshan.client.object.Server;
import org.eclipse.leshan.client.resource.ObjectsInitializer;
import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.core.util.Hex;
import org.thingsboard.lwm2m.client.LwM2MClientContext;
import org.thingsboard.lwm2m.client.LwM2MSecurityMode;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

import static org.eclipse.leshan.client.object.Security.*;
import static org.eclipse.leshan.client.object.Security.noSec;
import static org.eclipse.leshan.core.LwM2mId.SECURITY;
import static org.eclipse.leshan.core.LwM2mId.SERVER;
import static org.thingsboard.lwm2m.client.LwM2MClientHandler.*;
import static org.thingsboard.lwm2m.client.LwM2MClientHandler.coapLink;

@Slf4j
@Data
public class LwM2MSecurityStore {

    private KeyStore keyStoreServer;
    private X509Certificate serverCertificate;
    private X509Certificate bootstrapCertificate;
    private KeyStore keyStoreClient;
    private X509Certificate clientCertificate;
    private PublicKey serverPublicKey;
    private PublicKey bootstrapPublicKey;
    private PublicKey clientPublicKey;
    private PrivateKey clientPrivateKey;
    private LwM2MClientContext context;
    private String endpoint;
    private ObjectsInitializer initializer;

    public LwM2MSecurityStore(LwM2MClientContext context, ObjectsInitializer initializer, String endpoint) {
        this.context = context;
        this.endpoint = endpoint;
        this.initializer = initializer;
        switch (LwM2MSecurityMode.fromSecurityMode(context.getDtlsMode())) {
            case PSK:
                setInstancesPSK();
                if (context.getCreatePskRpk_key()) {
                    new generationPSkKeyRPKECCKey(context.getDtlsMode());
                }
                break;
            case RPK:
                setInstancesRPK();
                if (context.getCreatePskRpk_key()) {
                    new generationPSkKeyRPKECCKey(context.getDtlsMode());
                }
                break;
            case X509:
                setInstancesX509();
                break;
            case NO_SEC:
                setInstancesNoSec();
                break;
            default:
        }
    }


    private void setInstancesPSK() {
        byte[] pskIdentity = !context.getPskIdentity().isEmpty() ? context.getPskIdentity().getBytes() : (endpoint + context.getPskIdentitySub()).getBytes();
        byte[] pskKey = !context.getPskKey().isEmpty() ? Hex.decodeHex(context.getPskKey().toCharArray()) : Hex.decodeHex(pskKeyDefault.toCharArray());
        String serverSecureURI = null;
        if (context.getBootstrapEnable()) {
            serverSecureURI = coapLinkSec + context.getBootstrapSecureHost() + ":" + context.getBootstrapSecurePort();
            initializer.setInstancesForObject(SECURITY, pskBootstrap(serverSecureURI, pskIdentity, pskKey));
            initializer.setClassForObject(SERVER, Server.class);
        } else {
            serverSecureURI = coapLinkSec + context.getServerSecureHost() + ":" + context.getServerSecurePort();
            initializer.setInstancesForObject(SECURITY, psk(serverSecureURI, context.getServerShortId(), pskIdentity, pskKey));
            initializer.setInstancesForObject(SERVER, new Server(context.getServerShortId(), context.getLifetime(), BindingMode.U, false));
        }
        /** Display client Identity and Security key  to easily add it in servers. */
        getParamsPSKKey(pskIdentity, pskKey, serverSecureURI);
    }

    private void setInstancesRPK() {
        String serverSecureURI = null;
        getKeyForRPK();
        if (context.getBootstrapEnable()) {
            serverSecureURI = coapLinkSec + context.getBootstrapSecureHost() + ":" + context.getBootstrapSecurePort();
            initializer.setInstancesForObject(SECURITY, rpkBootstrap(serverSecureURI, getClientPublicKey().getEncoded(),
                    getClientPrivateKey().getEncoded(), getBootstrapPublicKey().getEncoded()));
            initializer.setClassForObject(SERVER, Server.class);
            getParamsRawPublicKey(getClientPublicKey(), getClientPrivateKey(),  getBootstrapPublicKey());
        } else {
            serverSecureURI = coapLinkSec + context.getServerSecureHost() + ":" + context.getServerSecurePort();
            initializer.setInstancesForObject(SECURITY, rpk(serverSecureURI, context.getServerShortId(), getClientPublicKey().getEncoded(),
                    getClientPrivateKey().getEncoded(), getServerPublicKey().getEncoded()));
            initializer.setInstancesForObject(SERVER, new Server(context.getServerShortId(), context.getLifetime(), BindingMode.U, false));
            getParamsRawPublicKey(getClientPublicKey(), getClientPrivateKey(), getServerPublicKey());
        }
        /** Display client public key to easily add it in servers. */
//        getParamsRawPublicKey(getClientPublicKey(), getClientPrivateKey());

    }

    private void setInstancesX509() {
        String serverSecureURI = null;
        getKeyCertForX509();
        try {
            if (context.getBootstrapEnable()) {
                serverSecureURI = coapLinkSec + context.getBootstrapSecureHost() + ":" + context.getBootstrapSecurePort();
//                String bsHexCert = "3082019B30820140A003020102020900EDB5BF4E072D31D9300A06082A8648CE3D04030230273125302306035504030C1C4C657368616E20426F6F747374726170205365727665722044656D6F3020170D3138313031323132333632375A180F32313138303931383132333632375A30273125302306035504030C1C4C657368616E20426F6F747374726170205365727665722044656D6F3059301306072A8648CE3D020106082A8648CE3D030107034200041C52FFDBD8D88031950B30E5FDEB971F7279246B791A2209CE281D82CDEDF7D6A734CE187612F8A013ECDCFC0564F0EE17248CA08A176D0FE53910975FBB51E7A3533051301D0603551D0E04160414FC9BFE3D7E43270B48C722F07AA1B2D90E9A7850301F0603551D23041830168014FC9BFE3D7E43270B48C722F07AA1B2D90E9A7850300F0603551D130101FF040530030101FF300A06082A8648CE3D0403020349003046022100D9A8CF87D8C78F02B76DCA43F07ED7CBB74D6B045DC98195827CADFD07B794BA022100C581D94A2C4B00EA9AB4811FD9F040580EC9A0378BBDEB4F2B510D0736D18092";
                initializer.setInstancesForObject(SECURITY, x509Bootstrap(serverSecureURI, getClientCertificate().getEncoded(),
                        getClientPrivateKey().getEncoded(), getBootstrapCertificate().getEncoded()));
//                        getClientPrivateKey().getEncoded(), Hex.decodeHex(bsHexCert.toCharArray())));
//                initializer.setClassForObject(SERVER, Server.class);
                initializer.setClassForObject(SERVER, Server.class);
            } else {
                serverSecureURI = coapLinkSec + context.getServerSecureHost() + ":" + context.getServerSecurePort();
                initializer.setInstancesForObject(SECURITY, x509(serverSecureURI, context.getServerShortId(), getClientCertificate().getEncoded(),
                        getClientPrivateKey().getEncoded(), getServerCertificate().getEncoded()));
                initializer.setInstancesForObject(SERVER, new Server(context.getServerShortId(), context.getLifetime(), BindingMode.U, true));
            }
            /** Display X509 credentials to easily at it in servers. */
            if (getClientCertificate() != null) {
                getParamsX509();
            }
        } catch (CertificateEncodingException e) {
            log.error("DTLS mode: [{}] Error secure initializer: [{}]", LwM2MSecurityMode.fromSecurityMode(context.getDtlsMode()), e.getMessage());
        }
    }

    private void setInstancesNoSec() {

        String serverURI = null;
        if (context.getBootstrapEnable()) {
            serverURI = coapLink + context.getBootstrapHost() + ":" + context.getBootstrapPort();
            initializer.setInstancesForObject(SECURITY, noSecBootstap(serverURI));
            initializer.setClassForObject(SERVER, Server.class);
        } else {
            serverURI = coapLink + context.getServerHost() + ":" + context.getServerPort();
            initializer.setInstancesForObject(SECURITY, noSec(serverURI, context.getServerShortId()));
            initializer.setInstancesForObject(SERVER, new Server(context.getServerShortId(), context.getLifetime(), BindingMode.U, false));
        }
    }

    private void getKeyForRPK() {
        if (context.getBootstrapEnable())
            generateKeyRPK(context.getBootstrapRPkPublic_x(), context.getBootstrapRPkPublic_y(), null);
        else generateKeyRPK(context.getServerRPkPublic_x(), context.getServerRPkPublic_y(), null);
        generateKeyRPK(context.getClientRPkPublic_x(), context.getClientRPkPublic_y(), context.getClientRPkPrivate_s());
    }

    private void generateKeyRPK(String publX, String publY, String privS) {
        try {
            /** Get Elliptic Curve Parameter spec for secp256r1 */
            AlgorithmParameters algoParameters = AlgorithmParameters.getInstance("EC");
            algoParameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec parameterSpec = algoParameters.getParameterSpec(ECParameterSpec.class);
            if (publX != null && !publX.isEmpty() && publY != null && !publY.isEmpty()) {
                /** Get point values **/
                byte[] publicX = Hex.decodeHex(publX.toCharArray());
                byte[] publicY = Hex.decodeHex(publY.toCharArray());
                /** Create key specs */
                KeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(publicX), new BigInteger(publicY)),
                        parameterSpec);
                /** Get keys */
                /** Server, bootstrap */
                if (privS == null || privS.isEmpty()) {
                    if (context.getBootstrapEnable())
                        this.bootstrapPublicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
                    else this.serverPublicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
                }  /** Client */
                else this.clientPublicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
            }
            if (privS != null && !privS.isEmpty()) {
                /** Get point values */
                byte[] privateS = Hex.decodeHex(privS.toCharArray());
                /** Create key specs */
                KeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(privateS), parameterSpec);
                /** Get keys */
                this.clientPrivateKey = KeyFactory.getInstance("EC").generatePrivate(privateKeySpec);
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            log.error("[{}] Failed generate Server KeyRPK", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void getKeyCertForX509() {
        readKeyStores();
        try {
            this.clientCertificate = (X509Certificate) this.keyStoreClient.getCertificate(context.getClientAlias());
            this.clientPrivateKey = (PrivateKey) this.keyStoreClient.getKey(context.getClientAlias(), context.getClientKeyStorePwd().toCharArray());
            if (context.getBootstrapEnable())
                this.bootstrapCertificate = (X509Certificate) this.keyStoreServer.getCertificate(context.getBootstrapAlias());
            else
                this.serverCertificate = (X509Certificate) this.keyStoreServer.getCertificate(context.getServerAlias());
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            log.error("Unable to load key and certificates for X509: [{}]", e.getMessage());
        }
    }

    private void readKeyStores() {
        /** Get certificates from key store */

        try (InputStream inClient = context.getClientKeyStorePathFile().isEmpty() ?
                ClassLoader.getSystemResourceAsStream(context.getClientKeyStorePathResource()) : new FileInputStream(new File(context.getClientKeyStorePathFile()))) {
            try (InputStream inServer = context.getServerKeyStorePathFile().isEmpty() ?
                    ClassLoader.getSystemResourceAsStream(context.getServerKeyStorePathResource()) : new FileInputStream(new File(context.getServerKeyStorePathFile()))) {
                this.keyStoreServer = KeyStore.getInstance(context.getServerKeyStoreType());
                this.keyStoreServer.load(inServer, context.getServerKeyStorePwd() == null ? null : context.getServerKeyStorePwd().toCharArray());
                serverCertificate = (X509Certificate) keyStoreServer.getCertificate(context.getServerAlias());
                this.keyStoreClient = KeyStore.getInstance(context.getClientKeyStoreType());
                this.keyStoreClient.load(inClient, context.getClientKeyStorePwd() == null ? null : context.getClientKeyStorePwd().toCharArray());
            } catch (Exception ex) {
                log.error("[{}] [{}] Unable to load X509 keyStoreServer: [{}]",
                        context.getServerKeyStorePathFile().isEmpty() ? context.getServerKeyStorePathResource() : context.getServerKeyStorePathFile(),
                        context.getServerKeyStorePwd(), ex.getMessage());
            }
        } catch (Exception e) {
            log.error("[{}] [{}] Unable to load X509 keyStoreClient: [{}]",
                    context.getClientKeyStorePathFile().isEmpty() ? context.getClientKeyStorePathResource() : context.getClientKeyStorePathFile(),
                    context.getClientKeyStorePwd(), e.getMessage());
        }
    }


    private void getParamsPSKKey(byte[] pskIdentity, byte[] pskKey, String serverSecureURI) {
        log.info("\nClient uses PSK : \n EndPoint : [{}] \n Identity : [{}] \n security key : [{}] \n serverSecureURI : [{}]",
                endpoint,
                new String(pskIdentity),
                Hex.encodeHexString(pskKey),
                serverSecureURI);

    }

    private void getParamsRawPublicKey(PublicKey rawPublicKey, PrivateKey clientPrivateKey, PublicKey serverPublicKey) {
        if (rawPublicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) rawPublicKey;
            /** Get x coordinate */
            byte[] x = ecPublicKey.getW().getAffineX().toByteArray();
            if (x[0] == 0)
                x = Arrays.copyOfRange(x, 1, x.length);

            /** Get Y coordinate */
            byte[] y = ecPublicKey.getW().getAffineY().toByteArray();
            if (y[0] == 0)
                y = Arrays.copyOfRange(y, 1, y.length);

            /** Get Curves params */
            String params = ecPublicKey.getParams().toString();
            if (context.getBootstrapEnable()) {
                log.info(
                        " \nClient uses RPK : \n Endpoint : [{}]\n Elliptic Curve parameters  : [{}] \n Public x coord : [{}] \n Public y coord : [{}] \n Public Key (Hex): [{}] \n Private Key (Hex): [{}]\n Public Bootstrap Server Key (Hex): [{}] ",
                        endpoint, params, Hex.encodeHexString(x), Hex.encodeHexString(y),
                        Hex.encodeHexString(rawPublicKey.getEncoded()).toUpperCase(),
                        Hex.encodeHexString(clientPrivateKey.getEncoded()),
                        Hex.encodeHexString(serverPublicKey.getEncoded()).toUpperCase());
            }
            else {
                log.info(
                        " \nClient uses RPK : \n Endpoint : [{}]\n Elliptic Curve parameters  : [{}] \n Public x coord : [{}] \n Public y coord : [{}] \n Public Key (Hex): [{}] \n Private Key (Hex): [{}]\n Public LwM2M Server Key (Hex): [{}] ",
                        endpoint, params, Hex.encodeHexString(x), Hex.encodeHexString(y),
                        Hex.encodeHexString(rawPublicKey.getEncoded()).toUpperCase(),
                        Hex.encodeHexString(clientPrivateKey.getEncoded()),
                        Hex.encodeHexString(serverPublicKey.getEncoded()).toUpperCase());
            }

        } else {
            throw new IllegalStateException("Unsupported Public Key Format (only ECPublicKey supported).");
        }
    }

    private void getParamsX509() {
        try {
            log.info("Client uses X509 : \n X509 Certificate (Hex): [{}] \n Private Key (Hex): [{}]",
                    Hex.encodeHexString(getClientCertificate().getEncoded()),
                    Hex.encodeHexString(getClientPrivateKey().getEncoded()));
            try {
                if (context.getBootstrapEnable()) {
                    PrivateKey bootstrapKey = (PrivateKey) this.getKeyStoreServer().getKey(context.getBootstrapAlias(), context.getServerKeyStorePwd().toCharArray());

                    log.info("BootStrap uses X509 : \n X509 Certificate (Hex): [{}] \n Private Key (Hex): [{}]",
                            Hex.encodeHexString(getBootstrapCertificate().getEncoded()),
                            Hex.encodeHexString(bootstrapKey.getEncoded()));
                }
                log.info("Server uses X509 : \n X509 Certificate (Hex): [{}]",
                        Hex.encodeHexString(getServerCertificate().getEncoded()));
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            }

        } catch (CertificateEncodingException e) {
            log.error(" [{}]", e.getMessage());
        }
    }
}
