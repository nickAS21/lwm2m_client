package org.thingsboard.lwm2m.secure;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.leshan.client.object.Server;
import org.eclipse.leshan.client.resource.ObjectsInitializer;
import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.core.util.Hex;
import org.thingsboard.lwm2m.client.LwM2MClientContext;
import org.thingsboard.lwm2m.client.LwM2MSecurityMode;

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
public class LwM2MSecurityStore{

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

    public LwM2MSecurityStore (LwM2MClientContext context, ObjectsInitializer initializer, String endpoint) {
        this.context = context;
        this.endpoint = endpoint;
        this.initializer = initializer;
        switch (LwM2MSecurityMode.fromSecurityMode(context.getDtlsMode())) {
            case PSK:
                setInstancesPSK();
                break;
            case RPK:
                setInstancesRPK();
                break;
            case X509:
                setInstancesX509();
                break;
            case NO_SEC:
                setInstancesNoSec();
        }
    }


    private void setInstancesPSK() {
        byte[] pskIdentity = !context.getPskIdentity().isEmpty() ? context.getPskIdentity().getBytes() : (endpoint + "_identity").getBytes();
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
        getParamsPSKKey(pskIdentity, pskKey);
     }

    private void setInstancesRPK() {
        String serverSecureURI = null;
        getKeyForRPK();
        if (context.getBootstrapEnable()) {
            serverSecureURI = coapLinkSec + context.getBootstrapSecureHost() + ":" + context.getBootstrapSecurePort();
            initializer.setInstancesForObject(SECURITY, rpkBootstrap(serverSecureURI, getClientPublicKey().getEncoded(),
                    getClientPrivateKey().getEncoded(), getBootstrapPublicKey().getEncoded()));
            initializer.setClassForObject(SERVER, Server.class);
        } else {
            serverSecureURI = coapLinkSec + context.getServerSecureHost() + ":" + context.getServerSecurePort();
            initializer.setInstancesForObject(SECURITY, rpk(serverSecureURI, context.getServerShortId(), getClientPublicKey().getEncoded(),
                    getClientPrivateKey().getEncoded(), getServerPublicKey().getEncoded()));
            initializer.setInstancesForObject(SERVER, new Server(context.getServerShortId(), context.getLifetime(), BindingMode.U, false));
        }
        /** Display client public key to easily add it in servers. */
        getParamsRawPublicKey(getClientPublicKey(), getClientPrivateKey());
    }

    private void setInstancesX509() {
        String serverSecureURI = null;
        getKeyCertForX509();
        try {
            if (context.getBootstrapEnable()) {
                serverSecureURI = coapLinkSec + context.getBootstrapSecureHost() + ":" + context.getBootstrapSecurePort();
                initializer.setInstancesForObject(SECURITY, x509Bootstrap(serverSecureURI, getClientCertificate().getEncoded(),
                        getClientPrivateKey().getEncoded(), getBootstrapCertificate().getEncoded()));
                initializer.setClassForObject(SERVER, Server.class);
            } else {
                serverSecureURI = coapLinkSec + context.getServerSecureHost() + ":" + context.getServerSecurePort();
                initializer.setInstancesForObject(SECURITY, x509(serverSecureURI, context.getServerShortId(), getClientCertificate().getEncoded(),
                        getClientPrivateKey().getEncoded(), getServerCertificate().getEncoded()));
                initializer.setInstancesForObject(SERVER, new Server(context.getServerShortId(), context.getLifetime(), BindingMode.U, false));
            }
            /** Display X509 credentials to easily at it in servers. */
            if (getClientCertificate() != null) {
                log.info("Client uses X509 : \n X509 Certificate (Hex): [{}] \n Private Key (Hex): [{}]",
                        Hex.encodeHexString(getClientCertificate().getEncoded()),
                        Hex.encodeHexString(getClientPrivateKey().getEncoded()));
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
        }
        else {
            serverURI = coapLink + context.getServerHost() + ":" + context.getServerPort();
            initializer.setInstancesForObject(SECURITY, noSec(serverURI, context.getServerShortId()));
            initializer.setInstancesForObject(SERVER, new Server(context.getServerShortId(), context.getLifetime(), BindingMode.U, false));
        }
    }

    private void getKeyForRPK() {
        if (context.getBootstrapEnable()) generateKeyRPK(context.getBootstrapRPkPublic_x(), context.getBootstrapRPkPublic_y(), null);
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
                    if (context.getBootstrapEnable()) this.bootstrapPublicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
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
        try (InputStream inClient = ClassLoader.getSystemResourceAsStream(context.getClientKeyStorePath())) {
            try (InputStream inServer = ClassLoader.getSystemResourceAsStream(context.getServerKeyStorePath())) {

                char[] serverKeyStorePwd = context.getServerKeyStorePwd().toCharArray();
                this.keyStoreServer = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStoreServer.load(inServer, serverKeyStorePwd);
                char[] clientKeyStorePwd = context.getClientKeyStorePwd().toCharArray();
                this.keyStoreClient = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStoreClient.load(inClient, clientKeyStorePwd);
            } catch (Exception ex) {
                log.error("Unable to load X509 keyStoreServer: [{}]", ex.getMessage());
            }
        } catch (Exception e) {
            log.error("Unable to load X509 keyStoreClient: [{}]", e.getMessage());
        }
    }


    private void getParamsPSKKey(byte[] pskIdentity, byte[] pskKey) {
        log.info("Client uses PSK : \n EndPoint : [{}] \n Identity : [{}] \n security key : [{}]",
                endpoint,
                new String(pskIdentity),
                Hex.encodeHexString(pskKey));

    }
    private void getParamsRawPublicKey(PublicKey rawPublicKey, PrivateKey clientPrivateKey) {
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
            log.info(
                    " \nClient uses RPK : \nEndpoint : [{}]\n Elliptic Curve parameters  : [{}] \n Public x coord : [{}] \n Public y coord : [{}] \n Public Key (Hex): [{}] \n Private Key (Hex): [{}]",
                    endpoint, params, Hex.encodeHexString(x), Hex.encodeHexString(y),
                    Hex.encodeHexString(rawPublicKey.getEncoded()).toUpperCase(),
                    Hex.encodeHexString(clientPrivateKey.getEncoded()));

        } else {
            throw new IllegalStateException("Unsupported Public Key Format (only ECPublicKey supported).");
        }
    }
}
