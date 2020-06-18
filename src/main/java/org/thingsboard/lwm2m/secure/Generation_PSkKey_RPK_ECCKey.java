package org.thingsboard.lwm2m.secure;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.leshan.core.util.Hex;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

@Slf4j
public class Generation_PSkKey_RPK_ECCKey {
    public static void main(String[] args) throws Exception {
        /** PSK */
        int lenPSkKey = 32;
        /** RPK */
        String algorithm = "EC";
        String provider = "SunEC";
        String nameParameterSpec = "secp256r1";

        /** Start PSK
         * Clients and Servers MUST support PSK keys of up to 64 bytes in length, as required by [RFC7925]
         * SecureRandom object must be unpredictable, and all SecureRandom output sequences must be cryptographically strong, as described in [RFC4086]
         * */
        SecureRandom randomPSK = new SecureRandom();
        byte bytesPSK[] = new byte[lenPSkKey];
        randomPSK.nextBytes(bytesPSK);
        log.info("PSK key:  [{}]", Hex.encodeHexString(bytesPSK));

        /** Start RPK
         * Elliptic Curve parameters  : [secp256r1 [NIST P-256, X9.62 prime256v1] (1.2.840.10045.3.1.7)]
         * */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
        ECGenParameterSpec ecsp = new ECGenParameterSpec(nameParameterSpec);
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        if (pubKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) pubKey;
            /** Get x coordinate */
            byte[] x = ecPublicKey.getW().getAffineX().toByteArray();
            if (x[0] == 0)
                x = Arrays.copyOfRange(x, 1, x.length);

            /** Get Y coordinate */
            byte[] y = ecPublicKey.getW().getAffineY().toByteArray();
            if (y[0] == 0)
                y = Arrays.copyOfRange(y, 1, y.length);

            /** Get Curves params */
            String privHex = Hex.encodeHexString(privKey.getEncoded());
            log.info("Elliptic Curve parameters  : [{}]", ecPublicKey.getParams().toString());
            log.info("public_x :  [{}]", Hex.encodeHexString(x));
            log.info("public_y :  [{}]", Hex.encodeHexString(y));
            log.info("private_s : [{}]", privHex.substring(privHex.length() - 64));
            log.info("Public Key (Hex): [{}]", Hex.encodeHexString(pubKey.getEncoded()));
            log.info("Private Key (Hex): [{}]", Hex.encodeHexString(privKey.getEncoded()));
        }
        /**
         *   Elliptic Curve parameters  : [secp256r1 [NIST P-256, X9.62 prime256v1] (1.2.840.10045.3.1.7)]
         *  Public x coord : [89c048261979208666f2bfb188be1968fc9021c416ce12828c06f4e314c167b5]
         *  Public y coord : [cbf1eb7587f08e01688d9ada4be859137ca49f79394bad9179326b3090967b68]
         *  Public Key (Hex):  [3059301306072A8648CE3D020106082A8648CE3D03010703420004 89C048261979208666F2BFB188BE1968FC9021C416CE12828C06F4E314C167B5 CBF1EB7587F08E01688D9ADA4BE859137CA49F79394BAD9179326B3090967B68]
         rpk_public_x: "${RPK_CLIENT_PUBLIC_X:                                         89c048261979208666f2bfb188be1968fc9021c416ce12828c06f4e314c167b5}"
         rpk_public_y: "${RPK_CLIENT_PUBLIC_Y:                                                                                                          cbf1eb7587f08e01688d9ada4be859137ca49f79394bad9179326b3090967b68}"
         *  Private Key (Hex): [3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420 e67b68d2aaeb6550f19d98cade3ad62b39532e02e6b422e1f7ea189dabaea5d2]
         rpk_private_s: "${RPK_CLIENT_PRIVATE_S:                                                       e67b68d2aaeb6550f19d98cade3ad62b39532e02e6b422e1f7ea189dabaea5d2}"

         /**
         * new
         pubEn : 3059301306072a8648ce3d020106082a8648ce3d03010703420004 33dd9c657e9d17ece73c40c1718ebcc6047bd312530faee8446c604093fe6f00 f15c1c62d516c792d1334edc9a93140a70e999ff5cbf928b1ecf2fdff0b81c19
         x :                                                            33dd9c657e9d17ece73c40c1718ebcc6047bd312530faee8446c604093fe6f00 lenth : 32
         y :                                                                                                                             f15c1c62d516c792d1334edc9a93140a70e999ff5cbf928b1ecf2fdff0b81c19 lenth : 32
         prvEn : 3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420 5f0c08da13583f965324e7619aa7af1401a79da99ccd54820bdd486ebcfa0d5a
         s :                                                                            5f0c08da13583f965324e7619aa7af1401a79da99ccd54820bdd486ebcfa0d5a lenth : 64
         */


    }
}
