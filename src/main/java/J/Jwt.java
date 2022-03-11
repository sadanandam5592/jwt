package J;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class Jwt {
    public String key = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDE7jAsAArT8SoU\n" +
            "PXUOcpibo9qC6PMBVwa/rxFu7ge9oxTXM1gDn9fmhcK7+zlzhdOLtb9lzC+ZmFMU\n" +
            "P38vhYGfBdo36FWvuFWVFF0NcCZ6LWgto0xDg0+vLoYoOCWzH8UZ3cCln6n8OH9v\n" +
            "7LwnACSx2WJBQx84jkV5EOCSgGpPPHljENy/tN+WK4+kVMVk6jhchgvm0REqnzCg\n" +
            "SiyecNr2w7PZ1AUZ2xARxqHtSBRMnUorMulblDVvXD7+l9I0+zhPPon/e7OwM+HD\n" +
            "/V+6RSe8sKUYA2W8nJvSum+7SQZ41gWW/8RMlwyK80bVvUfAT7tUAUXsXGn7rQ1a\n" +
            "OkRxAzyNAgMBAAECggEBAKt20E6fQs5CvuaclB0ePi3Vvt4Ywey6v0+KuN0jN24w\n" +
            "Xmb5d3rAZBV9BY7zMJSbQxP0DVAvNoq/jCanGrBfx/qT9+qRynmTQEDrWBHpQjdC\n" +
            "7eA+vJpT7L+U/I5sRLbvxIe/Aouytyi6cIsdTr2ObGTF57z3Gmn9xhOhVEd6tBWE\n" +
            "A8te0ZEz6bV892XCJ28GbsxKfZ0ExYJkEDUAjoh0TQ+FOrUJ73dSTsKWwH+kk2Ud\n" +
            "1eFOoYDSdEkPNn5+OAMUX9KQO0lxknexfLu9uDARLKGCp4GQqDH/BT8qWYzHGhB9\n" +
            "hDYhurSRQwe4TkPJbS68qwB5dPROlyY4xGqz6Kc5gqkCgYEA84dqf1l/73WRVvRJ\n" +
            "vKFcPDK0i7eBsmBNT2uy7ZTKSyiIXkozOqbjA8NT+9Rvsr1G/qG7XjOEvhRQT4o1\n" +
            "TNfSQTMPIOJL+Xn6mhYlMJuLc/JdD7h0E48T4ey/bwvOUXHVyuIu91AnmH9PHewS\n" +
            "/RuFru+jkQoHHPku7mfasmeDfQMCgYEAzwPhdG6biWSF0ETm8x3Pw7+u+7I4Tt4W\n" +
            "ryRYx8k5EfJGF2o6HS5BzaMZND/s7IV9D8YQ9s3rv/ubNqCbqnE2VuqVeccbhXJZ\n" +
            "mQUg+tiWtKYNl4aXINoeUoXpYIklIXkirmt2z08FLGvHFzD2sJKjXkfd4AjtQ8zT\n" +
            "zF1Mqvniwy8CgYBVCsbv7es1ThMREIHnc1noU7SkzdJm3iZhQ7TaLoluMZtdgf/d\n" +
            "zYWdPMrJOGhBPMPcC9KIlOkYD7Pz8smmKf/scM4pp5zsY+JViMI39Tl/pfVFlh5C\n" +
            "7kX9MVWwi6ji3CPSk6XfC4ioQlz4kAYZiVDnxBuUfLH7NjFjY7UFdAyAzQKBgQCi\n" +
            "3YK6f2qOpS9Bs3OfQYz7jAq2qnfyVHe0Qvw18fGcVOcf9MrTuli61940ZTaYvkyt\n" +
            "5D3kbg1TdTefuqu9ZGRD7Tq8HBFi45vp70cLEus+JIX8+D5d8jx44DHDaSJ1O0A1\n" +
            "yQYoAxsm34Q6kqMCN9ufiRrd7yf7d2IKHjz7Jq1osQKBgDfDqIKAQAeQgzGmOJW+\n" +
            "yFIMoHTD4wgIKUTxAUqzUNQbF5VBOnWRFSGR+u7tkKthfmx8osQ+usNq6z7UxFMU\n" +
            "K3bEQ9H6udEAaBhHIBNPyN1qoF3v1l/9wl463NO3DPg72cN0CAUBSWu9gFMVaZdU\n" +
            "Fe9fnkfZgD/D5KHdvDP5U9Ry\n" +
            "-----END PRIVATE KEY-----\n";

    /**
     * Convert a PKCS#8 formatted private key in string format into a java PrivateKey
     *
     * @param key
     *            PCKS#8 string
     * @return private key
     * @throws GeneralSecurityException
     *             if we couldn't parse the string
     */
    private static PrivateKey getPrivateKeyFromString(final String key) throws GeneralSecurityException {
        if (key.contains(" RSA ")) {
            throw new InvalidKeySpecException(
                    "Private key must be a PKCS#8 formatted string, to convert it from PKCS#1 use: "
                            + "openssl pkcs8 -topk8 -inform PEM -outform PEM -in current-key.pem -out new-key.pem -nocrypt");
        }

        // Remove all comments and whitespace from PEM
        // such as "-----BEGIN PRIVATE KEY-----" and newlines
        String privateKeyContent = key.replaceAll("(?m)^--.*", "").replaceAll("\\s", "");

        KeyFactory kf = KeyFactory.getInstance("RSA");

        try {
            byte[] decode = Base64.getDecoder().decode(privateKeyContent);
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(decode);

            return kf.generatePrivate(keySpecPKCS8);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Failed to decode private key: " + e.getMessage(), e);
        }
    }

    public String k() throws GeneralSecurityException {

   PrivateKey privatekey=getPrivateKeyFromString(key);
        String s = Jwts.builder()
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (100 * 60))).setIssuer("176843")
                .signWith(SignatureAlgorithm.RS256,privatekey).compact();
        return s;
    }

    public static void main(String[] args) throws GeneralSecurityException {
        Jwt jwt = new Jwt();
        System.out.println(jwt.k());
    }


}
