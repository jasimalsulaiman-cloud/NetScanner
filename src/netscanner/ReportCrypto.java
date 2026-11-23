package netscanner;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and decrypts saved scan reports with a password.
 *
 * Algorithm: AES-256 in GCM mode. The key is derived from the password with
 * PBKDF2-HMAC-SHA256 (100,000 iterations) and a random salt.
 *
 * File layout:  "NSC1" | salt (16 bytes) | IV (12 bytes) | ciphertext + 16-byte tag
 */
public final class ReportCrypto {

    private static final byte[] MAGIC = {'N', 'S', 'C', '1'};
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_BITS = 256;
    private static final int ITERATIONS = 100_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private ReportCrypto() {
    }

    public static byte[] encrypt(String plainText, char[] password) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_LEN];
        byte[] iv = new byte[IV_LEN];
        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(iv);

        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(MAGIC);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return ByteBuffer.allocate(MAGIC.length + SALT_LEN + IV_LEN + cipherText.length)
                .put(MAGIC).put(salt).put(iv).put(cipherText)
                .array();
    }

    public static String decrypt(byte[] data, char[] password) throws GeneralSecurityException {
        if (data.length < MAGIC.length + SALT_LEN + IV_LEN + TAG_BITS / 8
                || !Arrays.equals(Arrays.copyOf(data, MAGIC.length), MAGIC)) {
            throw new GeneralSecurityException("This is not a NetScanner encrypted report.");
        }
        ByteBuffer buf = ByteBuffer.wrap(data);
        buf.position(MAGIC.length);
        byte[] salt = new byte[SALT_LEN];
        byte[] iv = new byte[IV_LEN];
        buf.get(salt);
        buf.get(iv);
        byte[] cipherText = new byte[buf.remaining()];
        buf.get(cipherText);

        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(MAGIC);
        try {
            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new GeneralSecurityException("Wrong password, or the file has been modified.", e);
        }
    }

    private static SecretKeySpec deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        try {
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }
}
