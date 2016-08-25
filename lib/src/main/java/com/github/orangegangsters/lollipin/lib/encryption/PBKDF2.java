package com.github.orangegangsters.lollipin.lib.encryption;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Created by sathvik on 2016-08-25.
 */
public class PBKDF2 {
    // Number of PBKDF2 hardening rounds to use. Larger values increase
    // computation time. You should select a value that causes computation
    // to take >100ms.
    private static final int ITERATIONS = 60001;

    // Generate a 256-bit key
    private static final int KEY_LENGTH = 256; // bits


    public static String hashPassword(String passphraseOrPin, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        char[] passphraseOrPinChars = passphraseOrPin.toCharArray();
        byte[] saltBytes = salt.getBytes();

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec keySpec = new PBEKeySpec(passphraseOrPinChars, saltBytes, ITERATIONS, KEY_LENGTH);

        byte[] hashedPassword = secretKeyFactory.generateSecret(keySpec).getEncoded();

        return String.format("%x", new BigInteger(hashedPassword));
    }

}
