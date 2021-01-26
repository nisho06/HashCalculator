package org.wso2.carbon.core.pbkdf2.internal;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.wso2.carbon.core.pbkdf2.constants.Constants;
import org.wso2.carbon.core.pbkdf2.HashCalculator;

/**
 * This class contains the implementation for the PBKDF2 hashing algorithm.
 */
public class PBKDF2HashCalculator implements HashCalculator {

    // TODO: 2021-01-22 package name should include identity
    public PBKDF2HashCalculator() {

    }

    @Override
    public String calculateHash(String value, String salt, Map<String, Object> metaProperties)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {

        PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), base64ToByteArray(salt),
                (int) (metaProperties.get("Iteration Count")), (int) (metaProperties.get("Derived Key Length")));
        SecretKeyFactory skf = SecretKeyFactory.getInstance(Constants.PBKDF2_PRF);
        byte[] hash = skf.generateSecret(spec).getEncoded();
        String base64Hash = new String(Base64.getEncoder().encode(hash));
        return base64Hash;
    }

    @Override
    public String getAlgorithm() {

        return Constants.PBKDF2_PRF;
    }

    /**
     * this method is responsible for converting the base64 string value value of salt to byte array.
     *
     * @param Salt The salt value which needs to be converted into byte array.
     * @return The converted byte array from base64 Salt value.
     * @throws UnsupportedEncodingException when the base64 encoding does not support.
     */
    private byte[] base64ToByteArray(String Salt) throws UnsupportedEncodingException {

        byte[] name = Base64.getEncoder().encode(Salt.getBytes());
        byte[] decodedString = Base64.getDecoder().decode(new String(name).getBytes("UTF-8"));
        return decodedString;
    }
}
