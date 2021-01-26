package org.wso2.carbon.core.pbkdf2;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

/**
 * This interface is the common interface for all the hashing algorithms which can be implemented from this.
 */
public interface HashCalculator {

    /**
     * This method is responsible for calculating the hash value of a value(Password, Token) using the particular
     * hashing
     * algorithm which is residing in the implemented class.
     *
     * @param value          the value which needs to be hashed. (eg:- Password, Token)
     * @param salt           the salt value which is needed for each respective passwords inorder to be hashed.
     * @param metaProperties The attribute which were needed to a hashing algorithm other than salt and value.
     * @return The calculated hash value.
     * @throws NoSuchAlgorithmException thrown if there were no such algorithm which is being specified to be used in
     * particular hashing.
     * @throws UnsupportedEncodingException thrown when the encoding feature for particular hashing was unsupported.
     * @throws InvalidKeySpecException
     */
    String calculateHash(String value, String salt, Map<String, Object> metaProperties)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException;

    /**
     * This method is responsible for returning the specific hashing algorithm is being used.
     * @return Hashing algorithm which is being used for hashing.
     */
    String getAlgorithm();
}
