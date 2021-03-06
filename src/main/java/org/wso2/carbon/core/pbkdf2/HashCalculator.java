
/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
     * @throws NoSuchAlgorithmException     thrown if there were no such algorithm which is being specified to be
     *                                      used in particular hashing.
     * @throws UnsupportedEncodingException thrown when the encoding feature for particular hashing was unsupported.
     * @throws InvalidKeySpecException
     */
    String calculateHash(String value, String salt, Map<String, Object> metaProperties)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException;

    /**
     * This method is responsible for returning the specific hashing algorithm is being used.
     *
     * @return Hashing algorithm which is being used for hashing.
     */
    String getAlgorithm();
}
