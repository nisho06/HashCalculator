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

package org.wso2.carbon.core.pbkdf2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.core.pbkdf2.HashCalculator;

/**
 * This class contains the PBKDF2 hashing service component.
 */
@Component(
        name = "org.wso2.carbon.core.pbkdf2",
        immediate = true
)

public class PBKDF2ServiceComponent {

    private static Log log = LogFactory.getLog(PBKDF2ServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        HashCalculator hashCalculator = new PBKDF2HashCalculator();
        ctxt.getBundleContext().registerService(HashCalculator.class.getName(),
                hashCalculator, null);
        log.info("PBKDF2 bundle activated successfully..");
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("PBKDF2 bundle is deactivated ");
        }
    }
}
