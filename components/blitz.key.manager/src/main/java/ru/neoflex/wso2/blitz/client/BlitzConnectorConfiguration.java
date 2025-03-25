/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package ru.neoflex.wso2.blitz.client;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static ru.neoflex.wso2.blitz.client.BlitzConstants.*;

@Component(
        name = "custom.configuration.component",
        immediate = true,
        service = KeyManagerConnectorConfiguration.class
)
public class BlitzConnectorConfiguration implements KeyManagerConnectorConfiguration {

    @Override
    public String getImplementation() {

        return BlitzOAuthClient.class.getName();
    }

    @Override
    public String getJWTValidator() {

        // If you need to implement a custom JWT validation logic you need to implement
        // org.wso2.carbon.apimgt.impl.jwt.JWTValidator interface and instantiate it in here.
        return null;
    }

    /*
     *  Provides list of Configurations that need to show in Admin portal in order to connect with KeyManager
     *
     *
     * */
    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<ConfigurationDto>();

        configurationDtoList
                .add(new ConfigurationDto(CLIENT_ID_NAME, CLIENT_ID_LABEL, CLIENT_ID_TYPE, CLIENT_ID_TOOLTIP, CLIENT_ID_DEFAULT_VALUE,
                        CLIENT_ID_REQUIRED, CLIENT_ID_MASK,
                        Collections.emptyList(),
                        CLIENT_ID_MULTIPLE));
        configurationDtoList
                .add(new ConfigurationDto(CLIENT_SECRET_NAME, CLIENT_SECRET_LABEL, CLIENT_SECRET_TYPE,
                        CLIENT_SECRET_TOOLTIP, CLIENT_SECRET_DEFAULT_VALUE, CLIENT_SECRET_REQUIRED,
                        CLIENT_SECRET_MASK,
                        Collections.emptyList(),
                        CLIENT_SECRET_MULTIPLE));
        return configurationDtoList;
    }

    /*
     *   Provides list of configurations need to create Oauth applications in Oauth server in Devportal
     *
     * */
    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {
        List<ConfigurationDto> configurationDtoList = new ArrayList<ConfigurationDto>();

        configurationDtoList.add(new ConfigurationDto(CLIENT_APPLICATION_TYPE_NAME, CLIENT_APPLICATION_TYPE_LABEL,
                CLIENT_APPLICATION_TYPE_TYPE, CLIENT_APPLICATION_TYPE_TOOLTIP, CLIENT_APPLICATION_TYPE_DEFAULT_VALUE,
                CLIENT_APPLICATION_TYPE_REQUIRED, CLIENT_APPLICATION_TYPE_MASK,
                Arrays.asList("web", "native", "service", "browser"),
                CLIENT_APPLICATION_TYPE_MULTIPLE
        ));
        configurationDtoList.add(new ConfigurationDto(
                CLIENT_RESPONSE_TYPE_NAME, CLIENT_RESPONSE_TYPE_LABEL, CLIENT_RESPONSE_TYPE_TYPE, CLIENT_RESPONSE_TYPE_TOOLTIP,
                CLIENT_RESPONSE_TYPE_DEFAULT_VALUE, CLIENT_RESPONSE_TYPE_REQUIRED, CLIENT_RESPONSE_TYPE_MASK,
                Arrays.asList("code", "token", "id_token"),
                CLIENT_RESPONSE_TYPE_MULTIPLE
        ));
        configurationDtoList.add(new ConfigurationDto(
                CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_NAME, CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_LABEL, CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_TYPE,
                CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_TOOLTIP, CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT_VALUE, CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_REQUIRED,
                CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_MASK,
                Arrays.asList("client_secret_basic", "client_secret_post", "client_secret_jwt"),
                CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_MULTIPLE
        ));
        return configurationDtoList;
    }

    @Override
    public String getType() {

        return BlitzConstants.CUSTOM_TYPE;
    }

    @Override
    public String getDisplayName() {

        return BlitzConstants.DISPLAY_NAME;
    }
}
