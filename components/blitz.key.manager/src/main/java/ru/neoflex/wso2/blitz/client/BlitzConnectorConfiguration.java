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
        return null;
    }

    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<ConfigurationDto>();
        configurationDtoList
                .add(new ConfigurationDto(
                        APPLICATION_REGISTRATION_ENDPOINT_NAME,
                        APPLICATION_REGISTRATION_ENDPOINT_LABEL,
                        FIELD_TYPE_INPUT,
                        APPLICATION_REGISTRATION_ENDPOINT_TOOLTIP,
                        EMPTY_DEFAULT_VALUE,
                        true,
                        false,
                        Collections.emptyList(),
                        false
                ));

        configurationDtoList
                .add(new ConfigurationDto(
                        CLIENT_ID_NAME,
                        CLIENT_ID_LABEL,
                        FIELD_TYPE_INPUT,
                        CLIENT_ID_TOOLTIP,
                        EMPTY_DEFAULT_VALUE,
                        true,
                        false,
                        Collections.emptyList(),
                        false));
        configurationDtoList
                .add(new ConfigurationDto(
                        CLIENT_SECRET_NAME,
                        CLIENT_SECRET_LABEL,
                        FIELD_TYPE_INPUT,
                        CLIENT_SECRET_TOOLTIP,
                        EMPTY_DEFAULT_VALUE,
                        true,
                        true,
                        Collections.emptyList(),
                        false));
        return configurationDtoList;
    }


    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {
        List<ConfigurationDto> configurationDtoList = new ArrayList<ConfigurationDto>();

        configurationDtoList
                .add(new ConfigurationDto(
                        CLIENT_RESPONSE_TYPE_NAME,
                        CLIENT_RESPONSE_TYPE_LABEL,
                        FIELD_TYPE_SELECT,
                        CLIENT_RESPONSE_TYPE_TOOLTIP,
                        EMPTY_DEFAULT_VALUE,
                        true,
                        false,
                        CLIENT_RESPONSE_TYPE_LIST,
                        true
                ));
        configurationDtoList
                .add(new ConfigurationDto(
                        CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_NAME,
                        CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_LABEL,
                        FIELD_TYPE_SELECT,
                        CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_TOOLTIP,
                        CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT_VALUE,
                        true,
                        true,
                        CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_LIST,
                        false
                ));
        return configurationDtoList;
    }

    @Override
    public String getType() {

        return BlitzConstants.BLITZ_TYPE;
    }

    @Override
    public String getDisplayName() {

        return BlitzConstants.DISPLAY_NAME;
    }
}
