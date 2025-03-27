/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package ru.neoflex.wso2.blitz.client;

import java.util.Arrays;
import java.util.List;

public class BlitzConstants {
    public static final String UTF_8 = "UTF-8";
    public static final String BLITZ_TYPE = "Blitz";
    public static final String DISPLAY_NAME = "Blitz";
    public static final  String FIELD_TYPE_INPUT = "input";
    public static final  String FIELD_TYPE_SELECT = "select";
    public static final String EMPTY_DEFAULT_VALUE = "";

    public static final String CLIENT_ID_NAME = "client_id";
    public static final String CLIENT_ID_LABEL = "Client ID";
    public static final String CLIENT_ID_TOOLTIP = "Client ID of service Application";

    public static final String CLIENT_SECRET_NAME = "client_secret";
    public static final String CLIENT_SECRET_LABEL = "Client Secret";
    public static final String CLIENT_SECRET_TOOLTIP = "Client secret of service Application";

    public static final String APPLICATION_REGISTRATION_ENDPOINT_NAME = "app_registration_endpoint";
    public static final String APPLICATION_REGISTRATION_ENDPOINT_LABEL = "App Registration Endpoint";
    public static final String APPLICATION_REGISTRATION_ENDPOINT_TOOLTIP = "Endpoint for Application Registration";

    public static final String CLIENT_RESPONSE_TYPE_NAME = "response_types";
    public static final String CLIENT_RESPONSE_TYPE_LABEL = "Response Type";
    public static final String CLIENT_RESPONSE_TYPE_TOOLTIP = "Type Of Token response";
    public static final List<String> CLIENT_RESPONSE_TYPE_LIST = Arrays.asList("code", "token", "id_token", "device_code");

    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_NAME = "token_endpoint_auth_method";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_LABEL = "Token endpoint Authentication Method";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_TOOLTIP = "How to Authenticate Token Endpoint";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT_VALUE = "client_secret_basic";
    public static final List<String> CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_LIST = Arrays.asList(
            "client_secret_basic", "client_secret_post", "client_secret_jwt");

    public static final String REGISTRATION_API_KEY = "API Token";

    public static final String GRANT_TYPES_FIELD = "client_credentials";
    public static final String SCORE_FIELD = "blitz_api_sys_app blitz_api_sys_app_chg";

    public static final String DEFAULT_SCORE = "default";
    public static final String CALLBACK_URL = "https://api-manager:9443";

    BlitzConstants() {
    }
}
