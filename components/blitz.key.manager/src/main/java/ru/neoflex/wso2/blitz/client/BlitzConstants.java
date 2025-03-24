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

/**
 * This class will hold constants related to Okta key manager implementation.
 */
public class BlitzConstants {
    public static final String UTF_8 = "UTF-8";
    public static final String CUSTOM_TYPE = "Custom";
    public static final String DISPLAY_NAME = "Custom";


    public static final String CLIENT_ID_NAME = "client_id";
    public static final String CLIENT_ID_LABEL = "Client ID";
    public static final String CLIENT_ID_TYPE = "input";
    public static final String CLIENT_ID_TOOLTIP = "Client ID of service Application";
    public static final String CLIENT_ID_DEFAULT_VALUE = "";
    public static final boolean CLIENT_ID_REQUIRED = true;
    public static final boolean CLIENT_ID_MASK = false;
    public static final boolean CLIENT_ID_MULTIPLE = false;

    public static final String CLIENT_SECRET_NAME = "client_secret";
    public static final String CLIENT_SECRET_LABEL = "Client Secret";
    public static final String CLIENT_SECRET_TYPE = "input";
    public static final String CLIENT_SECRET_TOOLTIP = "Client secret of service Application";
    public static final String CLIENT_SECRET_DEFAULT_VALUE = "";
    public static final boolean CLIENT_SECRET_REQUIRED = true;
    public static final boolean CLIENT_SECRET_MASK = true;
    public static final boolean CLIENT_SECRET_MULTIPLE = false;

    public static final String CLIENT_APPLICATION_TYPE_NAME = "application_type";
    public static final String CLIENT_APPLICATION_TYPE_LABEL = "Application Type";
    public static final String CLIENT_APPLICATION_TYPE_TYPE = "select";
    public static final String CLIENT_APPLICATION_TYPE_TOOLTIP = "Type Of Application to create";
    public static final String CLIENT_APPLICATION_TYPE_DEFAULT_VALUE = "web";
    public static final boolean CLIENT_APPLICATION_TYPE_REQUIRED = false;
    public static final boolean CLIENT_APPLICATION_TYPE_MASK = false;
    public static final boolean CLIENT_APPLICATION_TYPE_MULTIPLE = false;

    public static final String CLIENT_RESPONSE_TYPE_NAME = "response_types";
    public static final String CLIENT_RESPONSE_TYPE_LABEL = "Response Type";
    public static final String CLIENT_RESPONSE_TYPE_TYPE = "select";
    public static final String CLIENT_RESPONSE_TYPE_TOOLTIP = "Type Of Token response";
    public static final String CLIENT_RESPONSE_TYPE_DEFAULT_VALUE = "";
    public static final boolean CLIENT_RESPONSE_TYPE_REQUIRED = true;
    public static final boolean CLIENT_RESPONSE_TYPE_MASK = false;
    public static final boolean CLIENT_RESPONSE_TYPE_MULTIPLE = true;

    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_NAME = "token_endpoint_auth_method";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_LABEL = "Token endpoint Authentication Method";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_TYPE = "select";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_TOOLTIP = "How to Authenticate Token Endpoint";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT_VALUE = "client_secret_basic";
    public static final boolean CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_REQUIRED = true;
    public static final boolean CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_MASK = true;
    public static final boolean CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_MULTIPLE = false;

    BlitzConstants() {
    }
}
