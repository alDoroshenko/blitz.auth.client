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

import com.google.gson.Gson;
import feign.Feign;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.okhttp.OkHttpClient;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.kmclient.FormEncoder;
import org.wso2.carbon.apimgt.impl.kmclient.model.IntrospectionClient;
import ru.neoflex.wso2.blitz.client.Interceptor.BearerTokenInterceptor;
import ru.neoflex.wso2.blitz.client.client.BlitzAdminTokenClient;
import ru.neoflex.wso2.blitz.client.client.BlitzAplicationClient;
import ru.neoflex.wso2.blitz.client.client.CustomDCRClient;
import ru.neoflex.wso2.blitz.client.model.BlitzAdminTokenResponse;
import ru.neoflex.wso2.blitz.client.model.BlitzClientInfo;
import ru.neoflex.wso2.blitz.client.model.Oauth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ru.neoflex.wso2.blitz.client.BlitzConstants.APPLICATION_REGISTRATION_ENDPOINT_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CALLBACK_URL;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_ID_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_RESPONSE_TYPE_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_SECRET_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.DEFAULT_SCORE;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.GRANT_TYPES_FIELD;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.SCORE_FIELD;


public class BlitzOAuthClient extends AbstractKeyManager {
    private BlitzAdminTokenClient blitzAdminTokenClient;
    private BlitzAplicationClient blitzAplicationClient;
    private BlitzAdminTokenClient blitzAplicationTokenClient;

    private CustomDCRClient customDCRClient;
    private IntrospectionClient introspectionClient;

    private final Gson gson = new Gson();

    private static final Log log = LogFactory.getLog(BlitzOAuthClient.class);


    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        System.out.println("BlitzCustomClient loadConfiguration");

        this.configuration = keyManagerConfiguration;

        String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
        String clientId = (String) configuration.getParameter(CLIENT_ID_NAME);
        String clientSecret = (String) configuration.getParameter(CLIENT_SECRET_NAME);

        //TODO: добавить APIManagementException при null в стрингах
        blitzAdminTokenClient = Feign
                .builder()
                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                .decoder(new GsonDecoder(gson))
                .encoder(new FormEncoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor(clientId, clientSecret))
                .target(BlitzAdminTokenClient.class, tokenEndpoint);
    }


    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        System.out.println("BlitzCustomClient createApplication");

        if (oAuthAppRequest == null) {
            throw new APIManagementException("BlitzCustomClient: OAuthAppRequest cannot be null.");
        }
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();

        System.out.println("BlitzCustomClient: POST request to Blitz. Get Admin Token");
        BlitzAdminTokenResponse blitzAdminTokenResponse = blitzAdminTokenClient.getToken(GRANT_TYPES_FIELD, SCORE_FIELD);

        if (blitzAdminTokenResponse == null || blitzAdminTokenResponse.getAccessToken() == null) {
            throw new APIManagementException("BlitzCustomClient: Failed to obtain admin token");
        }

        System.out.println("BlitzCustomClient: PUT request to Blitz. Set application settings");

        String appRegistrationEndpoint = (String) configuration.getParameter(APPLICATION_REGISTRATION_ENDPOINT_NAME);

        if (appRegistrationEndpoint == null) {
            throw new APIManagementException("BlitzCustomClient: Failed to obtain application endpoint");
        }

        String clientName = oAuthApplicationInfo.getClientName();
        if (clientName == null) {
            throw new APIManagementException("BlitzCustomClient: Failed to obtain application name");
        }

        blitzAplicationClient = Feign
                .builder()
                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                .decoder(new GsonDecoder(gson))
                .encoder(new GsonEncoder(gson))
                .logger(new Slf4jLogger())
                .requestInterceptor(new BearerTokenInterceptor(blitzAdminTokenResponse.getAccessToken()))
                .target(BlitzAplicationClient.class, appRegistrationEndpoint + clientName);

        BlitzClientInfo blitzClientInfo = createBlitzClientInfo(oAuthApplicationInfo);
        BlitzClientInfo responseblitzClientInfo = blitzAplicationClient.getBlitzAplicationSettings(blitzClientInfo);

        //TODO: понять почему последний пост запрос возвращает 400, хотя он и правильный.
//
//        System.out.println("POST request to Blitz. Get Application Token");
//
//        String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
//        String clientSecret = oauth.getClientSecret();
//
//        System.out.println(clientName);
//        System.out.println(oauth.getClientSecret());
//        blitzAplicationTokenClient = Feign
//                .builder()
//                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
//                .decoder(new GsonDecoder(gson))
//                .encoder(new FormEncoder())
//                .logger(new Slf4jLogger())
//                .requestInterceptor(new BasicAuthRequestInterceptor(clientName, clientSecret))
//                .target(BlitzAdminTokenClient.class, tokenEndpoint);
//
//        BlitzAdminTokenResponse blitzClientTokenResponse = blitzAplicationTokenClient.getToken(GRANT_TYPES_FIELD, "default");
//
//        System.out.println(blitzClientTokenResponse.getAccessToken());
//        System.out.println(blitzClientTokenResponse.getTokenType());
//        System.out.println(blitzClientTokenResponse.getExpiresIn());

        //TODO: Добавить return OAuthApplicationInfo и метод для его конструирования
        return null;
    }

    private BlitzClientInfo createBlitzClientInfo(OAuthApplicationInfo oAuthApplicationInfo) {
        System.out.println("BlitzCustomClient: createBlitzClientInfo");

        String clientName = oAuthApplicationInfo.getClientName();

        BlitzClientInfo blitzClientInfo = new BlitzClientInfo();
        Oauth oauth = new Oauth();

        String clientPassword = PasswordGenerator.generatePassword();
        oauth.setClientSecret(clientPassword);

        ArrayList<String> redirectUriPrefixes = new ArrayList<>();
        redirectUriPrefixes.add(CALLBACK_URL);
        oauth.setRedirectUriPrefixes(redirectUriPrefixes);

        ArrayList<String> scopes = new ArrayList<>();
        scopes.add(DEFAULT_SCORE);
        oauth.setAvailableScopes(scopes);
        oauth.setDefaultScopes(scopes);

        oauth.setEnabled(true);
        oauth.setDefaultAccessType("offline");
        oauth.setPixyMandatory(true);

        Object additionalParameters = oAuthApplicationInfo.getParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES);
        Map<String, Object> additionalProperties = new HashMap<>();
        if (additionalParameters instanceof String) {
            additionalProperties = new Gson().fromJson((String) additionalParameters, Map.class);
        }

        if (additionalProperties.get(CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_NAME) instanceof String) {
            oauth.setTokenEndpointAuthMethod((String) additionalProperties.get(CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_NAME));
        }

        if (additionalProperties.get(CLIENT_RESPONSE_TYPE_NAME) instanceof List) {
            oauth.setResponseTypes((List<String>) additionalProperties.get(CLIENT_RESPONSE_TYPE_NAME));
        }

        if (oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES) instanceof String){
            String grandTypes = (String) oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES);
            oauth.setGrantTypes(Arrays.asList(grandTypes.split(",")));
        }

        blitzClientInfo.setName(clientName);
        blitzClientInfo.setDomain(CALLBACK_URL);
        blitzClientInfo.setDisabled(false);
        blitzClientInfo.setOauth(oauth);

        return blitzClientInfo;
    }

    /**
     * This method will update an existing OAuth client in Custom Authorization Server.
     *
     * @param oAuthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        System.out.println("BlitzCustomClient: updateApplication");
        //todo update oauth app in the authorization server

        return null;
    }

    @Override
    public OAuthApplicationInfo updateApplicationOwner(OAuthAppRequest appInfoDTO, String owner)
            throws APIManagementException {
        System.out.println("BlitzCustomClient: updateApplicationOwner");

        return null;
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param clientId consumer key of the OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public void deleteApplication(String clientId) throws APIManagementException {
        System.out.println("BlitzCustomClient: deleteApplication");
        //todo delete oauth app in the authorization server

    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param clientId consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {
        System.out.println("BlitzCustomClient: retrieveApplication");
        //todo retrieve oauth app in the authorization server
        return null;
    }

    /**
     * Gets new access token and returns it in an AccessTokenInfo object.
     *
     * @param accessTokenRequest Info of the token needed.
     * @return AccessTokenInfo Info of the new token.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {
        System.out.println("BlitzCustomClient: getNewApplicationAccessToken");
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        // todo implement the logic to get a new access token

        return tokenInfo;
    }

    /**
     * This is used to build accesstoken request from OAuth application info.
     *
     * @param oAuthApplication OAuth application details.
     * @param tokenRequest     AccessTokenRequest that is need to be updated with addtional info.
     * @return AccessTokenRequest after adding OAuth application details.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(
            OAuthApplicationInfo oAuthApplication, AccessTokenRequest tokenRequest) throws APIManagementException {
        System.out.println("BlitzCustomClient: buildAccessTokenRequestFromOAuthApp");

        log.debug("Invoking buildAccessTokenRequestFromOAuthApp() method..");
        if (oAuthApplication == null) {
            return tokenRequest;
        }
        if (tokenRequest == null) {
            tokenRequest = new AccessTokenRequest();
        }
        // todo implement logic to build an access token request

        return tokenRequest;
    }


    /**
     * This is used to get the meta data of the accesstoken.
     *
     * @param accessToken AccessToken.
     * @return The meta data details of accesstoken.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        System.out.println("BlitzCustomClient: getTokenMetaData");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting access token metadata from authorization server. Access token %s",
                    accessToken));
        }
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
// todo implemnt logic to get access token meta data from the introspect endpoint
        return tokenInfo;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        System.out.println("BlitzCustomClient: getKeyManagerConfiguration");
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {
        System.out.println("BlitzCustomClient: buildFromJSON");
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param oAuthAppRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        System.out.println("BlitzCustomClient: mapOAuthApplication");
        return oAuthAppRequest.getOAuthApplicationInfo();
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        System.out.println("BlitzCustomClient: registerNewResource");
        // invoke APIResource registration endpoint of the authorization server and creates a new resource.

        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        System.out.println("BlitzCustomClient: getResourceByApiId");
        //  retrieves the registered resource by the given API ID from the  APIResource registration endpoint.

        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        System.out.println("BlitzCustomClient: updateRegisteredResource");
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {
        System.out.println("BlitzCustomClient: deleteRegisteredResourceByAPIId");
    }

    @Override
    public void deleteMappedApplication(String clientId) throws APIManagementException {
        System.out.println("BlitzCustomClient: deleteMappedApplication");
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        System.out.println("BlitzCustomClient: getActiveTokensByConsumerKey");
        return Collections.emptySet();
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        System.out.println("BlitzCustomClient: getAccessTokenByConsumerKey");
        return null;
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest accessTokenRequest) throws APIManagementException {
        System.out.println("BlitzCustomClient: getNewApplicationConsumerSecret");
        return null;
    }

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String apiIdsString) throws APIManagementException {
        System.out.println("BlitzCustomClient: getScopesForAPIS");
        return null;
    }

    @Override
    public void registerScope(Scope scope) throws APIManagementException {
        System.out.println("BlitzCustomClient: registerScope");
    }

    @Override
    public Scope getScopeByName(String name) throws APIManagementException {
        System.out.println("BlitzCustomClient: getScopeByName");
        return null;
    }

    @Override
    public Map<String, Scope> getAllScopes() throws APIManagementException {
        System.out.println("BlitzCustomClient: getAllScopes");
        return null;
    }

    @Override
    public void attachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {
        System.out.println("BlitzCustomClient: attachResourceScopes");
    }

    @Override
    public void updateResourceScopes(API api, Set<String> oldLocalScopeKeys, Set<Scope> newLocalScopes,
                                     Set<URITemplate> oldURITemplates, Set<URITemplate> newURITemplates)
            throws APIManagementException {
        System.out.println("BlitzCustomClient: updateResourceScopes");
    }

    @Override
    public void detachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {
        System.out.println("BlitzCustomClient: detachResourceScopes");
    }

    @Override
    public void deleteScope(String scopeName) throws APIManagementException {
        System.out.println("BlitzCustomClient: deleteScope");
    }

    @Override
    public void updateScope(Scope scope) throws APIManagementException {
        System.out.println("BlitzCustomClient: updateScope");
    }

    @Override
    public boolean isScopeExists(String scopeName) throws APIManagementException {
        System.out.println("BlitzCustomClient: isScopeExists");
        return false;
    }

    @Override
    public void validateScopes(Set<Scope> scopes) throws APIManagementException {
        System.out.println("BlitzCustomClient: validateScopes");
    }

    @Override
    public String getType() {
        System.out.println("BlitzCustomClient: getType");
        return BlitzConstants.BLITZ_TYPE;
    }
}
