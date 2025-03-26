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
import org.wso2.carbon.apimgt.impl.recommendationmgt.AccessTokenGenerator;
import ru.neoflex.wso2.blitz.client.Interceptor.BearerTokenInterceptor;
import ru.neoflex.wso2.blitz.client.client.BlitzAdminTokenClient;
import ru.neoflex.wso2.blitz.client.client.BlitzAplicationClient;
import ru.neoflex.wso2.blitz.client.client.CustomDCRClient;
import ru.neoflex.wso2.blitz.client.model.BlitzAdminTokenResponse;
import ru.neoflex.wso2.blitz.client.model.BlitzClientInfo;
import ru.neoflex.wso2.blitz.client.model.Oauth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static ru.neoflex.wso2.blitz.client.BlitzConstants.APPLICATION_REGISTRATION_ENDPOINT_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_ID_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_SECRET_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.GRANT_TYPES_FIELD;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.REGISTRATION_API_KEY;
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
        System.out.println("loadConfiguration");

        this.configuration = keyManagerConfiguration;

        String clientRegistrationEndpoint =
                (String) configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT);
        String apiToken = (String) configuration.getParameter(REGISTRATION_API_KEY);

        String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
        String revokeEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.REVOKE_ENDPOINT);
        String clientId = (String) configuration.getParameter(CLIENT_ID_NAME);
        String clientSecret = (String) configuration.getParameter(CLIENT_SECRET_NAME);

        AccessTokenGenerator accessTokenGenerator =
                new AccessTokenGenerator(tokenEndpoint, revokeEndpoint, clientId,
                        clientSecret);

        blitzAdminTokenClient = Feign
                .builder()
                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                .decoder(new GsonDecoder(gson))
                .encoder(new FormEncoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor(clientId, clientSecret))
                .target(BlitzAdminTokenClient.class, tokenEndpoint);

        customDCRClient = Feign
                .builder()
                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                .decoder(new GsonDecoder(gson))
                .encoder(new GsonEncoder(gson))
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor(clientId, clientSecret))
                .target(CustomDCRClient.class, tokenEndpoint);

        String introspectEndpoint =
                (String) configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT);

        introspectionClient = Feign
                .builder()
                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor(clientId, clientSecret))
                .encoder(new FormEncoder())
                .target(IntrospectionClient.class, introspectEndpoint);
        System.out.println(introspectionClient);
    }


    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        System.out.println("createApplication");

        if (oAuthAppRequest == null) {
            throw new APIManagementException("OAuthAppRequest cannot be null.");
        }
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();

        System.out.println("POST request to Blitz. Get Admin Token");
        BlitzAdminTokenResponse blitzAdminTokenResponse = blitzAdminTokenClient.getToken(GRANT_TYPES_FIELD, SCORE_FIELD);
        if (blitzAdminTokenResponse == null || blitzAdminTokenResponse.getAccessToken() == null) {
            throw new APIManagementException("Failed to obtain admin token");
        }

        System.out.println("PUT request to Blitz. Set application settings");
        String appRegistrationEndpoint = (String) configuration.getParameter(APPLICATION_REGISTRATION_ENDPOINT_NAME);
        if (appRegistrationEndpoint == null) {
            throw new APIManagementException("Failed to obtain application endpoint");
        }
        String clientName = oAuthApplicationInfo.getClientName();
        if (clientName == null) {
            throw new APIManagementException("Failed to obtain application name");
        }

        blitzAplicationClient = Feign
                .builder()
                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                .decoder(new GsonDecoder(gson))
                .encoder(new GsonEncoder(gson))
                .logger(new Slf4jLogger())
                .requestInterceptor(new BearerTokenInterceptor(blitzAdminTokenResponse.getAccessToken()))
                .target(BlitzAplicationClient.class, appRegistrationEndpoint + clientName);

        ArrayList<String> redirectUriPrefixes = new ArrayList<>();//TODO захардкодить через константу или получать через какое-то поле
        redirectUriPrefixes.add("https://api-manager:9443");

        ArrayList<String> scopes = new ArrayList<>();
        scopes.add("default");

        ArrayList<String> grantTypes = new ArrayList<>();
        grantTypes.add("authorization_code");
        grantTypes.add("password");
        grantTypes.add("client_credentials");

        ArrayList<String> responseTypes = new ArrayList<>();
        responseTypes.add("code");
        responseTypes.add("token");

        //TODO нам бы сделать билдер или метод для заполнения полей объекта
        Oauth oauth = new Oauth();
        oauth.setClientSecret("test_Password");//TODO нужен генератор пароля
        oauth.setRedirectUriPrefixes(redirectUriPrefixes);
        oauth.setAvailableScopes(scopes);
        oauth.setDefaultScopes(scopes);
        oauth.setEnabled(true);
        oauth.setDefaultAccessType("offline");
        oauth.setPixyMandatory(true);
        oauth.setTokenEndpointAuthMethod("client_secret_basic");
        oauth.setGrantTypes(grantTypes);
        oauth.setResponseTypes(responseTypes);

        //TODO нам бы сделать билдер или метод для заполнения полей объекта
        BlitzClientInfo blitzClientInfo = new BlitzClientInfo();
        blitzClientInfo.setName(clientName);
        blitzClientInfo.setDomain("https://api-manager:9443");//TODO захардкодить через константу или получать через какое-то поле
        blitzClientInfo.setDisabled(false);
        blitzClientInfo.setOauth(oauth);

        BlitzClientInfo responseblitzClientInfo = blitzAplicationClient.setSetting(blitzClientInfo);

        System.out.println("POST request to Blitz. Get Application Token");

        String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);

        System.out.println(clientName);
        System.out.println(oauth.getClientSecret());
        blitzAplicationTokenClient = Feign
                .builder()
                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                .decoder(new GsonDecoder(gson))
                .encoder(new FormEncoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor(clientName, oauth.getClientSecret()))
                .target(BlitzAdminTokenClient.class, tokenEndpoint);

        BlitzAdminTokenResponse blitzClientTokenResponse = blitzAplicationTokenClient.getToken(GRANT_TYPES_FIELD, "default");

        System.out.println(blitzClientTokenResponse.getAccessToken());
        System.out.println(blitzClientTokenResponse.getTokenType());
        System.out.println(blitzClientTokenResponse.getExpiresIn());

        return null;
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

        //todo update oauth app in the authorization server

        return null;
    }

    @Override
    public OAuthApplicationInfo updateApplicationOwner(OAuthAppRequest appInfoDTO, String owner)
            throws APIManagementException {

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

        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {

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

        return oAuthAppRequest.getOAuthApplicationInfo();
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {

        // invoke APIResource registration endpoint of the authorization server and creates a new resource.

        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {

        //  retrieves the registered resource by the given API ID from the  APIResource registration endpoint.

        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {

        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {
    }

    @Override
    public void deleteMappedApplication(String clientId) throws APIManagementException {
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {

        return Collections.emptySet();
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {

        return null;
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest accessTokenRequest) throws APIManagementException {

        return null;
    }

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String apiIdsString) throws APIManagementException {

        return null;
    }

    @Override
    public void registerScope(Scope scope) throws APIManagementException {

    }

    @Override
    public Scope getScopeByName(String name) throws APIManagementException {

        return null;
    }

    @Override
    public Map<String, Scope> getAllScopes() throws APIManagementException {

        return null;
    }

    @Override
    public void attachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

    }

    @Override
    public void updateResourceScopes(API api, Set<String> oldLocalScopeKeys, Set<Scope> newLocalScopes,
                                     Set<URITemplate> oldURITemplates, Set<URITemplate> newURITemplates)
            throws APIManagementException {

    }

    @Override
    public void detachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

    }

    @Override
    public void deleteScope(String scopeName) throws APIManagementException {

    }

    @Override
    public void updateScope(Scope scope) throws APIManagementException {

    }

    @Override
    public boolean isScopeExists(String scopeName) throws APIManagementException {

        return false;
    }

    @Override
    public void validateScopes(Set<Scope> scopes) throws APIManagementException {

    }

    @Override
    public String getType() {

        return BlitzConstants.BLITZ_TYPE;
    }
}
