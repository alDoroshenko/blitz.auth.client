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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.kmclient.FormEncoder;
import org.wso2.carbon.apimgt.impl.kmclient.model.IntrospectionClient;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import ru.neoflex.wso2.blitz.client.Interceptor.BearerTokenInterceptor;
import ru.neoflex.wso2.blitz.client.client.BlitzAdminTokenClient;
import ru.neoflex.wso2.blitz.client.client.BlitzAplicationClient;
import ru.neoflex.wso2.blitz.client.client.BlitzApplicationClient;
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

import static ru.neoflex.wso2.blitz.client.BlitzConstants.ACCESS_TYPE_OFFLINE;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.APPLICATION_REGISTRATION_ENDPOINT_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_ID_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_RESPONSE_TYPE_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_SECRET_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.DEFAULT_SCORE;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.GRANT_TYPES_FIELD;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.SCORE_FIELD;


public class BlitzOAuthClient extends AbstractKeyManager {
    private BlitzAdminTokenClient blitzAdminTokenClient;

    private BlitzApplicationClient blitzApplicationClient;
    private BlitzAdminTokenClient blitzApplicationTokenClient;
    private BearerTokenInterceptor bearerCLientTokenInterceptor = new BearerTokenInterceptor();

    private final Gson gson = new Gson();

    private static final Log log = LogFactory.getLog(BlitzOAuthClient.class);


    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        System.out.println("BlitzCustomClient loadConfiguration");

        this.configuration = keyManagerConfiguration;

        String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
        String clientId = (String) configuration.getParameter(CLIENT_ID_NAME);
        String clientSecret = (String) configuration.getParameter(CLIENT_SECRET_NAME);

        if (StringUtils.isNotEmpty(tokenEndpoint) && StringUtils.isNotEmpty(clientId) && StringUtils.isNotEmpty(clientSecret)) {
            blitzAdminTokenClient = Feign
                    .builder()
                    .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                    .decoder(new GsonDecoder(gson))
                    .encoder(new FormEncoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(new BasicAuthRequestInterceptor(clientId, clientSecret))
                    .target(BlitzAdminTokenClient.class, tokenEndpoint);

            blitzApplicationClient = Feign
                    .builder()
                    .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                    .decoder(new GsonDecoder(gson))
                    .encoder(new GsonEncoder(gson))
                    .logger(new Slf4jLogger())
                    .requestInterceptor(bearerCLientTokenInterceptor)
                    .target(BlitzApplicationClient.class, appRegistrationEndpoint);
        } else {
            throw new APIManagementException("BlitzCustomClient: Error while configuring Blitz Connector");
        }
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        System.out.println("BlitzCustomClient createApplication");

        if (oAuthAppRequest == null) {
            throw new APIManagementException("BlitzCustomClient: OAuthAppRequest cannot be null.");
        } else {
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

            String keyType = (String) oAuthApplicationInfo.getParameter(APIConstants.SUBSCRIPTION_KEY_TYPE.toLowerCase());
            String clientName = oAuthApplicationInfo.getClientName() + "_" + keyType;

            blitzAplicationClient = Feign
                    .builder()
                    .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                    .decoder(new GsonDecoder(gson))
                    .encoder(new GsonEncoder(gson))
                    .logger(new Slf4jLogger())
                    .requestInterceptor(new BearerTokenInterceptor(blitzAdminTokenResponse.getAccessToken()))
                    .target(BlitzAplicationClient.class, appRegistrationEndpoint + clientName);

            BlitzClientInfo blitzClientInfo = createBlitzClientInfo(oAuthApplicationInfo);
            blitzClientInfo.setName(clientName);
            BlitzClientInfo responceBlitzClientInfo = blitzAplicationClient.getBlitzAplicationSettings(blitzClientInfo);

            oAuthApplicationInfo = createOauthApplicationInfo(responceBlitzClientInfo);

            System.out.println("BlitzCustomClient: oAuthApplicationInfo = " +
                    oAuthApplicationInfo.getClientId() + " _ " +
                    oAuthApplicationInfo.getClientName() + " _ " +
                    oAuthApplicationInfo.getClientSecret()
            );
            return oAuthApplicationInfo;
        }
    }

    private OAuthApplicationInfo createOauthApplicationInfo(BlitzClientInfo responceBlitzClientInfo) {
        OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo();

        oAuthApplicationInfo.setClientId(responceBlitzClientInfo.getName());
        oAuthApplicationInfo.setClientName(responceBlitzClientInfo.getName());
        oAuthApplicationInfo.setClientSecret(responceBlitzClientInfo.getOauth().getClientSecret());

        if (responceBlitzClientInfo.getOauth().getRedirectUriPrefixes() != null) {
            oAuthApplicationInfo.setCallBackURL(
                    String.join(",", responceBlitzClientInfo.getOauth().getRedirectUriPrefixes())
            );
        }

        if (responceBlitzClientInfo.getOauth().getGrantTypes() != null) {
            oAuthApplicationInfo.addParameter(
                    APIConstants.KeyManager.AVAILABLE_GRANT_TYPE,
                    String.join(" ", responceBlitzClientInfo.getOauth().getGrantTypes())
            );
        }

        if (StringUtils.isNotEmpty(responceBlitzClientInfo.getName())) {
            oAuthApplicationInfo.addParameter(
                    ApplicationConstants.OAUTH_CLIENT_NAME,
                    responceBlitzClientInfo.getName()
            );
        }
        if (StringUtils.isNotEmpty(responceBlitzClientInfo.getName())) {
            oAuthApplicationInfo.addParameter(
                    ApplicationConstants.OAUTH_CLIENT_ID,
                    responceBlitzClientInfo.getName()
            );
        }
        if (StringUtils.isNotEmpty(responceBlitzClientInfo.getOauth().getClientSecret())) {
            oAuthApplicationInfo.addParameter(
                    ApplicationConstants.OAUTH_CLIENT_SECRET,
                    responceBlitzClientInfo.getOauth().getClientSecret()
            );
        }

        return oAuthApplicationInfo;
    }

    private BlitzClientInfo createBlitzClientInfo(OAuthApplicationInfo oAuthApplicationInfo) throws APIManagementException {
        System.out.println("BlitzCustomClient: createBlitzClientInfo");

        BlitzClientInfo blitzClientInfo = new BlitzClientInfo();
        Oauth oauth = new Oauth();
        String wso2URL = APIUtil.getServerURL();
        System.out.println("wso2URL:" + wso2URL);

        String clientPassword = PasswordGenerator.generatePassword();
        oauth.setClientSecret(clientPassword);
        String callBackURL = oAuthApplicationInfo.getCallBackURL();
        ArrayList<String> redirectUriPrefixes = new ArrayList<>();
        if (callBackURL != null) {
            redirectUriPrefixes.add(callBackURL);
        } else redirectUriPrefixes.add(wso2URL);

        oauth.setRedirectUriPrefixes(redirectUriPrefixes);

        ArrayList<String> scopes = new ArrayList<>();
        scopes.add(DEFAULT_SCORE);
        oauth.setAvailableScopes(scopes);
        oauth.setDefaultScopes(scopes);

        oauth.setEnabled(true);
        oauth.setDefaultAccessType(ACCESS_TYPE_OFFLINE);
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

        if (oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES) instanceof String) {
            String grandTypes = (String) oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES);
            oauth.setGrantTypes(Arrays.asList(grandTypes.split(",")));
        }

        blitzClientInfo.setDomain(wso2URL);
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
        String clientId = accessTokenRequest.getClientId();
        String clientSecret = accessTokenRequest.getClientSecret();
        String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);

        blitzAplicationTokenClient = Feign
                .builder()
                .client(new OkHttpClient(UnsafeOkHttpClient.getUnsafeOkHttpClient()))
                .decoder(new GsonDecoder(gson))
                .encoder(new FormEncoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor(clientId, clientSecret))
                .target(BlitzAdminTokenClient.class, tokenEndpoint);

        BlitzAdminTokenResponse blitzClientTokenResponse = blitzAplicationTokenClient.getToken(accessTokenRequest.getGrantType(), DEFAULT_SCORE);
        if (blitzClientTokenResponse != null) {
            tokenInfo.setAccessToken(blitzClientTokenResponse.getAccessToken());
            tokenInfo.setValidityPeriod(blitzClientTokenResponse.getExpiresIn());
            tokenInfo.setScope(accessTokenRequest.getScope());
        } else {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
        }

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

        if (tokenRequest.getClientId() == null) {
            tokenRequest.setClientId(oAuthApplication.getClientId());
        }

        if (tokenRequest.getClientSecret() == null) {
            tokenRequest.setClientSecret(oAuthApplication.getClientSecret());
        }
        System.out.println("BlitzCustomClient: grant type " + oAuthApplication.getParameter(APIConstants.JSON_GRANT_TYPES));
        if (tokenRequest.getGrantType() == null) {
            tokenRequest.setGrantType((String) oAuthApplication.getParameter(APIConstants.JSON_GRANT_TYPES));
        }

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
