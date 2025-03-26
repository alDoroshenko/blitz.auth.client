package ru.neoflex.wso2.blitz.client.model;

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

public class Oauth {

    @SerializedName("clientSecret")
    private String clientSecret;

    @SerializedName("redirectUriPrefixes")
    private List<String> redirectUriPrefixes = new ArrayList<>();

    @SerializedName("predefinedRedirectUri")
    private String predefinedRedirectUri;

    @SerializedName("availableScopes")
    private List<String> availableScopes = new ArrayList<>();

    @SerializedName("defaultScopes")
    private List<String> defaultScopes = new ArrayList<>();

    @SerializedName("enabled")
    private boolean enabled;

    @SerializedName("defaultAccessType")
    private String defaultAccessType;

    @SerializedName("pixyMandatory")
    private boolean pixyMandatory;

    @SerializedName("teAuthMethod")
    private String tokenEndpointAuthMethod;

    @SerializedName("grantTypes")
    private List<String> grantTypes = new ArrayList<>();

    @SerializedName("responseTypes")
    private List<String> responseTypes = new ArrayList<>();


    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getRedirectUriPrefixes() {
        return redirectUriPrefixes;
    }

    public void setRedirectUriPrefixes(List<String> redirectUriPrefixes) {
        this.redirectUriPrefixes = redirectUriPrefixes;
    }

    public String getPredefinedRedirectUri() {
        return predefinedRedirectUri;
    }

    public void setPredefinedRedirectUri(String predefinedRedirectUri) {
        this.predefinedRedirectUri = predefinedRedirectUri;
    }

    public List<String> getAvailableScopes() {
        return availableScopes;
    }

    public void setAvailableScopes(List<String> availableScopes) {
        this.availableScopes = availableScopes;
    }

    public List<String> getDefaultScopes() {
        return defaultScopes;
    }

    public void setDefaultScopes(List<String> defaultScopes) {
        this.defaultScopes = defaultScopes;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getDefaultAccessType() {
        return defaultAccessType;
    }

    public void setDefaultAccessType(String defaultAccessType) {
        this.defaultAccessType = defaultAccessType;
    }

    public boolean isPixyMandatory() {
        return pixyMandatory;
    }

    public void setPixyMandatory(boolean pixyMandatory) {
        this.pixyMandatory = pixyMandatory;
    }

    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public List<String> getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(List<String> responseTypes) {
        this.responseTypes = responseTypes;
    }
}
