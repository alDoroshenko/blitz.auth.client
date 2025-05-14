package ru.neoflex.wso2.blitz.client.model;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class IntrospectInfo {
    @SerializedName("client_id")
    private String clientId;

    @SerializedName("token_type")
    private String tokenType;

    @SerializedName("active")
    private boolean active;

    @SerializedName("scope")
    private String scope;

    @SerializedName("jti")
    private String jti;

    @SerializedName("exp")
    private long expiry;

    @SerializedName("iat")
    private long issuedAt;

    @SerializedName("aud")
    private List<String> audience;

    @SerializedName("sub")
    private String sub;


    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public long getExpiry() {
        return expiry;
    }

    public void setExpiry(long expiry) {
        this.expiry = expiry;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    @Override
    public String toString() {
        return "IntrospectInfo{" +
                "clientId='" + clientId + '\'' +
                ", tokenType='" + tokenType + '\'' +
                ", active=" + active +
                ", scope='" + scope + '\'' +
                ", jti='" + jti + '\'' +
                ", expiry=" + expiry +
                ", issuedAt=" + issuedAt +
                ", aud=" + audience +
                ", sub='" + sub + '\'' +
                '}';
    }
}
