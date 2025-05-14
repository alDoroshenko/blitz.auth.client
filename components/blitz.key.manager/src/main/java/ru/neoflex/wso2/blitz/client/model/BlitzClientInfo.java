package ru.neoflex.wso2.blitz.client.model;

import com.google.gson.annotations.SerializedName;

public class BlitzClientInfo {

    @SerializedName("name")
    private String name;

    @SerializedName("domain")
    private String domain;

    @SerializedName("disabled")
    private boolean disabled;

    @SerializedName("oauth")
    private Oauth oauth;


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    public Oauth getOauth() {
        return oauth;
    }

    public void setOauth(Oauth oauth) {
        this.oauth = oauth;
    }
}
