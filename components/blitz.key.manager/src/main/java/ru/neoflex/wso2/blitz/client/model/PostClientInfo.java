package ru.neoflex.wso2.blitz.client.model;

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_ID_NAME;
import static ru.neoflex.wso2.blitz.client.BlitzConstants.CLIENT_SECRET_NAME;

public class PostClientInfo {
    @SerializedName("grant_types")
    private String grantTypes;
    @SerializedName("scope")
    private String scope;

    public String getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(String grantTypes) {
        this.grantTypes = grantTypes;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
