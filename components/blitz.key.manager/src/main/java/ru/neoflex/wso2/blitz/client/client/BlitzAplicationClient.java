package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.RequestLine;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import ru.neoflex.wso2.blitz.client.model.BlitzClientInfo;

public interface BlitzAplicationClient {
    @RequestLine("PUT")
    @Headers("Content-Type: application/json")
    BlitzClientInfo getBlitzAplicationSettings(BlitzClientInfo blitzClientInfo);
}
