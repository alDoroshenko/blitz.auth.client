package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import ru.neoflex.wso2.blitz.client.model.BlitzAdminTokenResponse;

public interface BlitzAdminTokenClient {
    @RequestLine("POST")
    @Headers("Content-type:application/x-www-form-urlencoded")
    BlitzAdminTokenResponse getToken(@Param("grant_type") String grantType, @Param("scope") String scope);
}
