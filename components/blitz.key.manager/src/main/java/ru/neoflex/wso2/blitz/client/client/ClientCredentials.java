package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.Param;
import feign.RequestLine;

//TODO Переназвать интерфейс
public interface ClientCredentials {
    @RequestLine("POST")
    @Headers("Content-type:application/x-www-form-urlencoded")
    BlitzTokenResponse getToken(@Param("grant_type") String grantType, @Param("scope") String scope);
}
