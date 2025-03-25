package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.Param;
import feign.RequestLine;

//TODO Переназвать интерфейс
public interface TokenClient {
    @RequestLine("POST")
    @Headers("Content-type:application/x-www-form-urlencoded")
    PasswortClient getToken(@Param("grant_type") String grantType, @Param("scope") String scope);
}
