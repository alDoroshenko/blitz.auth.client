package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.RequestLine;
import ru.neoflex.wso2.blitz.client.model.CustomClientInfo;
import ru.neoflex.wso2.blitz.client.model.PostClientInfo;

public interface TokenClient {
    @RequestLine("POST")
    @Headers("Content-type:application/x-www-form-urlencoded")
    CustomClientInfo getToken(PostClientInfo clientInfo);
}
