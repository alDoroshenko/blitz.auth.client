package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import ru.neoflex.wso2.blitz.client.model.IntrospectInfo;

public interface BlitzIntrospectClient {
    @RequestLine("POST")
    @Headers("Content-type:application/x-www-form-urlencoded")
    IntrospectInfo introspect(@Param("token") String token);
}
