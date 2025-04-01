package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;
import ru.neoflex.wso2.blitz.client.model.BlitzClientInfo;

public interface BlitzApplicationClient {
    @RequestLine("PUT/{clientId}")
    @Headers("Content-Type: application/json")
    BlitzClientInfo setBlitzApplicationSettings(@Param("clientId") String clientId, BlitzClientInfo blitzClientInfo);

    @RequestLine("GET/{clientId}")
    Response getBlitzApplicationSettings(@Param("clientId") String clientId);
}
