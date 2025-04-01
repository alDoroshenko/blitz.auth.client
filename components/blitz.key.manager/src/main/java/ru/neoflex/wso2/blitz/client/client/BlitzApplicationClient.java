package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;
import ru.neoflex.wso2.blitz.client.model.BlitzClientInfo;

public interface BlitzApplicationClient {
    @RequestLine("PUT/{clientId}")
    @Headers("Content-Type: application/json")
    BlitzClientInfo createApplication(@Param("clientId") String clientId, BlitzClientInfo blitzClientInfo);

    @RequestLine("GET/{clientId}")
    Response getBlitzApplicationSettings(@Param("clientId") String clientId) throws KeyManagerClientException;;

    @RequestLine("POST/{clientId}")
    @Headers({
            "Content-Type: application/json",
            "if-Match: {eTag}"
    })
    BlitzClientInfo updateBlitzApplicationSettings(@Param("clientId") String clientId, @Param("eTag") String eTag, BlitzClientInfo blitzClientInfo);
}
