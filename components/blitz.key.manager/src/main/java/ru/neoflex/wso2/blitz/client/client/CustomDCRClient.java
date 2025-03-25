package ru.neoflex.wso2.blitz.client.client;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import ru.neoflex.wso2.blitz.client.model.CustomClientInfo;
import ru.neoflex.wso2.blitz.client.model.PostClientInfo;

public interface CustomDCRClient {
    @RequestLine("POST") // PUT
    @Headers("Content-Type: application/json")
    CustomClientInfo createApplication(PostClientInfo clientInfo); // здесь переделать тело запроса на параметры, которые скинут. Запрос на регистрацию динамического клиента

    @RequestLine("GET /{clientId}")
    @Headers("Content-Type: application/json")
    // получение информации о клиенте
    CustomClientInfo getApplication(@Param("clientId") String clientId); //

    @RequestLine("PUT /{clientId}")
    @Headers("Content-Type: application/json")
    CustomClientInfo updateApplication(@Param("clientId") String clientId, CustomClientInfo customClientInfo);

    @RequestLine("DELETE /{clientId}")
    @Headers("Content-Type: application/json")
    void deleteApplication(@Param("clientId") String clientId);
}
