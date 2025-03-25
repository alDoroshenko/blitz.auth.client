package ru.neoflex.wso2.blitz.client;

import feign.Response;
import feign.codec.ErrorDecoder;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;

import java.io.IOException;

import static feign.FeignException.errorStatus;
import static java.nio.charset.StandardCharsets.UTF_8;

public class CustomErrorDecoder implements ErrorDecoder {

    @Override
    public Exception decode(String s, Response response) {
        String errorDescription = getErrorDescriptionFromStream(response);
        if (StringUtils.isEmpty(errorDescription)) {
            errorDescription = response.reason();
        }
        if ((response.status() >= 400 && response.status() <= 499) ||
            (response.status() >= 500 && response.status() <= 599)) {
            return new KeyManagerClientException(response.status(), errorDescription);
        }
        return errorStatus(s, response);
    }

    private String getErrorDescriptionFromStream(Response response) {

        String errorDescription = null;
        if (response.body() != null) {
            try {
                String responseStr = IOUtils.toString(response.body().asInputStream(), UTF_8);
                JSONParser jsonParser = new JSONParser();
                JSONObject responseJson = (JSONObject) jsonParser.parse(responseStr);
                Object errorObj = responseJson.get("error_description");
                if (errorObj != null) {
                    errorDescription = errorObj.toString();
                }
            } catch (IOException | ParseException ignore) {

            }
        }
        return errorDescription;
    }
}
