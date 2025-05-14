package ru.neoflex.wso2.blitz.client.Interceptor;

import feign.RequestInterceptor;
import feign.RequestTemplate;

import java.util.Objects;

public class BearerTokenInterceptor implements RequestInterceptor {
    private String token;
    public BearerTokenInterceptor() {
        this.token = "Non Valid Token";
    }

    public void setToken (String token) {
        this.token = Objects.requireNonNull(token);
    }

    public BearerTokenInterceptor(String token) {
        this.token = Objects.requireNonNull(token);
    }

    @Override
    public void apply(RequestTemplate template) {
        template.header("Authorization", "Bearer " + token);
    }
}