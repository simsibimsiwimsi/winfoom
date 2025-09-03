/*
 * Copyright (c) 2020. Eugen Covaci
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and limitations under the License.
 *
 * Changes applied to this file:
 * - exchanged basic auth verification
 * - generating API basic auth credentials if none are configured
 *
 */

package org.kpax.winfoom.api;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.kpax.winfoom.annotation.NotNull;
import org.kpax.winfoom.config.SystemConfig;
import org.kpax.winfoom.proxy.ProxyExecutorService;
import org.kpax.winfoom.util.Throwables;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * The base class for all API request handlers.
 * <p>It provides basic authentication and authorization.
 */
@Slf4j
public class GenericHttpRequestHandler implements HttpRequestHandler {

    private final UsernamePasswordCredentials credentials;

    private final ProxyExecutorService executorService;

    private final SystemConfig systemConfig;

    public GenericHttpRequestHandler(@NotNull UsernamePasswordCredentials credentials, ProxyExecutorService executorService, SystemConfig systemConfig) {
        this.credentials = credentials;
        this.executorService = executorService;
        this.systemConfig = systemConfig;
    }

    @Override
    public void handle(HttpRequest request, HttpResponse response, HttpContext context)
            throws HttpException, IOException {
        log.debug("Received request {}", request);
        boolean isAuthorized = handleAuthorization(request, response);
        if (isAuthorized) {
            Future<Object> future = executorService.submit(() -> {
                String method = request.getRequestLine().getMethod().toUpperCase(Locale.ROOT);
                switch (method) {
                    case "GET":
                        doGet(request, response, context);
                        break;
                    case "POST":
                        doPost(request, response, context);
                        break;
                    case "PUT":
                        doPut(request, response, context);
                        break;
                    case "DELETE":
                        doDelete(request, response, context);
                        break;
                    default:
                        response.setStatusCode(HttpStatus.SC_NOT_FOUND);
                        response.setReasonPhrase(String.format("No handler found for %s method", method));
                        break;
                }
                return null;
            });

            try {
                future.get(systemConfig.getApiServerRequestTimeout(), TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                log.debug("Request execution interrupted", e);
                response.setStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
                response.setEntity(new StringEntity("Command execution interrupted"));
            } catch (ExecutionException e) {
                Throwables.throwIfMatches(e.getCause(), HttpException.class);
                Throwables.throwIfMatches(e.getCause(), IOException.class);
                Throwables.throwIfMatches(e.getCause(), RuntimeException.class);
                log.debug("Error on executing request", e);
                response.setStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
                response.setEntity(new StringEntity("Error on executing command: " + e.getMessage()));
            } catch (TimeoutException e) {
                log.debug("Request timeout", e);
                response.setStatusCode(HttpStatus.SC_REQUEST_TIMEOUT);
                response.setEntity(new StringEntity("Command timeout"));
            }
        }
    }

    private boolean handleAuthorization(HttpRequest request, HttpResponse response) throws UnsupportedEncodingException {

        if(!request.containsHeader("Authorization")) {
            log.debug("API request missing Authorization header");
            return handleUnauthorized(response);
        }
        val authorization = request.getFirstHeader("Authorization").getValue();
        val validHeaderValue = "Basic " + new String(Base64.getEncoder().encode((credentials.getUserName() + ":" + credentials.getPassword()).getBytes(StandardCharsets.UTF_8)));
        if (validHeaderValue.equals(authorization)) {
            log.debug("API request authorized");
            return true;
        } else {
            log.debug("API request unauthorized");
            return handleUnauthorized(response);
        }
    }

    private boolean handleUnauthorized(HttpResponse response) throws UnsupportedEncodingException{
        response.setStatusCode(HttpStatus.SC_FORBIDDEN);
        response.setEntity(new StringEntity("Incorrect user/password"));
        return false;
    }

    public void doGet(HttpRequest request, HttpResponse response, HttpContext context)
            throws IOException {
        response.setStatusCode(HttpStatus.SC_NOT_FOUND);
        response.setReasonPhrase("No handler found for GET method");
    }

    public void doPost(HttpRequest request, HttpResponse response, HttpContext context)
            throws IOException {
        response.setStatusCode(HttpStatus.SC_NOT_FOUND);
        response.setReasonPhrase("No handler found for POST method");
    }

    public void doPut(HttpRequest request, HttpResponse response, HttpContext context) {
        response.setStatusCode(HttpStatus.SC_NOT_FOUND);
        response.setReasonPhrase("No handler found for PUT method");
    }

    public void doDelete(HttpRequest request, HttpResponse response, HttpContext context) {
        response.setStatusCode(HttpStatus.SC_NOT_FOUND);
        response.setReasonPhrase("No handler found for DELETE method");
    }

}
