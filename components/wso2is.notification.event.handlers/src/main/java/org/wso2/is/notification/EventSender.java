
/*
 *   Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.notification;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.wso2.is.notification.event.Event;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Utility class to push events.
 */
public class EventSender {

    private static final Log log = LogFactory.getLog(EventSender.class);
    private String notificationEndpoint;
    private String username;
    private char[] password;
    private Map<String, String> headers;
    private static final ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(200, 500, 100L,
            TimeUnit.SECONDS,
            new LinkedBlockingDeque<Runnable>() {
            });

    public EventSender(String notificationEndpoint, String userName, String password, Map<String, String> headers) {

        this.notificationEndpoint = notificationEndpoint;
        this.username = userName;
        this.password = password.toCharArray();
        this.headers = headers;
    }

    public EventSender(String notificationEndpoint, Map<String, String> headers) {

        this.notificationEndpoint = notificationEndpoint;
        this.headers = headers;
    }

    public void publishEvent(Event event) {

        EventRunner eventRunner =
                new EventRunner(notificationEndpoint, username, String.valueOf(password), headers, event);
        threadPoolExecutor.execute(eventRunner);
    }

    /**
     * This method is used to create a custom SSL Context instead of using the default
     *
     * @return The custom SSLContext
     * @throws KeyStoreException Throws a KeyStoreException
     * @throws NoSuchAlgorithmException Throws a NoSuchAlgorithmException
     * @throws CertificateException Throws a CertificateException
     * @throws IOException Throws a IOException
     * @throws KeyManagementException Throws a KeyManagementException
     */
    private static SSLContext createCustomSSLContext()
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            KeyManagementException {
        String trustStorePath = System.getProperty(NotificationConstants.SSLProperties.TRUSTSTORE);
        String trustStorePassword = System.getProperty(NotificationConstants.SSLProperties.TRUSTSTORE_PASSWORD);
        String trustStoreType = System.getProperty(NotificationConstants.SSLProperties.TRUSTSTORE_TYPE);
        if (trustStorePath == null || trustStorePassword == null) {
            throw new IllegalArgumentException("Truststore properties are not properly set.");
        }
        if (trustStoreType == null) {
            trustStoreType = "JKS";
        }
        KeyStore trustStore = KeyStore.getInstance(trustStoreType);
        // Load Truststore
        try (InputStream is = Files.newInputStream(Paths.get(trustStorePath))) {
            trustStore.load(is, trustStorePassword.toCharArray());
        }
        // Initialize TrustManagerFactory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        // Create SSL context
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), new SecureRandom());
        return context;
    }

    /**
     * Runnable Thread to send Event
     */
    public static class EventRunner implements Runnable {

        private String notificationEndpoint;
        private String username;
        private String password;
        private Map<String, String> headers;
        private Event event;
        private static final SSLContext customSSLContext;

        static {
            SSLContext context = null;
            try {
                context = createCustomSSLContext();
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException |
                    CertificateException | KeyManagementException e) {
                log.error("Failed to initialize custom SSL context during static init", e);
            }
            customSSLContext = context;
        }

        public EventRunner(String notificationEndpoint, String username, String password,
                           Map<String, String> headers, Event event) {

            this.notificationEndpoint = notificationEndpoint;
            this.username = username;
            this.password = password;
            this.headers = headers;
            this.event = event;
        }

        @Override
        public void run() {
            String hostNameVerifier = System.getProperty("httpclient.hostnameVerifier");
            String disableHostnameVerification = System.getProperty(
                    "org.opensaml.httpclient.https.disableHostnameVerification");
            CloseableHttpClient closeableHttpClient = null;
            if (Boolean.parseBoolean(disableHostnameVerification) || "AllowAll".equals(hostNameVerifier)) {
                if (customSSLContext != null) {
                    SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(customSSLContext,
                            new AllowAllHostnameVerifier());
                    closeableHttpClient = HttpClientBuilder.create().setSSLSocketFactory(sslSocketFactory)
                            .setHostnameVerifier(new AllowAllHostnameVerifier()).useSystemProperties().build();
                }
            } else {
                if (customSSLContext != null) {
                    SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(customSSLContext);
                    closeableHttpClient = HttpClientBuilder.create().setSSLSocketFactory(sslSocketFactory)
                            .useSystemProperties().build();
                }
            }
            try {
                HttpPost httpPost = new HttpPost(notificationEndpoint);
                if (StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password)) {
                    byte[] credentials =
                            Base64.encodeBase64((username + ":" + password).getBytes(StandardCharsets.UTF_8));
                    httpPost.addHeader("Authorization", "Basic " + new String(credentials, StandardCharsets.UTF_8));
                }
                headers.forEach((key, value) -> {
                    httpPost.addHeader(key, value);
                });

                String content = new Gson().toJson(event);
                StringEntity requestEntity = new StringEntity(content);
                requestEntity.setContentType("application/json");
                httpPost.setEntity(requestEntity);
                if (closeableHttpClient != null) {
                    try (CloseableHttpResponse execute = closeableHttpClient.execute(httpPost)) {
                    }
                } else {
                    log.error("HttpClient is null. Cannot execute request.");
                }
            } catch (IOException e) {
                log.error("Error while sending Revocation Event to " + notificationEndpoint, e);
            }
        }
    }
}
