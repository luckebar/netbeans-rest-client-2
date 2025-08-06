/*
 * Copyright 2025        Luca Bartoli <lbdevweb@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.lb.netbeans.rest.client.config;

import java.util.Objects;

/**
 *
 * @author Luca Bartoli <lbdevweb@gmail.com>
 */
public class EnvironmentConfig {
    private String environmentName;
    private String authType;
    private String username;
    private String password;
    private boolean passwordSave;
    private String token;
    private String grantType;
    private String callbackUrl;
    private String authUrl;
    private String accessTokenUrl;
    private String clientId;
    private String clientSecret;
    private String codeChallenge;
    private String codeVerifier;
    private String scope;
    private String authenticationMode;
    private String baseHost;
    
    public EnvironmentConfig() {
    }
    
    // Costruttore completo
    public EnvironmentConfig(String environmentName, String authType, String username, String password, 
                            boolean passwordSave, String token, String authUrl, String callbackUrl, 
                            String codeVerifier, String codeChallenge, String grantType, 
                            String accessTokenUrl, String clientId, String clientSecret, String scope, 
                            String authenticationMode, String baseHost) {
        this.environmentName = environmentName;
        this.authType = authType;
        this.username = username;
        this.password = password;
        this.passwordSave = passwordSave;
        this.token = token;
        this.authUrl = authUrl;
        this.callbackUrl = callbackUrl;
        this.codeVerifier = codeVerifier;
        this.codeChallenge = codeChallenge;
        this.grantType = grantType;
        this.accessTokenUrl = accessTokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scope = scope;
        this.authenticationMode = authenticationMode;
        this.baseHost = baseHost;
    }

    // Getters e setters
    public String getEnvironmentName() { return environmentName; }
    public void setEnvironmentName(String environmentName) { this.environmentName = environmentName; }
    
    public String getAuthType() { return authType; }
    public void setAuthType(String authType) { this.authType = authType; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public boolean isPasswordSave() { return passwordSave; }
    public void setPasswordSave(boolean passwordSave) { this.passwordSave = passwordSave; }
    
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    
    public String getAuthUrl() { return authUrl; }
    public void setAuthUrl(String authUrl) { this.authUrl = authUrl; }
    
    public String getCallbackUrl() { return callbackUrl; }
    public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }
    
    public String getCodeVerifier() { return codeVerifier; }
    public void setCodeVerifier(String codeVerifier) { this.codeVerifier = codeVerifier; }
    
    public String getCodeChallenge() { return codeChallenge; }
    public void setCodeChallenge(String codeChallenge) { this.codeChallenge = codeChallenge; }
    
    public String getGrantType() { return grantType; }
    public void setGrantType(String grantType) { this.grantType = grantType; }
    
    public String getAccessTokenUrl() { return accessTokenUrl; }
    public void setAccessTokenUrl(String accessTokenUrl) { this.accessTokenUrl = accessTokenUrl; }
    
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    
    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
    
    public String getAuthenticationMode() { return authenticationMode; }
    public void setAuthenticationMode(String authenticationMode) { this.authenticationMode = authenticationMode; }
    
    public String getBaseHost() { return baseHost; }
    public void setBaseHost(String baseHost) { this.baseHost = baseHost; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EnvironmentConfig that = (EnvironmentConfig) o;
        return Objects.equals(environmentName, that.environmentName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(environmentName);
    }
}