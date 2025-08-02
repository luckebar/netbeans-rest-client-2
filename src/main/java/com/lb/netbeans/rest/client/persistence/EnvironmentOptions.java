package com.lb.netbeans.rest.client.persistence;

import com.lb.netbeans.rest.client.ui.AuthPanel;
import com.lb.netbeans.rest.client.ui.UrlPanel;
import com.lb.netbeans.rest.client.ui.RestClientTopComponent;
import com.lb.netbeans.rest.client.RestClient;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * Utility methods to persist and load environment options (.rstopt files).
 */
public class EnvironmentOptions {

    private EnvironmentOptions() {
    }

    public static void save(File file, String env, AuthPanel authPanel, UrlPanel urlPanel) throws IOException {
        Properties props = new Properties();
        if (file.exists()) {
            try (InputStream in = new FileInputStream(file)) {
                props.load(in);
            }
        }
        String prefix = env + ".";
        props.setProperty(prefix + RestClientTopComponent.URL_PROPERTY, urlPanel.getUrl());
        props.setProperty(prefix + RestClientTopComponent.AUTH_TYPE_PROPERTY, authPanel.getAuthType());
        props.setProperty(prefix + RestClientTopComponent.USERNAME_PROPERTY, authPanel.getUsername());
        props.setProperty(prefix + RestClientTopComponent.PASSWORD_PROPERTY, authPanel.getPassword());
        props.setProperty(prefix + RestClientTopComponent.TOKEN_CC_PROPERTY, authPanel.getToken());
        props.setProperty(prefix + RestClientTopComponent.GRANT_TYPE_PROPERTY, authPanel.getGrantType());
        props.setProperty(prefix + RestClientTopComponent.ACCESS_TOKEN_URL_PROPERTY, authPanel.getAccessTokenUrl());
        props.setProperty(prefix + RestClientTopComponent.CLIENT_ID_PROPERTY, authPanel.getClientId());
        props.setProperty(prefix + RestClientTopComponent.CLIENT_SECRET_PROPERTY, authPanel.getClientSecret());
        props.setProperty(prefix + RestClientTopComponent.SCOPE_PROPERTY, authPanel.getScope());
        props.setProperty(prefix + RestClientTopComponent.AUTH_MODE_PROPERTY, authPanel.getAuthenticationMode());
        props.setProperty(prefix + RestClientTopComponent.AUTH_URL_PROPERTY, authPanel.getAuthUrl());
        props.setProperty(prefix + RestClientTopComponent.CALLBACK_URL_PROPERTY, authPanel.getCallbackUrl());
        props.setProperty(prefix + RestClientTopComponent.CODE_VERIFIER_PROPERTY, authPanel.getCodeVerifier());
        props.setProperty(prefix + RestClientTopComponent.CODE_CHALLENGE_PROPERTY, authPanel.getCodeChallenge());
        try (OutputStream out = new FileOutputStream(file)) {
            props.store(out, "REST Client Options");
        }
    }

    public static List<String> getEnvironmentNames(File file) throws IOException {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(file)) {
            props.load(in);
        }
        Set<String> envs = new HashSet<>();
        for (String key : props.stringPropertyNames()) {
            int idx = key.indexOf('.');
            if (idx > 0) {
                envs.add(key.substring(0, idx));
            }
        }
        return new ArrayList<>(envs);
    }

    public static void load(File file, String env, AuthPanel authPanel, UrlPanel urlPanel) throws IOException {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(file)) {
            props.load(in);
        }
        String prefix = env + ".";
        authPanel.setAuthType(props.getProperty(prefix + RestClientTopComponent.AUTH_TYPE_PROPERTY, RestClient.NO_AUTH));
        authPanel.setUsername(props.getProperty(prefix + RestClientTopComponent.USERNAME_PROPERTY, ""));
        authPanel.setPassword(props.getProperty(prefix + RestClientTopComponent.PASSWORD_PROPERTY, ""));
        authPanel.setToken(props.getProperty(prefix + RestClientTopComponent.TOKEN_CC_PROPERTY, ""));
        authPanel.setGrantType(props.getProperty(prefix + RestClientTopComponent.GRANT_TYPE_PROPERTY, "Manual"));
        authPanel.setAccessTokenUrl(props.getProperty(prefix + RestClientTopComponent.ACCESS_TOKEN_URL_PROPERTY, ""));
        authPanel.setClientId(props.getProperty(prefix + RestClientTopComponent.CLIENT_ID_PROPERTY, ""));
        authPanel.setClientSecret(props.getProperty(prefix + RestClientTopComponent.CLIENT_SECRET_PROPERTY, ""));
        authPanel.setScope(props.getProperty(prefix + RestClientTopComponent.SCOPE_PROPERTY, ""));
        authPanel.setAuthenticationMode(props.getProperty(prefix + RestClientTopComponent.AUTH_MODE_PROPERTY, ""));
        authPanel.setAuthUrl(props.getProperty(prefix + RestClientTopComponent.AUTH_URL_PROPERTY, ""));
        authPanel.setCallbackUrl(props.getProperty(prefix + RestClientTopComponent.CALLBACK_URL_PROPERTY, ""));
        authPanel.setCodeVerifier(props.getProperty(prefix + RestClientTopComponent.CODE_VERIFIER_PROPERTY, ""));
        authPanel.setCodeChallenge(props.getProperty(prefix + RestClientTopComponent.CODE_CHALLENGE_PROPERTY, ""));
        urlPanel.setUrl(props.getProperty(prefix + RestClientTopComponent.URL_PROPERTY, ""));
    }
}
