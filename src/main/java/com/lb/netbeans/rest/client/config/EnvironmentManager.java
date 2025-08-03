package com.lb.netbeans.rest.client.config;


import com.lb.netbeans.rest.client.ui.RestClientTopComponent;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonWriter;
import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import org.openide.filesystems.FileChooserBuilder;
import org.openide.filesystems.FileUtil;
import org.openide.util.NbBundle;

public class EnvironmentManager {
    private static final Logger logger = Logger.getLogger(EnvironmentManager.class.getName());
    
    public static final String ENVIRONMENT_FILE_EXTENSION = "rstopt";
    public static final String ENVIRONMENT_FILE_DESCRIPTION = "REST Client Environment (*.rstopt)";
    public static final String IMPORT_FILE_PROPERTIES = "Import File Properties";
    
    private EnvironmentManager() {
    }
    
    public static void saveEnvironment(File file, String environmentName, EnvironmentConfig config) throws IOException {
        Map<String, EnvironmentConfig> existingEnvironments = new HashMap<>();
        
        // Se il file esiste già, carica le configurazioni esistenti
        if (file.exists()) {
            try (InputStream is = new FileInputStream(file);
                 JsonReader reader = Json.createReader(is)) {
                
                JsonArray jsonArray = reader.readArray();
                for (int i = 0; i < jsonArray.size(); i++) {
                    JsonObject obj = jsonArray.getJsonObject(i);
                    EnvironmentConfig envConfig = parseEnvironmentConfig(obj);
                    existingEnvironments.put(envConfig.getEnvironmentName(), envConfig);
                }
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error loading existing environments", e);
            }
        }
        
        // Aggiorna o aggiunge la configurazione
        config.setEnvironmentName(environmentName);
        existingEnvironments.put(environmentName, config);
        
        // Salva tutte le configurazioni
        try (OutputStream os = new FileOutputStream(file);
             JsonWriter writer = Json.createWriter(os)) {
            
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            for (EnvironmentConfig envConfig : existingEnvironments.values()) {
                arrayBuilder.add(buildJsonObject(envConfig));
            }
            writer.writeArray(arrayBuilder.build());
        }
    }
    
    public static Map<String, EnvironmentConfig> loadEnvironments(File file) throws IOException {
        Map<String, EnvironmentConfig> environments = new HashMap<>();
        
        if (!file.exists()) {
            return environments;
        }
        
        try (InputStream is = new FileInputStream(file);
             JsonReader reader = Json.createReader(is)) {
            
            JsonArray jsonArray = reader.readArray();
            for (int i = 0; i < jsonArray.size(); i++) {
                JsonObject obj = jsonArray.getJsonObject(i);
                EnvironmentConfig config = parseEnvironmentConfig(obj);
                environments.put(config.getEnvironmentName(), config);
            }
        }
        
        return environments;
    }
    
    public static void updateEnvironment(File file, String environmentName, EnvironmentConfig config) throws IOException {
        saveEnvironment(file, environmentName, config);
    }
    
    public static File chooseEnvironmentFileForSave(RestClientTopComponent topComponent) {
        FileChooserBuilder builder = new FileChooserBuilder(EnvironmentManager.class)
                .setTitle(NbBundle.getMessage(EnvironmentManager.class, "CTL_SaveEnvironmentDialogTitle"))
                .setFilesOnly(true)
                //.setDefaultExtension(ENVIRONMENT_FILE_EXTENSION)
                .setAcceptAllFileFilterUsed(false)
                .setFileFilter(new javax.swing.filechooser.FileFilter() {
                    @Override
                    public boolean accept(File f) {
                        return f.isDirectory() || f.getName().toLowerCase().endsWith("." + ENVIRONMENT_FILE_EXTENSION);
                    }

                    @Override
                    public String getDescription() {
                        return ENVIRONMENT_FILE_DESCRIPTION;
                    }
                });
        
        File projectDirectory = topComponent.getFile() != null ? 
                FileUtil.toFile(topComponent.getFile().getParent()) : null;
        
        if (projectDirectory != null) {
            builder.setDefaultWorkingDirectory(projectDirectory);
        }
        
        File selectedFile = builder.showSaveDialog();
        
        if (selectedFile != null && !selectedFile.getName().toLowerCase().endsWith("." + ENVIRONMENT_FILE_EXTENSION)) {
            selectedFile = new File(selectedFile.getParentFile(), selectedFile.getName() + "." + ENVIRONMENT_FILE_EXTENSION);
        }
        
        return selectedFile;
    }
    
    public static File chooseEnvironmentFileForLoad(RestClientTopComponent topComponent) {
        FileChooserBuilder builder = new FileChooserBuilder(EnvironmentManager.class)
                .setTitle(NbBundle.getMessage(EnvironmentManager.class, "CTL_LoadEnvironmentDialogTitle"))
                .setFilesOnly(true)
                //.setDefaultExtension(ENVIRONMENT_FILE_EXTENSION)
                .setAcceptAllFileFilterUsed(false)
                .setFileFilter(new javax.swing.filechooser.FileFilter() {
                    @Override
                    public boolean accept(File f) {
                        return f.isDirectory() || f.getName().toLowerCase().endsWith("." + ENVIRONMENT_FILE_EXTENSION);
                    }

                    @Override
                    public String getDescription() {
                        return ENVIRONMENT_FILE_DESCRIPTION;
                    }
                });
        
        File projectDirectory = topComponent.getFile() != null ? 
                FileUtil.toFile(topComponent.getFile().getParent()) : null;
        
        if (projectDirectory != null) {
            builder.setDefaultWorkingDirectory(projectDirectory);
        }
        
        return builder.showOpenDialog();
    }
    
    public static String promptForEnvironmentName() {
        return JOptionPane.showInputDialog(
            null, 
            NbBundle.getMessage(EnvironmentManager.class, "MSG_EnvironmentNamePrompt"),
            NbBundle.getMessage(EnvironmentManager.class, "MSG_EnvironmentNameTitle"),
            JOptionPane.PLAIN_MESSAGE
        );
    }
    
    private static EnvironmentConfig parseEnvironmentConfig(JsonObject obj) {
        EnvironmentConfig config = new EnvironmentConfig();
        
        config.setEnvironmentName(obj.getString("environmentName", ""));
        config.setAuthType(obj.getString("authType", ""));
        config.setUsername(obj.getString("username", ""));
        config.setPassword(obj.getString("password", ""));
        config.setPasswordSave(obj.getBoolean("passwordSave", false));
        config.setToken(obj.getString("token", ""));
        config.setAuthUrl(obj.getString("authUrl", ""));
        config.setCallbackUrl(obj.getString("callbackUrl", ""));
        config.setCodeVerifier(obj.getString("codeVerifier", ""));
        config.setCodeChallenge(obj.getString("codeChallenge", ""));
        config.setGrantType(obj.getString("grantType", ""));
        config.setAccessTokenUrl(obj.getString("accessTokenUrl", ""));
        config.setClientId(obj.getString("clientId", ""));
        config.setClientSecret(obj.getString("clientSecret", ""));
        config.setScope(obj.getString("scope", ""));
        config.setAuthenticationMode(obj.getString("authenticationMode", ""));
        config.setUrl(obj.getString("url", ""));
        
        return config;
    }
    
    private static JsonObject buildJsonObject(EnvironmentConfig config) {
        JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("environmentName", config.getEnvironmentName())
                .add("authType", config.getAuthType())
                .add("username", config.getUsername())
                .add("password", config.getPassword())
                .add("passwordSave", config.isPasswordSave())
                .add("token", config.getToken())
                .add("authUrl", config.getAuthUrl())
                .add("callbackUrl", config.getCallbackUrl())
                .add("codeVerifier", config.getCodeVerifier())
                .add("codeChallenge", config.getCodeChallenge())
                .add("grantType", config.getGrantType())
                .add("accessTokenUrl", config.getAccessTokenUrl())
                .add("clientId", config.getClientId())
                .add("clientSecret", config.getClientSecret())
                .add("scope", config.getScope())
                .add("authenticationMode", config.getAuthenticationMode())
                .add("url", config.getUrl());
        
        return builder.build();
    }
}