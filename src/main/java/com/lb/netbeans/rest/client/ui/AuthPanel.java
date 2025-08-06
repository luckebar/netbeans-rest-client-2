/*
 * Copyright 2022 Javier Llorente <javier@opensuse.org>.
 * Copyright 2025 Luca Bartoli <lbdevweb@gmail.com>
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
package com.lb.netbeans.rest.client.ui;

import com.lb.netbeans.rest.client.RestClient;
import com.lb.netbeans.rest.client.config.EnvironmentConfig;
import com.lb.netbeans.rest.client.config.EnvironmentManager;
import jakarta.ws.rs.ProcessingException;
import java.awt.CardLayout;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Level;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JOptionPane;
import javax.swing.event.DocumentListener;
import org.openide.DialogDisplayer;
import org.openide.NotifyDescriptor;
import org.openide.filesystems.FileObject;
import org.openide.util.NbBundle;
import java.util.logging.Logger;
import javax.swing.SwingUtilities;


@NbBundle.Messages({
    "CTL_SaveEnvironment=Salva Configurazione",
    "CTL_SaveEnvironmentDialogTitle=Salva Configurazione Ambiente",
    "CTL_LoadEnvironmentDialogTitle=Carica Configurazione Ambiente",
    "CTL_AddEnvironment=Aggiungi",
    "CTL_DetachEnvironment=Scollega Ambiente",
    "LBL_Environment=Ambiente:",
    "LBL_EnvironmentFile=File Ambiente:",
    "MSG_EnvironmentNamePrompt=Inserisci il nome dell'ambiente:",
    "MSG_EnvironmentNameTitle=Nuovo Ambiente",
    "MSG_EnvironmentSaveSuccess={0} salvato con successo!",
    "MSG_EnvironmentSaveError=Errore nel salvataggio: {0}",
    "MSG_EnvironmentLoadError=Errore nel caricamento: {0}",
    "MSG_EnvironmentFileNotSelected=Nessun file ambiente selezionato.",
    "MSG_EnvironmentNameRequired=Il nome dell'ambiente è obbligatorio.",
    "MSG_EnvironmentAlreadyExists=Un ambiente con questo nome esiste già.",
    "MSG_EnvironmentDetached=Configurazione ambiente scollegata."
})
/**
 *
 * @author Javier Llorente
 * @author Luca Bartoli <lbdevweb@gmail.com>
 */
public class AuthPanel extends javax.swing.JPanel {

    private RestClient client;
    private RestClientTopComponent topComponent;
    
    private FileObject currentFile;
    private String environmentFilePath;
    private Map<String, EnvironmentConfig> environments;
    private Logger logger = Logger.getLogger(AuthPanel.class.getName());
    /**
     * Creates new form AuthPanel
     */
    public AuthPanel() {
        initComponents();
        enableDisableGetNewAccessTokenButton();
        callbackUrlTextField.setText(RestClient.DEFAULT_CALLBACK_URL);
    }
    
    public void setRestClient(RestClient client) {
        this.client = client;
    }
    
        public void setCurrentFile(FileObject currentFile) {
        this.currentFile = currentFile;
    }
    
    public void setEnvironmentFilePath(String environmentFilePath) {
        this.environmentFilePath = environmentFilePath;
        updateEnvironmentUI();
    }
    
    public String getEnvironmentFilePath() {
        return environmentFilePath;
    }
    
    public void loadEnvironments(String filePath) {
        try {
            File file = new File(filePath);
            environments = EnvironmentManager.loadEnvironments(file);
            updateEnvironmentComboBox();
            if (!environments.isEmpty()) {
                environmentComboBox.setSelectedIndex(0);
                loadSelectedEnvironment();
            }
            setEnvironmentFilePath(filePath);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Error loading environments", ex);
            NotifyDescriptor nd = new NotifyDescriptor.Message(
                NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentLoadError", ex.getMessage()),
                NotifyDescriptor.ERROR_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
        }
    }
    
    public void updateEnvironmentUI() {
        boolean hasEnvironmentFile = environmentFilePath != null && !environmentFilePath.isEmpty();
        
        environmentComboBox.setEnabled(hasEnvironmentFile);
        addEnvironmentButton.setEnabled(hasEnvironmentFile);
        //saveEnvironmentButton.setEnabled(hasEnvironmentFile);
        detachEnvironmentButton.setVisible(hasEnvironmentFile);
        
        if (hasEnvironmentFile) {
            //environmentFileLabel.setText(NbBundle.getMessage(AuthPanel.class, "LBL_EnvironmentFile") + " " + environmentFilePath);
        } else {
            //environmentFileLabel.setText(NbBundle.getMessage(AuthPanel.class, "LBL_EnvironmentFile"));
            environmentComboBox.setModel(new DefaultComboBoxModel<>());
        }
    }
    
    private void updateEnvironmentComboBox() {
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
        if (environments != null) {
            for (String name : environments.keySet()) {
                model.addElement(name);
            }
        }
        environmentComboBox.setModel(model);
    }
    
    private void saveCurrentConfiguration() {
        if (environmentFilePath == null || environmentFilePath.isEmpty()) {
            saveEnvironmentAs();
        } else {
            updateExistingEnvironment();
        }
    }
    
    private void saveEnvironmentAs() {
        File file = EnvironmentManager.chooseEnvironmentFileForSave(getTopComponent());
        if (file == null) {
            return;
        }
        String environmentName = EnvironmentManager.promptForEnvironmentName();
        if (environmentName == null || environmentName.trim().isEmpty()) {
            NotifyDescriptor nd = new NotifyDescriptor.Message(NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentNameRequired"), NotifyDescriptor.ERROR_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
            return;
        }
        try {
            EnvironmentConfig config = getCurrentConfiguration(environmentName);
            EnvironmentManager.saveEnvironment(file, environmentName, config);
            NotifyDescriptor nd = new NotifyDescriptor.Message(NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentSaveSuccess", environmentName), NotifyDescriptor.INFORMATION_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
            environmentFilePath = file.getAbsolutePath();
            loadEnvironments(environmentFilePath);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Error saving environment", ex);
            NotifyDescriptor nd = new NotifyDescriptor.Message(NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentSaveError", ex.getMessage()), NotifyDescriptor.ERROR_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
        }
    }
    
    private void updateExistingEnvironment() {
        String environmentName = (String) environmentComboBox.getSelectedItem();
        if (environmentName == null) {
            environmentName = EnvironmentManager.promptForEnvironmentName();
            if (environmentName == null || environmentName.trim().isEmpty()) {
                NotifyDescriptor nd = new NotifyDescriptor.Message(
                    NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentNameRequired"),
                    NotifyDescriptor.ERROR_MESSAGE);
                DialogDisplayer.getDefault().notify(nd);
                return;
            }
        }
        
        try {
            EnvironmentConfig config = getCurrentConfiguration(environmentName);
            EnvironmentManager.updateEnvironment(new File(environmentFilePath), environmentName, config);
            
            NotifyDescriptor nd = new NotifyDescriptor.Message(
                NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentSaveSuccess", environmentName),
                NotifyDescriptor.INFORMATION_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
            
            loadEnvironments(environmentFilePath);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Error updating environment", ex);
            NotifyDescriptor nd = new NotifyDescriptor.Message(
                NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentSaveError", ex.getMessage()),
                NotifyDescriptor.ERROR_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
        }
    }
    
    private EnvironmentConfig getCurrentConfiguration(String environmentName) {
        EnvironmentConfig config = new EnvironmentConfig();
        config.setEnvironmentName(environmentName);
        config.setAuthType(authComboBox.getSelectedItem().toString());
        config.setUsername(usernameTextField.getText());
        config.setPassword(new String(passwordField.getPassword()));
        config.setPasswordSave(salvaPassword.isSelected());
        config.setToken(tokenTextField.getText());
        config.setAuthUrl(authUrlTextField.getText());
        config.setCallbackUrl(callbackUrlTextField.getText());
        config.setCodeVerifier(codeVerifierTextField.getText());
        config.setCodeChallenge(codeChallengeTextField.getText());
        config.setGrantType(grantTypeComboBox.getSelectedItem().toString());
        config.setAccessTokenUrl(accessTokenUrlTextField.getText());
        config.setClientId(clientIdTextField.getText());
        config.setClientSecret(clientSecretTextField.getText());
        config.setScope(scopeTextField.getText());
        config.setAuthenticationMode(authenticationSendModeComboBox.getSelectedItem().toString());
        config.setBaseHost(topComponent.getBaseUrl());
        
        return config;
    }
    
    public void loadSelectedEnvironment() {
        String environmentName = (String) environmentComboBox.getSelectedItem();
        if (environmentName == null || environments == null || !environments.containsKey(environmentName)) {
            return;
        }
        
        EnvironmentConfig config = environments.get(environmentName);
        
        // Impostiamo i valori nel pannello
        if (!config.getAuthType().isEmpty() && !config.getAuthType().equals(EnvironmentManager.IMPORT_FILE_PROPERTIES)) {
            authComboBox.setSelectedItem(config.getAuthType());
            CardLayout cardLayout = (CardLayout) authTypePanel.getLayout();
            cardLayout.show(authTypePanel, config.getAuthType());
        }
        usernameTextField.setText(config.getUsername());
        passwordField.setText(config.getPassword());
        salvaPassword.setSelected(config.isPasswordSave());
        tokenTextField.setText(config.getToken());
        authUrlTextField.setText(config.getAuthUrl());
        callbackUrlTextField.setText(config.getCallbackUrl());
        codeVerifierTextField.setText(config.getCodeVerifier());
        codeChallengeTextField.setText(config.getCodeChallenge());
        grantTypeComboBox.setSelectedItem(config.getGrantType());
        accessTokenUrlTextField.setText(config.getAccessTokenUrl());
        clientIdTextField.setText(config.getClientId());
        clientSecretTextField.setText(config.getClientSecret());
        scopeTextField.setText(config.getScope());
        authenticationSendModeComboBox.setSelectedItem(config.getAuthenticationMode());
        topComponent.updateBaseUrl(config.getBaseHost());
        // Imposta il focus sull'URL per evidenziare il cambiamento
        SwingUtilities.invokeLater(() -> {
            topComponent.getUrlPanel().requestUrlFocus();
        });
    }
    
    private void detachEnvironment() {
        environmentFilePath = null;
        environments = null;
        updateEnvironmentUI();
        
        NotifyDescriptor nd = new NotifyDescriptor.Message(
                NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentDetached"),
            NotifyDescriptor.INFORMATION_MESSAGE);
        DialogDisplayer.getDefault().notify(nd);
    }
    
    public void setTopComponent(RestClientTopComponent topComponent) {
        this.topComponent = topComponent;
    }

    private RestClientTopComponent getTopComponent() {
        return topComponent;
    }
    
    public String getAuthType() {
        return authComboBox.getSelectedItem().toString();
    }
    
    public void setAuthType(String type) {
        authComboBox.setSelectedItem(type);
    }
    
    public String getUsername() {
        return usernameTextField.getText();
    }
    
    public void setUsername(String username) {
        usernameTextField.setText(username);
    }
    
    public String getPassword() {
        return String.valueOf(passwordField.getPassword());
    }
    
    public void setPassword(String password) {
        passwordField.setText(password);
    }
    
    public boolean isSavable() {
        return salvaPassword.isSelected();
    }
    
    public void setSavable(boolean savable) {
        salvaPassword.setSelected(savable);
    }
    
    public void setToken(String token) {
        tokenTextField.setText(token);
    }
    
    public String getAuthUrl() {
        return authUrlTextField.getText();
    }

    public void setAuthUrl(String authUrl) {
        authUrlTextField.setText(authUrl);
    }

    public String getCallbackUrl() {
        return callbackUrlTextField.getText();
    }

    public void setCallbackUrl(String callbackUrl) {
        callbackUrlTextField.setText(callbackUrl);
    }

    public String getCodeVerifier() {
        return codeVerifierTextField.getText();
    }

    public void setCodeVerifier(String codeVerifier) {
        codeVerifierTextField.setText(codeVerifier);
    }

    public String getCodeChallenge() {
        return codeChallengeTextField.getText();
    }

    public void setCodeChallenge(String codeChallenge) {
        codeChallengeTextField.setText(codeChallenge);
    }
    
    // Aggiungere questi metodi
    public void addUsernameDocumentListener(DocumentListener dl) {
        usernameTextField.getDocument().addDocumentListener(dl);
    }

    public void addPasswordDocumentListener(DocumentListener dl) {
        passwordField.getDocument().addDocumentListener(dl);
    }
    
    public void addTokenDocumentListener(DocumentListener dl) {
        tokenTextField.getDocument().addDocumentListener(dl);
    }
    
    public void removeTokenDocumentListener(DocumentListener dl) {
        tokenTextField.getDocument().removeDocumentListener(dl);
    }
    
    public void addComboBoxListener(ActionListener l) {
        authComboBox.addActionListener(l);
    }
    
    // Metodi per grantTypeComboBox
    public String getGrantType() {
        return grantTypeComboBox.getSelectedItem().toString();
    }

    public void setGrantType(String type) {
        grantTypeComboBox.setSelectedItem(type);
    }

    // Metodi per accessTokenUrlTextField
    public String getAccessTokenUrl() {
        return accessTokenUrlTextField.getText();
    }

    public void setAccessTokenUrl(String url) {
        accessTokenUrlTextField.setText(url);
    }

    // Metodi per clientIdTextField
    public String getClientId() {
        return clientIdTextField.getText();
    }

    public void setClientId(String id) {
        clientIdTextField.setText(id);
    }

    // Metodi per clientSecretTextField
    public String getClientSecret() {
        return new String(clientSecretTextField.getText());
    }

    public void setClientSecret(String secret) {
        clientSecretTextField.setText(secret);
    }

    // Metodi per scopeTextField
    public String getScope() {
        return scopeTextField.getText();
    }

    public void setScope(String scope) {
        scopeTextField.setText(scope);
    }

    // Metodo per aggiungere listener al pulsante
    public void addGetNewAccessTokenButtonListener(ActionListener l) {
        getNewAccessTokenButton.addActionListener(l);
    }

    // Metodo per impostare la modalità di autenticazione
    public void setAuthenticationMode(String item) {
        authenticationSendModeComboBox.setSelectedItem(item);
    }
    
    public String getAuthenticationMode() {
        return authenticationSendModeComboBox.getSelectedItem().toString();
    }
    
    public void enableDisableGetNewAccessTokenButton() {
        if(grantTypeComboBox.getSelectedIndex()==0) {
            getNewAccessTokenButton.setEnabled(false);
        } else {
            getNewAccessTokenButton.setEnabled(true);
        }
    }
    
    public void showEnvironment(boolean visible) {
        environmentComboBox.setVisible(visible);
        addEnvironmentButton.setVisible(visible);
        detachEnvironmentButton.setVisible(visible);
    }
    
    public void setSelectedItemEnvironment(String environmentName) {
        environmentComboBox.setSelectedItem(environmentName);
    }
    
    public String getSelectedItemEnvironment() {
        Object selected = environmentComboBox.getSelectedItem();
        return (selected != null) ? selected.toString() : "";
    }

    // Aggiungi questi metodi di supporto
    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    private String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, bytes.length);
            byte[] digest = md.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    
    

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        authComboBox = new javax.swing.JComboBox<>();
        authTypePanel = new javax.swing.JPanel();
        noAuthPanel = new javax.swing.JPanel();
        bearerTokenPanel = new javax.swing.JPanel();
        tokenLabel = new javax.swing.JLabel();
        tokenTextField = new javax.swing.JTextField();
        grantTypeLabel = new javax.swing.JLabel();
        grantTypeComboBox = new javax.swing.JComboBox<>();
        accessTokenUrlLabel = new javax.swing.JLabel();
        accessTokenUrlTextField = new javax.swing.JTextField();
        clientIdLabel = new javax.swing.JLabel();
        clientIdTextField = new javax.swing.JTextField();
        clientSecretLabel = new javax.swing.JLabel();
        clientSecretTextField = new javax.swing.JTextField();
        scopeLabel = new javax.swing.JLabel();
        scopeTextField = new javax.swing.JTextField();
        authenticationLabel = new javax.swing.JLabel();
        getNewAccessTokenButton = new javax.swing.JButton();
        authenticationSendModeComboBox = new javax.swing.JComboBox<>();
        callbackUrlLabel = new javax.swing.JLabel();
        callbackUrlTextField = new javax.swing.JTextField();
        authUrlLabel = new javax.swing.JLabel();
        authUrlTextField = new javax.swing.JTextField();
        codeChallengeLabel = new javax.swing.JLabel();
        codeChallengeTextField = new javax.swing.JTextField();
        codeVerifierLabel = new javax.swing.JLabel();
        codeVerifierTextField = new javax.swing.JTextField();
        basicAuthPanel = new javax.swing.JPanel();
        usernameLabel = new javax.swing.JLabel();
        passwordLabel = new javax.swing.JLabel();
        usernameTextField = new javax.swing.JTextField();
        passwordField = new javax.swing.JPasswordField();
        salvaPasswordLabel = new javax.swing.JLabel();
        salvaPassword = new javax.swing.JCheckBox();
        saveEnvironmentButton = new javax.swing.JButton();
        environmentComboBox = new javax.swing.JComboBox<>();
        addEnvironmentButton = new javax.swing.JButton();
        detachEnvironmentButton = new javax.swing.JButton();

        setPreferredSize(new java.awt.Dimension(800, 144));

        authComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "No Auth", "Bearer Token", "Basic Auth", "Import File Properties" }));
        authComboBox.setMaximumSize(new java.awt.Dimension(72, 32767));
        authComboBox.setMinimumSize(new java.awt.Dimension(72, 22));
        authComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                authComboBoxActionPerformed(evt);
            }
        });

        authTypePanel.setLayout(new java.awt.CardLayout());

        javax.swing.GroupLayout noAuthPanelLayout = new javax.swing.GroupLayout(noAuthPanel);
        noAuthPanel.setLayout(noAuthPanelLayout);
        noAuthPanelLayout.setHorizontalGroup(
            noAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 582, Short.MAX_VALUE)
        );
        noAuthPanelLayout.setVerticalGroup(
            noAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 554, Short.MAX_VALUE)
        );

        authTypePanel.add(noAuthPanel, "No Auth");

        org.openide.awt.Mnemonics.setLocalizedText(tokenLabel, "Token:");

        org.openide.awt.Mnemonics.setLocalizedText(grantTypeLabel, "Grant Type:");

        grantTypeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Manual", "Client Credentials", "PKCE" }));
        grantTypeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                grantTypeComboBoxActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(accessTokenUrlLabel, "Access Token URL:");

        org.openide.awt.Mnemonics.setLocalizedText(clientIdLabel, "Client ID:");

        org.openide.awt.Mnemonics.setLocalizedText(clientSecretLabel, "Client Secret:");

        org.openide.awt.Mnemonics.setLocalizedText(scopeLabel, "Scope");

        org.openide.awt.Mnemonics.setLocalizedText(authenticationLabel, "Authentication:");
        authenticationLabel.setToolTipText("");

        org.openide.awt.Mnemonics.setLocalizedText(getNewAccessTokenButton, "Get New Access Token");
        getNewAccessTokenButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                getNewAccessTokenButtonActionPerformed(evt);
            }
        });

        authenticationSendModeComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Send as Basic Auth header", "Send client credentials in body" }));

        org.openide.awt.Mnemonics.setLocalizedText(callbackUrlLabel, "Callback URL:");

        callbackUrlTextField.setToolTipText("");

        org.openide.awt.Mnemonics.setLocalizedText(authUrlLabel, "Auth URL:");

        org.openide.awt.Mnemonics.setLocalizedText(codeChallengeLabel, "Code Challenge:");

        org.openide.awt.Mnemonics.setLocalizedText(codeVerifierLabel, "Code Verifier:");

        javax.swing.GroupLayout bearerTokenPanelLayout = new javax.swing.GroupLayout(bearerTokenPanel);
        bearerTokenPanel.setLayout(bearerTokenPanelLayout);
        bearerTokenPanelLayout.setHorizontalGroup(
            bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(bearerTokenPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(getNewAccessTokenButton)
                            .addGroup(bearerTokenPanelLayout.createSequentialGroup()
                                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(authenticationLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(scopeLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(clientSecretLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(clientIdLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(accessTokenUrlLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 152, Short.MAX_VALUE)
                                    .addComponent(tokenLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(grantTypeLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGap(18, 18, 18)
                                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(grantTypeComboBox, 0, 400, Short.MAX_VALUE)
                                    .addComponent(accessTokenUrlTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
                                    .addComponent(clientIdTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
                                    .addComponent(clientSecretTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
                                    .addComponent(scopeTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
                                    .addComponent(tokenTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
                                    .addComponent(authenticationSendModeComboBox, 0, 400, Short.MAX_VALUE))))
                        .addGroup(bearerTokenPanelLayout.createSequentialGroup()
                            .addComponent(callbackUrlLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGap(18, 18, 18)
                            .addComponent(callbackUrlTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)))
                    .addGroup(bearerTokenPanelLayout.createSequentialGroup()
                        .addComponent(authUrlLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(authUrlTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 400, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(bearerTokenPanelLayout.createSequentialGroup()
                        .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(codeChallengeLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(codeVerifierLabel))
                        .addGap(18, 18, 18)
                        .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(codeVerifierTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 400, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(codeChallengeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 400, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        bearerTokenPanelLayout.setVerticalGroup(
            bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(bearerTokenPanelLayout.createSequentialGroup()
                .addGap(29, 29, 29)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tokenLabel)
                    .addComponent(tokenTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(grantTypeLabel)
                    .addComponent(grantTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(callbackUrlLabel)
                    .addComponent(callbackUrlTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(authUrlLabel)
                    .addComponent(authUrlTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(accessTokenUrlLabel)
                    .addComponent(accessTokenUrlTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(clientIdLabel)
                    .addComponent(clientIdTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(clientSecretLabel)
                    .addComponent(clientSecretTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(codeChallengeLabel)
                    .addComponent(codeChallengeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(codeVerifierLabel)
                    .addComponent(codeVerifierTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(scopeLabel)
                    .addComponent(scopeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(bearerTokenPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(authenticationLabel)
                    .addComponent(authenticationSendModeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(getNewAccessTokenButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        authTypePanel.add(bearerTokenPanel, "Bearer Token");

        org.openide.awt.Mnemonics.setLocalizedText(usernameLabel, "Username:");

        org.openide.awt.Mnemonics.setLocalizedText(passwordLabel, "Password:");

        org.openide.awt.Mnemonics.setLocalizedText(salvaPasswordLabel, "Salva Password:");

        javax.swing.GroupLayout basicAuthPanelLayout = new javax.swing.GroupLayout(basicAuthPanel);
        basicAuthPanel.setLayout(basicAuthPanelLayout);
        basicAuthPanelLayout.setHorizontalGroup(
            basicAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(basicAuthPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(basicAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(basicAuthPanelLayout.createSequentialGroup()
                        .addGroup(basicAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(usernameLabel)
                            .addComponent(passwordLabel))
                        .addGap(18, 18, 18)
                        .addGroup(basicAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(usernameTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 315, Short.MAX_VALUE)
                            .addComponent(passwordField)))
                    .addGroup(basicAuthPanelLayout.createSequentialGroup()
                        .addComponent(salvaPasswordLabel)
                        .addGap(18, 18, 18)
                        .addComponent(salvaPassword)))
                .addContainerGap(187, Short.MAX_VALUE))
        );
        basicAuthPanelLayout.setVerticalGroup(
            basicAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(basicAuthPanelLayout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addGroup(basicAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(usernameLabel)
                    .addComponent(usernameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(basicAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(passwordLabel)
                    .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(basicAuthPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(salvaPasswordLabel)
                    .addComponent(salvaPassword))
                .addContainerGap(443, Short.MAX_VALUE))
        );

        authTypePanel.add(basicAuthPanel, "Basic Auth");

        org.openide.awt.Mnemonics.setLocalizedText(saveEnvironmentButton, "Save Config");
        saveEnvironmentButton.setToolTipText("");
        saveEnvironmentButton.setMaximumSize(new java.awt.Dimension(72, 23));
        saveEnvironmentButton.setMinimumSize(new java.awt.Dimension(72, 23));
        saveEnvironmentButton.setPreferredSize(new java.awt.Dimension(72, 23));
        saveEnvironmentButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveEnvironmentButtonActionPerformed(evt);
            }
        });

        environmentComboBox.setMaximumSize(new java.awt.Dimension(72, 32767));
        environmentComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                environmentComboBoxActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(addEnvironmentButton, "Add Env");
        addEnvironmentButton.setMaximumSize(new java.awt.Dimension(72, 23));
        addEnvironmentButton.setMinimumSize(new java.awt.Dimension(72, 23));
        addEnvironmentButton.setPreferredSize(new java.awt.Dimension(72, 23));
        addEnvironmentButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addEnvironmentButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(detachEnvironmentButton, "Disconnect Config");
        detachEnvironmentButton.setMaximumSize(new java.awt.Dimension(72, 23));
        detachEnvironmentButton.setMinimumSize(new java.awt.Dimension(72, 23));
        detachEnvironmentButton.setPreferredSize(new java.awt.Dimension(72, 23));
        detachEnvironmentButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                detachEnvironmentButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(addEnvironmentButton, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(saveEnvironmentButton, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(authComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(detachEnvironmentButton, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(environmentComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(authTypePanel, javax.swing.GroupLayout.DEFAULT_SIZE, 618, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(authComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(environmentComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(addEnvironmentButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 205, Short.MAX_VALUE)
                        .addComponent(saveEnvironmentButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(detachEnvironmentButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(authTypePanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void authComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_authComboBoxActionPerformed
        CardLayout cardLayout = (CardLayout) authTypePanel.getLayout();
        
        String authComboBoxSelected = authComboBox.getSelectedItem().toString();
        
        if (authComboBoxSelected.equals(EnvironmentManager.IMPORT_FILE_PROPERTIES)) {
            if (environmentFilePath == null || environmentFilePath.isEmpty()) {
                // Carica un nuovo file
                File file = EnvironmentManager.chooseEnvironmentFileForLoad(getTopComponent());
                if (file != null) {
                    loadEnvironments(file.getAbsolutePath());
                } else {
                    authComboBox.setSelectedItem("No Auth");
                }
            } else {
                // File già caricato, mostra semplicemente gli ambienti
                updateEnvironmentComboBox();
                if (!environments.isEmpty()) {
                    environmentComboBox.setSelectedIndex(0);
                    loadSelectedEnvironment();
                }
            }
        } else {
            cardLayout.show(authTypePanel, authComboBoxSelected);
        }
    }//GEN-LAST:event_authComboBoxActionPerformed

    private void getNewAccessTokenButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_getNewAccessTokenButtonActionPerformed
        // TODO add your handling code here:
        if(grantTypeComboBox.getSelectedItem().equals("Client Credentials")) {
            String tokenUrl = accessTokenUrlTextField.getText();
            String clientId = clientIdTextField.getText();
            String clientSecret = clientSecretTextField.getText();
            String scope = scopeTextField.getText();

            if(tokenUrl.isEmpty() || clientId.isEmpty() || clientSecret.isEmpty()) {
                JOptionPane.showMessageDialog(this, 
                    "Compila tutti i campi obbligatori", 
                    "Errore", JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                String token = null;
                if(authenticationSendModeComboBox.getSelectedIndex() == 0)
                    token = client.getClientCredentialsTokenHeader(tokenUrl, clientId, clientSecret, scope);
                else if(authenticationSendModeComboBox.getSelectedIndex() == 1)
                    token = client.getClientCredentialsTokenOnlyBody(tokenUrl, clientId, clientSecret, scope);
                
                if(token != null)
                    tokenTextField.setText(token);
                else
                    throw new ProcessingException("Mode Authentication not supported");
            } catch (ProcessingException ex) {
                JOptionPane.showMessageDialog(this, 
                    "Errore durante il recupero del token: " + ex.getMessage(),
                    "Errore", JOptionPane.ERROR_MESSAGE);
            }
        } else if(grantTypeComboBox.getSelectedItem().equals("PKCE")) {
            String authUrl = authUrlTextField.getText();
            String callbackUrl = callbackUrlTextField.getText();
            String clientId = clientIdTextField.getText();
            String scope = scopeTextField.getText();
            String accessTokenUrl = accessTokenUrlTextField.getText();
            
            // Genera automaticamente codeVerifier e codeChallenge se vuoti
            String codeVerifier = codeVerifierTextField.getText();
            if (codeVerifier.isEmpty()) {
                codeVerifier = generateCodeVerifier();
                codeVerifierTextField.setText(codeVerifier);
            }

            String codeChallenge = codeChallengeTextField.getText();
            if (codeChallenge.isEmpty()) {
                codeChallenge = generateCodeChallenge(codeVerifier);
                codeChallengeTextField.setText(codeChallenge);
            }
            
            if(authUrl.isEmpty() || callbackUrl.isEmpty() || clientId.isEmpty() || 
               codeVerifier.isEmpty() || codeChallenge.isEmpty()) {
                JOptionPane.showMessageDialog(this, 
                    "Compila tutti i campi obbligatori", 
                    "Errore", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            client.handlePKCEFlow(this, authUrl, callbackUrl, clientId, codeVerifier, codeChallenge, scope, accessTokenUrl);
        }
    }//GEN-LAST:event_getNewAccessTokenButtonActionPerformed

    private void grantTypeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_grantTypeComboBoxActionPerformed
        // TODO add your handling code here:
        enableDisableGetNewAccessTokenButton();
        boolean isPKCE = grantTypeComboBox.getSelectedItem().equals("PKCE");
        authUrlLabel.setVisible(isPKCE);
        authUrlTextField.setVisible(isPKCE);
        callbackUrlLabel.setVisible(isPKCE);
        callbackUrlTextField.setVisible(isPKCE);
        codeVerifierLabel.setVisible(isPKCE);
        codeVerifierTextField.setVisible(isPKCE);
        codeChallengeLabel.setVisible(isPKCE);
        codeChallengeTextField.setVisible(isPKCE);
        //generateCodeVerifierButton.setVisible(isPKCE); // TODO lo chiamo in automatico quando voglio riprendermi il token
        clientSecretLabel.setVisible(!isPKCE);
        clientSecretTextField.setVisible(!isPKCE);
    }//GEN-LAST:event_grantTypeComboBoxActionPerformed

    private void addEnvironmentButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addEnvironmentButtonActionPerformed

        String environmentName = EnvironmentManager.promptForEnvironmentName();
        if (environmentName == null || environmentName.trim().isEmpty()) {
            NotifyDescriptor nd = new NotifyDescriptor.Message(
                NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentNameRequired"),
                NotifyDescriptor.ERROR_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
            return;
        }
        
        if (environments.containsKey(environmentName)) {
            NotifyDescriptor nd = new NotifyDescriptor.Message(
                NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentAlreadyExists"),
                NotifyDescriptor.ERROR_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
            return;
        }
        
        try {
            EnvironmentConfig config = getCurrentConfiguration(environmentName);
            EnvironmentManager.updateEnvironment(new File(environmentFilePath), environmentName, config);
            
            NotifyDescriptor nd = new NotifyDescriptor.Message(
                NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentSaveSuccess", environmentName),
                NotifyDescriptor.INFORMATION_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
            
            loadEnvironments(environmentFilePath);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Error adding new environment", ex);
            NotifyDescriptor nd = new NotifyDescriptor.Message(
                NbBundle.getMessage(AuthPanel.class, "MSG_EnvironmentSaveError", ex.getMessage()),
                NotifyDescriptor.ERROR_MESSAGE);
            DialogDisplayer.getDefault().notify(nd);
        }
    }//GEN-LAST:event_addEnvironmentButtonActionPerformed

    private void saveEnvironmentButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveEnvironmentButtonActionPerformed
        saveCurrentConfiguration();
    }//GEN-LAST:event_saveEnvironmentButtonActionPerformed

    private void detachEnvironmentButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_detachEnvironmentButtonActionPerformed
        detachEnvironment();
    }//GEN-LAST:event_detachEnvironmentButtonActionPerformed

    private void environmentComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_environmentComboBoxActionPerformed
        loadSelectedEnvironment();
    }//GEN-LAST:event_environmentComboBoxActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel accessTokenUrlLabel;
    private javax.swing.JTextField accessTokenUrlTextField;
    private javax.swing.JButton addEnvironmentButton;
    private javax.swing.JComboBox<String> authComboBox;
    private javax.swing.JPanel authTypePanel;
    private javax.swing.JLabel authUrlLabel;
    private javax.swing.JTextField authUrlTextField;
    private javax.swing.JLabel authenticationLabel;
    private javax.swing.JComboBox<String> authenticationSendModeComboBox;
    private javax.swing.JPanel basicAuthPanel;
    private javax.swing.JPanel bearerTokenPanel;
    private javax.swing.JLabel callbackUrlLabel;
    private javax.swing.JTextField callbackUrlTextField;
    private javax.swing.JLabel clientIdLabel;
    private javax.swing.JTextField clientIdTextField;
    private javax.swing.JLabel clientSecretLabel;
    private javax.swing.JTextField clientSecretTextField;
    private javax.swing.JLabel codeChallengeLabel;
    private javax.swing.JTextField codeChallengeTextField;
    private javax.swing.JLabel codeVerifierLabel;
    private javax.swing.JTextField codeVerifierTextField;
    private javax.swing.JButton detachEnvironmentButton;
    private javax.swing.JComboBox<String> environmentComboBox;
    private javax.swing.JButton getNewAccessTokenButton;
    private javax.swing.JComboBox<String> grantTypeComboBox;
    private javax.swing.JLabel grantTypeLabel;
    private javax.swing.JPanel noAuthPanel;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JLabel passwordLabel;
    private javax.swing.JCheckBox salvaPassword;
    private javax.swing.JLabel salvaPasswordLabel;
    private javax.swing.JButton saveEnvironmentButton;
    private javax.swing.JLabel scopeLabel;
    private javax.swing.JTextField scopeTextField;
    private javax.swing.JLabel tokenLabel;
    private javax.swing.JTextField tokenTextField;
    private javax.swing.JLabel usernameLabel;
    private javax.swing.JTextField usernameTextField;
    // End of variables declaration//GEN-END:variables
}
