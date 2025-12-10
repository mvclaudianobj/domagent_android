package dnsfilter.android;

import android.Manifest;
import android.content.Context;
import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.text.Html;
import android.text.Spanned;
import android.text.method.LinkMovementMethod;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import android.content.pm.PackageManager;

import dnsfilter.ConfigurationAccess;
import dnsfilter.DNSFilterManager;
import dnsfilter.ConfigUtil;
import util.Logger;
import util.LoggerInterface;
import util.GroupedLogger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class DNSProxyActivity extends Activity {

    private static final String TAG = "DNSProxyActivity";
    private DNSFilterManager dnsManager;
    private ImageButton menuButton;
    private TextView statusIndicator;
    private EditText activationCodeInput;
    private Button activateButton;
    private TextView statusText;
    private TextView blockLogText;

    private static final int ADVANCED_SETTINGS_REQUEST = 1001;
    private static final int VPN_REQUEST_CODE = 100;
    private static final int NOTIFICATION_PERMISSION_REQUEST = 101;

    private boolean waitingForVpnPermission = false;
    private Handler statusUpdateHandler;
    private Runnable statusUpdateRunnable;
    private boolean servicesStarted = false;
    private boolean activationInProgress = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            Log.d(TAG, "onCreate iniciado");

            setContentView(R.layout.main);

            // ✅ VERIFICAR PERMISSÃO DE NOTIFICAÇÃO (Android 13+)
            checkNotificationPermission();

            // Apenas inicializar o ambiente Android
            AndroidEnvironment.initEnvironment(this);

            // Inicializar DNSFilterManager
            try {
                dnsManager = DNSFilterManager.getInstance();
                Log.d(TAG, "DNSFilterManager inicializado");
            } catch (Exception e) {
                Log.e(TAG, "Erro ao inicializar DNSFilterManager", e);
                dnsManager = null;
            }

            initializeViews();
            setupEventListeners();

            // ✅ Inicializar AdvancedFunctions
            initializeBackgroundServices();

            // ✅ Configurar logger para exibir logs de DNS na UI
            setupUILogger();

            // ✅ Ativar todos os recursos (filtros, logs, DoH) na primeira inicialização
            AdvancedFunctions.activateAllFeatures(this);

            // ✅ Verificar status e AUTO-INICIAR se necessário
            checkInitialStatus();

            // ✅ Configurar atualização periódica de status
            setupStatusUpdater();

            Log.d(TAG, "onCreate concluído com sucesso");

        } catch (Exception e) {
            Log.e(TAG, "ERRO FATAL no onCreate", e);
            e.printStackTrace();
            Toast.makeText(this, "Erro ao iniciar: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    /**
     * ✅ VERIFICAR PERMISSÃO DE NOTIFICAÇÃO (Android 13+)
     */
    private void checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33) {
            if (this.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                Log.d(TAG, "📢 Solicitando permissão de notificação...");
                this.requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, NOTIFICATION_PERMISSION_REQUEST);
            } else {
                Log.d(TAG, "✅ Permissão de notificação já concedida");
            }
        }
    }

    /**
     * ✅ TRATAR RESULTADO DA PERMISSÃO
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        if (grantResults.length == 0) return;

        if (requestCode == NOTIFICATION_PERMISSION_REQUEST) {
            if (permissions[0].equals(Manifest.permission.POST_NOTIFICATIONS) && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.d(TAG, "✅ Permissão de notificação concedida!");
                addBlockLog("📢 Permissão de notificação concedida");

                // ✅ SE O AGENTE JÁ ESTIVER ATIVADO, MOSTRAR POPUP DE BOAS-VINDAS
                if (dnsManager != null && dnsManager.isAgentActivated()) {
                    new Handler().postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            showWelcomePopup();
                        }
                    }, 1000);
                }

            } else {
                Log.w(TAG, "⚠️ Permissão de notificação negada");
                addBlockLog("⚠️ Permissão de notificação negada - algumas funcionalidades podem não funcionar");
                Toast.makeText(this,
                        "Permissão de notificação é recomendada para alertas do sistema",
                        Toast.LENGTH_LONG).show();
            }
        }
    }

    /**
     * ✅ MOSTRAR POPUP DE BOAS-VINDAS
     */
    private void showWelcomePopup() {
        try {
            ConfigUtil config = ConfigurationAccess.getLocal().getConfigUtil();
            boolean showInitialInfoPopUp = Boolean.parseBoolean(config.getConfigValue("showInitialInfoPopUp", "true"));

            if (showInitialInfoPopUp) {
                Dialog popUpDialog = new Dialog(this, R.style.Theme_dialog_TitleBar);
                popUpDialog.setContentView(R.layout.popup);
                popUpDialog.setTitle(config.getConfigValue("initialInfoPopUpTitle", "Bem-vindo ao DomCustosAgent!"));

                TextView infoText = popUpDialog.findViewById(R.id.infoPopUpTxt);
                String welcomeText = config.getConfigValue("initialInfoPopUpText",
                        "<h3>🎉 Parabéns! Seu agente está ativo!</h3>" +
                                "<p>Seu dispositivo agora está protegido com filtragem DNS e DNS over HTTPS.</p>" +
                                "<p><b>Funcionalidades ativas:</b></p>" +
                                "<ul>" +
                                "<li>🔒 Proteção contra domínios maliciosos</li>" +
                                "<li>🚀 DNS over HTTPS habilitado</li>" +
                                "<li>🛡️ Filtragem em tempo real</li>" +
                                "</ul>" +
                                "<p>Acesse as configurações avançadas para personalizar sua experiência.</p>");

                infoText.setText(fromHtml(welcomeText));
                infoText.setMovementMethod(LinkMovementMethod.getInstance());

                Button closeButton = popUpDialog.findViewById(R.id.closeInfoPopupBtn);
                CheckBox disableCheckbox = popUpDialog.findViewById(R.id.disableInfoPopUp);

                closeButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        if (disableCheckbox.isChecked()) {
                            // Salvar preferência para não mostrar novamente
                            try {
                                config.updateConfigValue("showInitialInfoPopUp", "false");
                                ConfigurationAccess.getLocal().updateConfig(config.getConfigBytes());
                                addBlockLog("✅ Configuração salva: Popup não será mostrado novamente");
                            } catch (Exception e) {
                                Log.e(TAG, "Erro ao salvar preferência do popup: " + e.toString());
                            }
                        }
                        popUpDialog.dismiss();
                        addBlockLog("📋 Informações de boas-vindas visualizadas");
                    }
                });

                popUpDialog.show();
                Window window = popUpDialog.getWindow();
                int displayWidth = ((WindowManager) getSystemService(WINDOW_SERVICE)).getDefaultDisplay().getWidth();
                int displayHeight = ((WindowManager) getSystemService(WINDOW_SERVICE)).getDefaultDisplay().getHeight();
                window.setLayout((int) (Math.min(displayWidth, displayHeight)*0.9), WindowManager.LayoutParams.WRAP_CONTENT);
                window.setBackgroundDrawableResource(android.R.color.transparent);

                addBlockLog("🎉 Mostrando informações de boas-vindas...");
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro ao mostrar popup de boas-vindas: " + e.toString());
            addBlockLog("❌ Erro ao mostrar informações: " + e.getMessage());
        }
    }

    /**
     * ✅ MÉTODO AUXILIAR for fromHtml
     */
    private Spanned fromHtml(String txt) {
        if (Build.VERSION.SDK_INT >= 24)
            return Html.fromHtml(txt, 0);
        else
            return Html.fromHtml(txt);
    }

    private void initializeBackgroundServices() {
        try {
            if (!AdvancedFunctions.isInitialized()) {
                addBlockLog("🔧 Inicializando serviços de background...");
                AdvancedFunctions.initializeBackgroundFunctions(this);
                addBlockLog("✅ Serviços inicializados com sucesso");
            } else {
                addBlockLog("✅ Serviços já inicializados");
            }

            // ✅ IMPORTANTE: Só verificar status, NÃO iniciar automaticamente
            if (AdvancedFunctions.isServiceRunning()) {
                addBlockLog("📡 Serviço DNS já está ativo");
                addBlockLog(AdvancedFunctions.getServiceStatus());
            } else {
                addBlockLog("ℹ️ Serviço DNS aguardando inicialização");
            }

        } catch (Exception e) {
            Log.e(TAG, "Erro na inicialização de background", e);
            addBlockLog("❌ Erro na inicialização: " + e.toString());
        }
    }

    private void initializeViews() {
        try {
            Log.d(TAG, "initializeViews iniciado");

            menuButton = findViewById(R.id.menuButton);
            statusIndicator = findViewById(R.id.statusIndicator);
            activationCodeInput = findViewById(R.id.activationCodeInput);
            activateButton = findViewById(R.id.activateButton);
            statusText = findViewById(R.id.statusText);
            blockLogText = findViewById(R.id.blockLogText);

            Log.d(TAG, "initializeViews concluído");

        } catch (Exception e) {
            Log.e(TAG, "ERRO em initializeViews", e);
            throw new RuntimeException("Falha ao inicializar views: " + e.getMessage(), e);
        }
    }

    /**
     * ✅ VERIFICAR STATUS INICIAL
     */
    private void checkInitialStatus() {
        try {
            Log.d(TAG, "checkInitialStatus iniciado");

            // Verificar status do agent
            if (dnsManager != null) {
                boolean isActivated = dnsManager.isAgentActivated();

                if (isActivated) {
                    updateUIForActivatedState();

                    String agentId = dnsManager.getAgentId();
                    addBlockLog("✅ Agente já está ativado");
                    addBlockLog("🔑 Agent ID: " + agentId);

                    // Verificar se DoH está habilitado
                    if (dnsManager.isDohEnabled()) {
                        addBlockLog("🔒 DoH (DNS over HTTPS) habilitado");
                    } else {
                        addBlockLog("🔧 DNS padrão configurado");
                    }

                    // ✅ VERIFICAR SE SERVIÇO JÁ ESTÁ RODANDO
                    if (AdvancedFunctions.isServiceRunning()) {
                        addBlockLog("📡 Serviço DNS já está ativo");
                        servicesStarted = true;
                        updateServiceStatus();
                    } else if (!servicesStarted && !activationInProgress) {
                        // ✅ AUTO-INICIAR SERVIÇO APENAS SE NÃO FOI INICIADO AINDA
                        // E NÃO ESTÁ NO MEIO DE UMA ATIVAÇÃO
                        addBlockLog("🚀 Iniciando serviço DNS automaticamente...");
                        servicesStarted = true;

                        // Aguardar um pouco para UI carregar
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                startDNSServiceWithVPN();
                            }
                        }, 2000);
                    }

                } else {
                    // Agente não ativado
                    updateUIForDeactivatedState();
                    addBlockLog("ℹ️ Agente não ativado");
                    addBlockLog("🔑 Digite seu código de ativação para começar");
                }
            } else {
                updateUIForDeactivatedState();
                addBlockLog("⚠️ DNSFilterManager não disponível");
            }

            Log.d(TAG, "checkInitialStatus concluído");

        } catch (Exception e) {
            Log.e(TAG, "ERRO em checkInitialStatus", e);
            addBlockLog("❌ Erro ao verificar status: " + e.toString());
        }
    }

    /**
     * ✅ CONFIGURAR ATUALIZAÇÃO PERIÓDICA DE STATUS
     */
    private void setupStatusUpdater() {
        statusUpdateHandler = new Handler();
        statusUpdateRunnable = new Runnable() {
            @Override
            public void run() {
                try {
                    // Atualizar status apenas se serviço estiver rodando
                    if (AdvancedFunctions.isServiceRunning()) {
                        updateServiceStatus();
                    }

                    // Reagendar para 5 segundos depois
                    statusUpdateHandler.postDelayed(this, 5000);

                } catch (Exception e) {
                    Log.e(TAG, "Erro ao atualizar status periódico", e);
                }
            }
        };

        // Iniciar atualização periódica
        statusUpdateHandler.postDelayed(statusUpdateRunnable, 5000);
    }

    private void setupEventListeners() {
        try {
            Log.d(TAG, "setupEventListeners iniciado");

            // ✅ Menu Advanced com validação de ativação
            if (menuButton != null) {
                menuButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        openAdvancedSettings();
                    }
                });
            }

            // Botão de Ativação
            if (activateButton != null) {
                activateButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        activateAgent();
                    }
                });
            }

            Log.d(TAG, "setupEventListeners concluído");

        } catch (Exception e) {
            Log.e(TAG, "ERRO em setupEventListeners", e);
        }
    }

    private void updateServiceStatus() {
        try {
            if (AdvancedFunctions.isInitialized() && AdvancedFunctions.isServiceRunning()) {
                String status = AdvancedFunctions.getServiceStatus();
                String filterStats = AdvancedFunctions.getFilterStats();

                // Atualizar indicador visual
                if (statusIndicator != null) {
                    statusIndicator.setText("● ATIVO");
                    statusIndicator.setTextColor(getResources().getColor(android.R.color.holo_green_dark));
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro ao atualizar status do serviço", e);
        }
    }

    private void activateAgent() {
        try {
            // ✅ PREVENIR ATIVAÇÃO DUPLICADA
            if (activationInProgress) {
                addBlockLog("⚠️ Ativação já em andamento...");
                return;
            }

            if (activationCodeInput == null) {
                addBlockLog("❌ Erro: Campo de ativação não encontrado");
                return;
            }

            String activationCode = activationCodeInput.getText().toString().trim();

            // ✅ Validações de formato
            if (activationCode.isEmpty()) {
                addBlockLog("❌ Digite um código de ativação");
                Toast.makeText(this, "Digite o código de ativação", Toast.LENGTH_SHORT).show();
                return;
            }

            if (activationCode.length() < 4) {
                addBlockLog("❌ Código muito curto (mínimo 4 caracteres)");
                Toast.makeText(this, "Código deve ter pelo menos 4 caracteres", Toast.LENGTH_SHORT).show();
                return;
            }

            // ✅ Verificar conexão com internet
            if (!isInternetAvailable()) {
                addBlockLog("❌ Sem conexão com a internet");
                Toast.makeText(this, "Verifique sua conexão com a internet", Toast.LENGTH_LONG).show();
                return;
            }

            // ✅ Mostrar progresso
            addBlockLog("🔍 Validando código de ativação...");
            addBlockLog("🌐 Conectando ao servidor...");

            // ✅ Ativar agent no servidor DomCustos
            if (DomCustosAPI.activateAgent(this, activationCode)) {
                addBlockLog("✅ Agent registrado no servidor!");
            } else {
                addBlockLog("⚠️ Agent não registrado (código inválido?)");
                // Continua mesmo assim, pois pode funcionar localmente
            }

            // Desabilitar botão durante validação
            if (activateButton != null) {
                activateButton.setEnabled(false);
                activateButton.setText("VALIDANDO...");
            }

            // ✅ MARCAR COMO EM PROGRESSO
            activationInProgress = true;

            // ✅ Executar ativação em thread separada
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Chamar o método de ativação
                        final boolean success = dnsManager != null && dnsManager.activateAgent(activationCode);

                        // Atualizar UI na thread principal
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                // ✅ DESMARCAR COMO EM PROGRESSO
                                activationInProgress = false;

                                // Reabilitar botão
                                if (activateButton != null) {
                                    activateButton.setEnabled(true);
                                }

                                if (success) {
                                    // ✅ SUCESSO
                                    updateUIForActivatedState();
                                    addBlockLog("✅ Agente ativado com sucesso!");
                                    addBlockLog("🔐 DoH (DNS over HTTPS) habilitado");
                                    addBlockLog("🛡️ Proteção ativada");

                                    Toast.makeText(DNSProxyActivity.this,
                                            "✅ Agente ativado com sucesso!",
                                            Toast.LENGTH_LONG).show();

                                    // ✅ VERIFICAR E SOLICITAR PERMISSÃO DE NOTIFICAÇÃO SE NECESSÁRIO
                                    if (Build.VERSION.SDK_INT >= 33) {
                                        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                                            addBlockLog("📢 Solicitando permissão para notificações...");
                                            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, NOTIFICATION_PERMISSION_REQUEST);
                                        } else {
                                            // ✅ Já tem permissão - mostrar popup diretamente
                                            new Handler().postDelayed(new Runnable() {
                                                @Override
                                                public void run() {
                                                    showWelcomePopup();
                                                }
                                            }, 1000);
                                        }
                                    } else {
                                        // ✅ Android anterior - mostrar popup diretamente
                                        new Handler().postDelayed(new Runnable() {
                                            @Override
                                            public void run() {
                                                showWelcomePopup();
                                            }
                                        }, 1000);
                                    }

                                    // ✅ INICIAR SERVIÇO DNS AUTOMATICAMENTE
                                    new Handler().postDelayed(new Runnable() {
                                        @Override
                                        public void run() {
                                            addBlockLog("🚀 Iniciando serviço DNS...");
                                            servicesStarted = true; // ✅ MARCAR COMO INICIADO
                                            startDNSServiceWithVPN();
                                        }
                                    }, 1000);

                                } else {
                                    // ❌ FALHA
                                    addBlockLog("❌ Falha na ativação");
                                    addBlockLog("📋 Verifique se o código está correto");
                                    addBlockLog("🌐 Verifique sua conexão com a internet");

                                    if (statusText != null) {
                                        statusText.setText("Falha na ativação - Código inválido");
                                        statusText.setTextColor(getResources().getColor(android.R.color.holo_red_dark));
                                    }

                                    if (activateButton != null) {
                                        activateButton.setText("TENTAR NOVAMENTE");
                                    }

                                    Toast.makeText(DNSProxyActivity.this,
                                            "❌ Código de ativação inválido",
                                            Toast.LENGTH_LONG).show();
                                }
                            }
                        });

                    } catch (final Exception e) {
                        // ❌ ERRO
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                // ✅ DESMARCAR COMO EM PROGRESSO
                                activationInProgress = false;

                                if (activateButton != null) {
                                    activateButton.setEnabled(true);
                                    activateButton.setText("TENTAR NOVAMENTE");
                                }

                                addBlockLog("❌ Erro durante ativação: " + e.getMessage());
                                Toast.makeText(DNSProxyActivity.this,
                                        "❌ Erro: " + e.getMessage(),
                                        Toast.LENGTH_LONG).show();
                            }
                        });
                    }
                }
            }).start();

        } catch (Exception e) {
            Log.e(TAG, "Erro ao ativar agent", e);
            addBlockLog("❌ Erro: " + e.getMessage());

            // ✅ DESMARCAR COMO EM PROGRESSO EM CASO DE ERRO
            activationInProgress = false;

            if (activateButton != null) {
                activateButton.setEnabled(true);
                activateButton.setText("ATIVAR AGENTE");
            }
        }
    }

    // =============================
    // 🌐 VERIFICAR INTERNET
    // =============================
    private boolean isInternetAvailable() {
        try {
            android.net.ConnectivityManager cm =
                    (android.net.ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);

            if (cm != null) {
                android.net.NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
                return activeNetwork != null && activeNetwork.isConnectedOrConnecting();
            }

            return false;
        } catch (Exception e) {
            Log.e(TAG, "Erro ao verificar internet", e);
            return true; // Assumir que tem internet em caso de erro
        }
    }

    private void startDNSServiceWithVPN() {
        try {
            addBlockLog("🔐 Iniciando serviço DNS com VPN...");

            // Verificar se já está rodando
            if (AdvancedFunctions.isServiceRunning()) {
                addBlockLog("✅ Serviço DNS já está ativo");
                return;
            }

            // Verificar permissão VPN
            Intent vpnIntent = VpnService.prepare(this);

            if (vpnIntent != null) {
                // Precisa solicitar permissão
                addBlockLog("📋 Solicitando permissão VPN...");
                waitingForVpnPermission = true;
                startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
            } else {
                // Já tem permissão - iniciar serviço diretamente
                addBlockLog("✅ Permissão VPN já concedida");
                startDNSService();
            }

        } catch (Exception e) {
            Log.e(TAG, "Erro ao configurar VPN", e);
            addBlockLog("❌ Erro ao configurar VPN: " + e.getMessage());
            Toast.makeText(this, "Erro ao configurar VPN", Toast.LENGTH_SHORT).show();
        }
    }

    private void startDNSService() {
        try {
            addBlockLog("🚀 Iniciando serviço DNS...");

            AdvancedFunctions.startDNSService(this);

            // Aguardar e verificar status
            new Handler().postDelayed(new Runnable() {
                @Override
                public void run() {
                    if (AdvancedFunctions.isServiceRunning()) {
                        addBlockLog("✅ Serviço DNS iniciado com sucesso!");
                        servicesStarted = true;

                        // ✅ Verificar se DoH foi habilitado
                        if (dnsManager != null && dnsManager.isDohEnabled()) {
                            addBlockLog("🔐 DoH ativado com sucesso!");
                        }

                        updateServiceStatus();
                        Toast.makeText(DNSProxyActivity.this,
                                "✅ Proteção ativada!", Toast.LENGTH_SHORT).show();
                    } else {
                        addBlockLog("⚠️ Serviço ainda não está ativo");
                        addBlockLog("🔄 Tentando novamente...");

                        // Tentar verificar novamente
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                if (AdvancedFunctions.isServiceRunning()) {
                                    addBlockLog("✅ Serviço DNS ativo!");
                                    servicesStarted = true;
                                    updateServiceStatus();
                                } else {
                                    addBlockLog("❌ Serviço não iniciou");
                                    addBlockLog("💡 Reinicie o aplicativo");
                                }
                            }
                        }, 3000);
                    }
                }
            }, 2000);

        } catch (Exception e) {
            Log.e(TAG, "Erro ao iniciar serviço", e);
            addBlockLog("❌ Erro ao iniciar serviço: " + e.toString());
            Toast.makeText(this, "❌ Erro ao iniciar", Toast.LENGTH_SHORT).show();
        }
    }

    // ✅ VALIDAÇÃO DE ATIVAÇÃO ANTES DE ABRIR CONFIGURAÇÕES AVANÇADAS
    private void openAdvancedSettings() {
        try {
            // ✅ TEMPORARIAMENTE REMOVIDO PARA DEBUG: Verificar se o agente está ativado
            // if (!dnsManager.isAgentActivated()) {
            //     addBlockLog("⚠️ Configurações avançadas requerem ativação");
            //     Toast.makeText(this,
            //             "🔒 Ative o agente primeiro para acessar configurações avançadas",
            //             Toast.LENGTH_LONG).show();
            //     return;
            // }

            addBlockLog("⚙️ Abrindo configurações avançadas...");

            Intent intent = new Intent(this, AdvancedSettingsActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);

            startActivityForResult(intent, ADVANCED_SETTINGS_REQUEST);

        } catch (Exception e) {
            Log.e(TAG, "Erro ao abrir configurações avançadas", e);
            addBlockLog("❌ Erro: " + e.getMessage());
            Toast.makeText(this, "Erro ao abrir configurações", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        try {
            if (requestCode == VPN_REQUEST_CODE) {
                waitingForVpnPermission = false;

                if (resultCode == RESULT_OK) {
                    addBlockLog("✅ Permissão VPN concedida!");
                    startDNSService(); // ✅ INICIAR SERVIÇO APÓS PERMISSÃO
                } else {
                    addBlockLog("❌ Permissão VPN negada");
                    addBlockLog("⚠️ O serviço DNS precisa de permissão VPN");
                    Toast.makeText(this,
                            "Permissão VPN necessária para funcionar",
                            Toast.LENGTH_LONG).show();
                }
            }

            if (requestCode == ADVANCED_SETTINGS_REQUEST) {
                addBlockLog("🔄 Retornou das configurações avançadas");
                checkInitialStatus(); // ✅ ATUALIZAR STATUS APÓS CONFIGURAÇÕES
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro em onActivityResult", e);
        }
    }

    // =============================
    // 🎨 ATUALIZAR UI - ESTADO ATIVADO
    // =============================
    private void updateUIForActivatedState() {
        try {
            if (statusIndicator != null) {
                statusIndicator.setText("● ATIVADO");
                statusIndicator.setTextColor(getResources().getColor(android.R.color.holo_green_dark));
            }

            if (statusText != null) {
                statusText.setText("✅ Agente Ativado - DoH Habilitado");
                statusText.setTextColor(getResources().getColor(android.R.color.holo_green_dark));
            }

            if (activateButton != null) {
                activateButton.setText("REATIVAR AGENTE");
            }

            // ✅ OCULTAR CAMPO DE CÓDIGO QUANDO ATIVADO
            if (activationCodeInput != null) {
                activationCodeInput.setText("");
                activationCodeInput.setHint("Agente já ativado");
                activationCodeInput.setVisibility(View.GONE); // ✅ NOVO: Oculta o campo
            }

        } catch (Exception e) {
            Log.e(TAG, "Erro ao atualizar UI (ativado)", e);
        }
    }

    // =============================
    // 🎨 ATUALIZAR UI - ESTADO DESATIVADO
    // =============================
    private void updateUIForDeactivatedState() {
        try {
            if (statusIndicator != null) {
                statusIndicator.setText("● DESATIVADO");
                statusIndicator.setTextColor(getResources().getColor(android.R.color.holo_red_dark));
            }

            if (statusText != null) {
                statusText.setText("⚠️ Aguardando ativação");
                statusText.setTextColor(getResources().getColor(android.R.color.holo_blue_dark));
            }

            if (activateButton != null) {
                activateButton.setText("ATIVAR AGENTE");
                activateButton.setEnabled(true);
            }

            // ✅ MOSTRAR CAMPO DE CÓDIGO QUANDO DESATIVADO
            if (activationCodeInput != null) {
                activationCodeInput.setHint("Digite o código de ativação");
                activationCodeInput.setVisibility(View.VISIBLE); // ✅ NOVO: Mostra o campo
            }

        } catch (Exception e) {
            Log.e(TAG, "Erro ao atualizar UI (desativado)", e);
        }
    }

    public void addBlockLog(final String message) {
        if (message == null) return;

        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (blockLogText != null) {
                        String currentLog = blockLogText.getText().toString();
                        String timestamp = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
                        String newLog = "[" + timestamp + "] " + message + "\n" + currentLog;

                        // Manter apenas as últimas 50 linhas
                        String[] lines = newLog.split("\n");
                        if (lines.length > 50) {
                            StringBuilder limitedLog = new StringBuilder();
                            for (int i = 0; i < 50; i++) {
                                limitedLog.append(lines[i]).append("\n");
                            }
                            newLog = limitedLog.toString();
                        }

                        blockLogText.setText(newLog);

                        // ✅ NOVO: Rolar automaticamente para o final
                        final ScrollView scrollView = findViewById(R.id.blockLogScroll);
                        if (scrollView != null) {
                            // Usar postDelayed para garantir que o texto foi renderizado
                            scrollView.postDelayed(new Runnable() {
                                @Override
                                public void run() {
                                    scrollView.fullScroll(View.FOCUS_DOWN);
                                }
                            }, 100);
                        }
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Erro ao adicionar log", e);
                }
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        try {
            addBlockLog("🔄 Activity retomada");

            // ✅ APENAS VERIFICAR STATUS, NÃO TENTAR INICIAR NOVAMENTE
            if (dnsManager != null && dnsManager.isAgentActivated()) {
                updateUIForActivatedState();

                if (AdvancedFunctions.isServiceRunning()) {
                    addBlockLog("📡 Serviço DNS ativo");
                    updateServiceStatus();
                } else if (!servicesStarted && !activationInProgress) {
                    // Apenas mostrar status, não tentar iniciar automaticamente
                    addBlockLog("⚠️ Serviço DNS parado");
                    addBlockLog("💡 Use o botão REATIVAR para iniciar");
                }
            } else {
                updateUIForDeactivatedState();
            }

            // ✅ Retomar atualizações periódicas
            if (statusUpdateHandler != null && statusUpdateRunnable != null) {
                statusUpdateHandler.removeCallbacks(statusUpdateRunnable);
                statusUpdateHandler.postDelayed(statusUpdateRunnable, 1000);
            }

            // ✅ NOVO: Garantir que o scroll está no final
            final ScrollView scrollView = findViewById(R.id.blockLogScroll);
            if (scrollView != null) {
                scrollView.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        scrollView.fullScroll(View.FOCUS_DOWN);
                    }
                }, 200);
            }

        } catch (Exception e) {
            Log.e(TAG, "Erro em onResume", e);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        try {
            addBlockLog("⏸️ Activity pausada - Serviço continua ativo");

            // ✅ Pausar atualizações periódicas para economizar bateria
            if (statusUpdateHandler != null && statusUpdateRunnable != null) {
                statusUpdateHandler.removeCallbacks(statusUpdateRunnable);
            }

        } catch (Exception e) {
            Log.e(TAG, "Erro em onPause", e);
        }
    }

    @Override
    public void onBackPressed() {
        try {
            addBlockLog("📱 App movido para background - Serviço continua ativo");
            moveTaskToBack(true);
        } catch (Exception e) {
            Log.e(TAG, "Erro em onBackPressed", e);
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        try {
            // ✅ Limpar handler para evitar memory leak
            if (statusUpdateHandler != null && statusUpdateRunnable != null) {
                statusUpdateHandler.removeCallbacks(statusUpdateRunnable);
            }

            addBlockLog("🔴 Activity destruída - Serviço continua rodando");
            Log.d(TAG, "onDestroy - Serviço continua em background");
        } catch (Exception e) {
            Log.e(TAG, "Erro em onDestroy", e);
        }
    }

    // =============================
    // 📝 LOGGER PARA UI (similar ao AdvancedSettingsActivity)
    // =============================
    private void setupUILogger() {
        try {
            LoggerInterface uiLogger = new LoggerInterface() {
                @Override
                public void logLine(String txt) {
                    runOnUiThread(new MyUIThreadLogger(txt));
                }

                @Override
                public void log(String txt) {
                    runOnUiThread(new MyUIThreadLogger(txt));
                }

                @Override
                public void logException(Exception e) {
                    runOnUiThread(new MyUIThreadLogger("Exception: " + e.toString()));
                }

                @Override
                public void message(String txt) {
                    runOnUiThread(new MyUIThreadLogger(txt));
                }

                @Override
                public void closeLogger() {
                    // Não faz nada
                }
            };

            // Combinar com logger existente
            LoggerInterface existingLogger = Logger.getLogger();
            if (existingLogger != null) {
                Logger.setLogger(new GroupedLogger(new LoggerInterface[]{existingLogger, uiLogger}));
            } else {
                Logger.setLogger(uiLogger);
            }

            Log.d(TAG, "Logger UI configurado");
        } catch (Exception e) {
            Log.e(TAG, "Erro ao configurar logger UI", e);
        }
    }

    private class MyUIThreadLogger implements Runnable {
        private String m_logStr;

        public MyUIThreadLogger(String logStr) {
            m_logStr = logStr;
        }

        @Override
        public synchronized void run() {
            addBlockLog(m_logStr);
        }
    }
}