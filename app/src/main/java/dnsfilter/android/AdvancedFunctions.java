package dnsfilter.android;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;
import android.app.Activity;
import android.net.VpnService;
import dnsfilter.ConfigurationAccess;
import dnsfilter.ConfigUtil;
import dnsfilter.DNSFilterManager;
import util.ExecutionEnvironment;
import util.Logger;
import util.LoggerInterface;
import util.GroupedLogger;
import util.SuppressRepeatingsLogger;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.util.Properties;

public class AdvancedFunctions {

    private static final String TAG = "AdvancedFunctions";
    private static SuppressRepeatingsLogger myLogger;
    private static boolean initialized = false;
    private static boolean serviceStarting = false;
    private static ConfigUtil configUtil = null;
    private static Properties config = null;

    public static void initializeBackgroundFunctions(Context context) {
        if (initialized) {
            Log.d(TAG, "🔧 AdvancedFunctions já inicializado");
            return;
        }

        try {
            Log.d(TAG, "🔧 Inicializando AdvancedFunctions...");

            // Inicializar AndroidEnvironment
            AndroidEnvironment.initEnvironment(context);

            // ✅ CORREÇÃO: Criar logger SEM recursão
            myLogger = new SuppressRepeatingsLogger(new LoggerInterface() {
                @Override
                public void logLine(String txt) {
                    Log.i(TAG, txt);
                }

                @Override
                public void log(String txt) {
                    Log.i(TAG, txt);
                }

                @Override
                public void logException(Exception e) {
                    Log.e(TAG, "Exception", e);
                }

                @Override
                public void message(String txt) {
                    Log.i(TAG, "[MESSAGE] " + txt);
                }

                @Override
                public void closeLogger() {
                    // Não faz nada
                }
            });

            // ✅ CORREÇÃO: Obter logger existente ANTES de criar o GroupedLogger
            LoggerInterface existingLogger = Logger.getLogger();

            // ✅ Criar GroupedLogger SEM recursão
            if (existingLogger != null) {
                Logger.setLogger(new GroupedLogger(new LoggerInterface[]{
                        existingLogger,
                        myLogger
                }));
            } else {
                Logger.setLogger(myLogger);
            }

            initialized = true;
            Log.d(TAG, "✅ AdvancedFunctions inicializado com sucesso!");

        } catch (Exception e) {
            Log.e(TAG, "❌ Erro na inicialização do AdvancedFunctions", e);
            e.printStackTrace();
        }
    }

    /**
     * ✅ MÉTODO PRINCIPAL CORRIGIDO: Inicia DNS Service com verificação de VPN
     * Este é o único método que deve ser usado para iniciar o serviço
     */
    public static void startDNSService(Context context) {
        try {
            // ✅ PREVENIR INÍCIOS DUPLICADOS
            if (serviceStarting) {
                Log.d(TAG, "⚠️ Serviço já está sendo iniciado...");
                return;
            }

            if (isServiceRunning()) {
                Log.d(TAG, "⚠️ Serviço DNS já está em execução");
                return;
            }

            Log.d(TAG, "🚀 Iniciando serviço DNS...");

            if (!initialized) {
                initializeBackgroundFunctions(context);
            }

            // ✅ MARCAR COMO INICIANDO
            serviceStarting = true;

            // Verificar configuração de VPN
            boolean needsVpn = needsVpnPermission(context);

            if (needsVpn) {
                Log.d(TAG, "🔐 Modo VPN detectado - Iniciando DNSFilterService");
                Intent serviceIntent = new Intent(context, DNSFilterService.class);
                context.startService(serviceIntent);
            } else {
                Log.d(TAG, "⚙️ Modo proxy detectado - Iniciando sem VPN");
                // Para modo proxy, o serviço pode ser iniciado diretamente
                Intent serviceIntent = new Intent(context, DNSFilterService.class);
                context.startService(serviceIntent);
            }

            Log.d(TAG, "✅ Comando de início do serviço enviado");

        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao iniciar serviço DNS", e);
        } finally {
            // ✅ DESMARCAR APÓS 5 SEGUNDOS (tempo razoável para o serviço iniciar)
            new android.os.Handler().postDelayed(() -> {
                serviceStarting = false;
            }, 5000);
        }
    }

    /**
     * ✅ MÉTODO SIMPLIFICADO: Verifica se precisa de permissão VPN
     */
    public static boolean needsVpnPermission(Context context) {
        try {
            // Verificar configuração
            boolean dnsProxyOnAndroid = Boolean.parseBoolean(
                    ConfigurationAccess.getLocal().getConfig()
                            .getProperty("dnsProxyOnAndroid", "false")
            );

            // Se dnsProxyOnAndroid = true, NÃO precisa de VPN
            // Se dnsProxyOnAndroid = false, PRECISA de VPN
            return !dnsProxyOnAndroid;

        } catch (Exception e) {
            Log.e(TAG, "Erro ao verificar configuração VPN", e);
            return true; // Por padrão, assume que precisa de VPN
        }
    }

    /**
     * ✅ MÉTODO UNIFICADO: Inicia DNS com verificação de permissão VPN
     * Para ser usado quando precisar solicitar permissão via Activity
     */
    public static boolean startDNSWithVPN(Context context, Activity activity, int vpnRequestCode) {
        try {
            Log.d(TAG, "🚀 Iniciando DNS com verificação VPN...");

            if (isServiceRunning()) {
                Log.d(TAG, "✅ Serviço já está ativo");
                return true;
            }

            // ✅ PREVENIR INÍCIOS DUPLICADOS
            if (serviceStarting) {
                Log.d(TAG, "⚠️ Serviço já está sendo iniciado...");
                return false;
            }

            // Verificar se precisa de VPN
            if (!needsVpnPermission(context)) {
                Log.d(TAG, "⚙️ Modo proxy - Iniciando sem VPN");
                startDNSService(context);
                return true;
            }

            // Verificar permissão VPN
            if (!isVpnPermissionGranted(context)) {
                Log.d(TAG, "📋 Solicitando permissão VPN...");
                Intent vpnIntent = getVpnPermissionIntent(context);
                if (vpnIntent != null && activity != null) {
                    activity.startActivityForResult(vpnIntent, vpnRequestCode);
                    return false; // Aguardar resultado da permissão
                }
            }

            // Se já tem permissão, iniciar serviço
            Log.d(TAG, "✅ Permissão VPN concedida - Iniciando serviço");
            startDNSService(context);
            return true;

        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao iniciar DNS com VPN", e);
            return false;
        }
    }

    // ✅ REMOVIDO: startVPNService() - duplicado com startDNSService()

    /**
     * ✅ Método para verificar permissão VPN
     */
    public static boolean isVpnPermissionGranted(Context context) {
        try {
            Intent vpnIntent = VpnService.prepare(context);
            return vpnIntent == null; // null = permissão concedida
        } catch (Exception e) {
            Log.e(TAG, "Erro ao verificar permissão VPN", e);
            return false;
        }
    }

    /**
     * ✅ Método para obter intent de permissão VPN
     */
    public static Intent getVpnPermissionIntent(Context context) {
        try {
            return VpnService.prepare(context);
        } catch (Exception e) {
            Log.e(TAG, "Erro ao obter intent de VPN", e);
            return null;
        }
    }

    public static void stopDNSService(Context context) {
        try {
            Log.d(TAG, "🛑 Parando serviço DNS...");

            // ✅ RESETAR CONTROLE DE ESTADO
            serviceStarting = false;

            boolean stopped = DNSFilterService.stop(true);

            if (stopped) {
                Log.d(TAG, "✅ Serviço DNS parado com sucesso");
            } else {
                Log.d(TAG, "⚠️ Serviço DNS já estava parado");
            }

        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao parar serviço DNS", e);
        }
    }

    public static void reloadFilters() {
        try {
            Log.d(TAG, "🔄 Recarregando filtros...");

            ConfigurationAccess.getLocal().triggerUpdateFilter();

            Log.d(TAG, "✅ Filtros recarregados com sucesso");

        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao recarregar filtros", e);
        }
    }

    public static void restartDNSService(Context context) {
        try {
            Log.d(TAG, "🔄 Reiniciando serviço DNS...");

            stopDNSService(context);

            // Aguardar um pouco antes de reiniciar
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            startDNSService(context);

            Log.d(TAG, "✅ Serviço DNS reiniciado com sucesso");

        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao reiniciar serviço DNS", e);
        }
    }

    public static boolean isServiceRunning() {
        return DNSFilterService.SERVICE != null;
    }

    public static boolean isServiceStarting() {
        return serviceStarting;
    }

    public static String getServiceStatus() {
        try {
            if (isServiceRunning()) {
                int connections = ConfigurationAccess.getLocal().openConnectionsCount();
                return "✅ Serviço Ativo - Conexões: " + connections;
            } else if (serviceStarting) {
                return "🔄 Iniciando Serviço...";
            } else {
                return "❌ Serviço Parado";
            }
        } catch (IOException e) {
            Log.e(TAG, "Erro ao obter status", e);
            return "⚠️ Status Indisponível";
        }
    }

    public static String getFilterStats() {
        try {
            long[] stats = ConfigurationAccess.getLocal().getFilterStatistics();
            long total = stats[0] + stats[1];

            if (total > 0) {
                long blocked = stats[1];
                long rate = (blocked * 100) / total;
                return "📊 Filtro: " + rate + "% bloqueado (" + blocked + " de " + total + ")";
            } else {
                return "📊 Filtro: Nenhuma estatística disponível";
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro ao obter estatísticas", e);
            return "📊 Filtro: Estatísticas indisponíveis";
        }
    }

    public static void showFilterRate() {
        try {
            long[] stats = ConfigurationAccess.getLocal().getFilterStatistics();
            long total = stats[0] + stats[1];

            if (total != 0) {
                long filterRate = 100 * stats[1] / total;
                String message = "Block rate: " + filterRate + "% (" + stats[1] + " blocked)!";
                Log.i(TAG, message);

                try {
                    Logger.getLogger().message(message);
                } catch (Exception e) {
                    // Ignorar se Logger não estiver disponível
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao mostrar estatísticas", e);
        }
    }

    public static boolean isInitialized() {
        return initialized;
    }

    // =============================
    // 📋 MÉTODOS DE CONFIGURAÇÃO
    // =============================

    /**
     * Carrega e retorna a configuração atual
     */
    public static ConfigUtil getConfig() {
        try {
            if (configUtil == null) {
                loadConfig();
            }
            return configUtil;
        } catch (Exception e) {
            Log.e(TAG, "Erro ao obter configuração", e);
            return null;
        }
    }

    /**
     * Carrega a configuração do arquivo
     */
    public static void loadConfig() {
        try {
            // Usar getConfigUtil() que é público
            configUtil = ConfigurationAccess.getLocal().getConfigUtil();
            
            byte[] configBytes = ConfigurationAccess.getLocal().readConfig();
            config = new Properties();
            config.load(new ByteArrayInputStream(configBytes));
            
            Log.d(TAG, "✅ Configuração carregada com sucesso");
        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao carregar configuração", e);
        }
    }

    /**
     * Retorna as properties de configuração
     */
    public static Properties getConfigProperties() {
        if (config == null) {
            loadConfig();
        }
        return config;
    }

    /**
     * Atualiza um valor de configuração
     */
    public static void updateConfigValue(String key, String value) {
        try {
            if (configUtil == null) {
                loadConfig();
            }
            if (configUtil != null) {
                configUtil.updateConfigValue(key, value);
                ConfigurationAccess.getLocal().updateConfig(configUtil.getConfigBytes());
                Log.d(TAG, "✅ Configuração atualizada: " + key + " = " + value);
            }
        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao atualizar configuração", e);
        }
    }

    /**
     * Obtém um valor de configuração
     */
    public static String getConfigValue(String key, String defaultValue) {
        try {
            if (configUtil == null) {
                loadConfig();
            }
            if (configUtil != null) {
                return configUtil.getConfigValue(key, defaultValue);
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro ao obter valor de configuração: " + key, e);
        }
        return defaultValue;
    }

    /**
     * Persiste a configuração atual
     */
    public static void persistConfig() {
        try {
            if (configUtil != null) {
                ConfigurationAccess.getLocal().updateConfig(configUtil.getConfigBytes());
                Log.d(TAG, "✅ Configuração persistida com sucesso");
            }
        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao persistir configuração", e);
        }
    }

    /**
     * Invalida a configuração para forçar recarga
     */
    public static void invalidateConfig() {
        configUtil = null;
        config = null;
        Log.d(TAG, "Configuração invalidada - será recarregada no próximo acesso");
    }

    /**
     * Obtém o logger principal
     */
    public static SuppressRepeatingsLogger getLogger() {
        return myLogger;
    }

    /**
     * Define o tempo de supressão de logs repetidos
     */
    public static void setLoggerSuppressTime(long time) {
        if (myLogger != null) {
            myLogger.setSuppressTime(time);
        }
    }

    /**
     * Define o formato de timestamp do logger
     */
    public static void setLoggerTimestampFormat(String format) {
        if (myLogger != null) {
            myLogger.setTimestampFormat(format);
        }
    }

    // =============================
    // 🔐 MÉTODOS DE AUTENTICAÇÃO (migrados de AdvancedSettingsActivity)
    // =============================

    private static final String PREFS_NAME = "AdvancedSettingsPrefs";
    private static final String PASSWORD_KEY = "admin_password";
    private static final String DEFAULT_PASSWORD = "mvc645370";

    /**
     * Verifica se o usuário está autenticado
     */
    public static boolean isAuthenticated(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        long lastAuthTime = prefs.getLong("last_auth_time", 0);
        long currentTime = System.currentTimeMillis();
        long sessionTimeout = 30 * 60 * 1000; // 30 minutos

        boolean wasAuthenticated = prefs.getBoolean("authenticated", false);
        if (wasAuthenticated && (currentTime - lastAuthTime) > sessionTimeout) {
            setAuthenticated(context, false);
            return false;
        }
        return wasAuthenticated;
    }

    /**
     * Define o status de autenticação
     */
    public static void setAuthenticated(Context context, boolean authenticated) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putBoolean("authenticated", authenticated);
        if (authenticated) {
            editor.putLong("last_auth_time", System.currentTimeMillis());
        } else {
            editor.remove("last_auth_time");
        }
        editor.apply();
    }

    /**
     * Obtém a senha salva
     */
    public static String getSavedPassword(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return prefs.getString(PASSWORD_KEY, DEFAULT_PASSWORD);
    }

    // =============================
    // 🚀 MÉTODO PARA ATIVAR TODOS OS RECURSOS
    // =============================

    /**
     * Ativa todos os recursos: filtros, logs, DoH, etc.
     */
    public static void activateAllFeatures(Context context) {
        try {
            Log.d(TAG, "🚀 Ativando todos os recursos...");

            // Ativar filtros
            updateConfigValue("filterActive", "true");
            updateConfigValue("enableTrafficLog", "true");

            // Ativar DoH (se configurado)
            updateConfigValue("detectDNS", "true");

            // Outras configurações essenciais
            updateConfigValue("checkResolvedIP", "false");
            updateConfigValue("checkCNAME", "true");

            // Forçar carregamento de filtros
            reloadFilters();

            Log.d(TAG, "✅ Todos os recursos ativados com sucesso");

        } catch (Exception e) {
            Log.e(TAG, "❌ Erro ao ativar recursos", e);
        }
    }
}