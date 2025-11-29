package dnsfilter.android;

import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.app.Activity;
import android.net.VpnService;
import dnsfilter.ConfigurationAccess;
import dnsfilter.DNSFilterManager;
import util.ExecutionEnvironment;
import util.Logger;
import util.LoggerInterface;
import util.GroupedLogger;
import util.SuppressRepeatingsLogger;
import java.io.IOException;

public class AdvancedFunctions {

    private static final String TAG = "AdvancedFunctions";
    private static SuppressRepeatingsLogger myLogger;
    private static boolean initialized = false;
    private static boolean serviceStarting = false; // ✅ CONTROLE DE ESTADO

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
}