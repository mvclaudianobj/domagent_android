package dnsfilter.android;

import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.io.File;
import java.io.FileInputStream;
import javax.net.ssl.HttpsURLConnection;
import android.provider.Settings;
import dnsfilter.BlockedHosts;
import dnsfilter.ConfigurationAccess;
import dnsfilter.ConfigUtil;
import util.Logger;

public class DomCustosAPI {
    private static final String TAG = "DomCustosAPI";
    private static final String API_BASE_URL = "https://domcustos.com.br/api";
    private static final int TIMEOUT_MS = 30000; // 30 segundos

    private static String agentID = null;
    private static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    // Classe para regras
    public static class Rules {
        public List<String> blockedApps = new ArrayList<>();
        public List<String> blockedSites = new ArrayList<>();
    }

    // Salvar agentID em agent_prefs.conf
    private static void saveAgentIdToPrefs(android.content.Context context, String agentId) throws Exception {
        File prefsFile = new File(context.getExternalFilesDir(null), "DomCustosAgent/agent_prefs.conf");
        prefsFile.getParentFile().mkdirs(); // Criar diretório se não existir

        Properties prefs = new Properties();
        if (prefsFile.exists()) {
            FileInputStream fis = new FileInputStream(prefsFile);
            prefs.load(fis);
            fis.close();
        }

        prefs.setProperty("agentId", agentId);

        java.io.FileOutputStream fos = new java.io.FileOutputStream(prefsFile);
        prefs.store(fos, "DomCustosAgent Preferences");
        fos.close();
    }

    // Gerar agentID usando ANDROID_ID diretamente (único por device)
    public static String generateHostID(android.content.Context context) {
        try {
            String androidId = Settings.Secure.getString(
                context.getContentResolver(),
                Settings.Secure.ANDROID_ID);
            if (androidId != null && !androidId.isEmpty() && !androidId.equals("9774d56d682e549c")) { // Evitar ID genérico
                // Usar primeiros 16 chars do ANDROID_ID
                return androidId.length() > 16 ? androidId.substring(0, 16) : androidId;
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro ao obter ANDROID_ID", e);
        }
        // Fallback
        return java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    // Inicializar API e agendamento
    public static void initialize(android.content.Context context) {
        try {
            // Ler agentID de agent_prefs.conf (mesmo arquivo usado por DNSFilterManager)
            File prefsFile = new File(context.getExternalFilesDir(null), "DomCustosAgent/agent_prefs.conf");
            Log.d(TAG, "Tentando carregar prefs de: " + prefsFile.getAbsolutePath());
            Log.d(TAG, "Arquivo prefs existe: " + prefsFile.exists());
            if (prefsFile.exists()) {
                Properties prefs = new Properties();
                FileInputStream fis = new FileInputStream(prefsFile);
                prefs.load(fis);
                fis.close();
                Log.d(TAG, "Conteúdo do prefs: " + prefs.toString());
                agentID = prefs.getProperty("agent_id", "default_agent");
                Log.d(TAG, "AgentID carregado de agent_prefs.conf: " + agentID);
            } else {
                Log.w(TAG, "Arquivo agent_prefs.conf não encontrado");
                agentID = "default_agent"; // Fallback
            }

            // Agendar busca de regras a cada 1 minuto
            scheduler.scheduleAtFixedRate(() -> {
                try {
                    Rules rules = fetchRules();
                    updateBlockCache(rules);
                } catch (Exception e) {
                    Logger.getLogger().logLine("Erro ao atualizar regras da API: " + e.getMessage());
                }
            }, 0, 1, TimeUnit.MINUTES);

            Log.d(TAG, "DomCustosAPI inicializado com agentID: " + agentID);
        } catch (Exception e) {
            Log.e(TAG, "Erro ao inicializar DomCustosAPI", e);
        }
    }

    // Buscar regras da API
    public static Rules fetchRules() throws Exception {
        String url = API_BASE_URL + "/agent/rules/" + agentID;
        Log.d(TAG, "Buscando regras da API: " + url);
        HttpsURLConnection conn = null;

        try {
            URL apiUrl = new URL(url);
            conn = (HttpsURLConnection) apiUrl.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", "application/json");

            int responseCode = conn.getResponseCode();
            Log.d(TAG, "Resposta da API rules: " + responseCode);

            if (responseCode == 404) {
                // Agente sem regras ainda
                Log.d(TAG, "Agente sem regras (404)");
                return new Rules();
            }

            if (responseCode != 200) {
                throw new Exception("API retornou status " + responseCode);
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            Log.d(TAG, "Resposta JSON: " + response.toString());

            // Parse JSON
            JSONObject json = new JSONObject(response.toString());
            Rules rules = new Rules();

            if (json.has("blocked_apps")) {
                JSONArray apps = json.getJSONArray("blocked_apps");
                for (int i = 0; i < apps.length(); i++) {
                    rules.blockedApps.add(apps.getString(i));
                }
            }

            if (json.has("blocked_sites")) {
                JSONArray sites = json.getJSONArray("blocked_sites");
                for (int i = 0; i < sites.length(); i++) {
                    rules.blockedSites.add(sites.getString(i));
                }
            }

            Log.d(TAG, "Regras carregadas: " + rules.blockedSites.size() + " sites, " + rules.blockedApps.size() + " apps");
            return rules;

        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // Ativar agent no servidor (unificada - gera agentID se necessário)
    public static boolean activateAgent(android.content.Context context, String activationCode) {
        try {
            // Garantir agentID
            if (agentID == null || "default_agent".equals(agentID)) {
                ConfigUtil configUtil = ConfigurationAccess.getLocal().getConfigUtil();
                String savedID = configUtil.getConfigValue("agentID", "default_agent");
                if ("default_agent".equals(savedID)) {
                agentID = generateHostID(context);
                // Salvar em agent_prefs.conf (mesmo arquivo usado por DNSFilterManager)
                saveAgentIdToPrefs(context, agentID);
                Log.d(TAG, "AgentID gerado para ativação: " + agentID);
                } else {
                    agentID = savedID;
                }
            }

            String url = API_BASE_URL + "/agent/activate";
            HttpsURLConnection conn = null;

            JSONObject data = new JSONObject();
            data.put("activation_code", activationCode);
            data.put("agent_id", agentID);
            data.put("os_type", "android");
            data.put("version", "1.0.0");
            Log.d(TAG, "Enviando activate com agentID: " + agentID + ", os_type: android");

            String jsonData = data.toString();

            URL apiUrl = new URL(url);
            conn = (HttpsURLConnection) apiUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            OutputStream os = conn.getOutputStream();
            os.write(jsonData.getBytes("UTF-8"));
            os.close();

            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            Log.d(TAG, "Resposta do servidor: " + responseCode + " - " + response.toString());

            if (responseCode == 200) {
            // Parse agent_id retornado pelo servidor
            try {
                JSONObject jsonResponse = new JSONObject(response.toString());
                if (jsonResponse.has("agent")) {
                    JSONObject agentObj = jsonResponse.getJSONObject("agent");
                    if (agentObj.has("agent_id")) {
                        String serverAgentId = agentObj.getString("agent_id");
                        Log.d(TAG, "AgentID do servidor: " + serverAgentId + ", local: " + agentID);
                        if (!serverAgentId.equals(agentID)) {
                            Log.d(TAG, "Atualizando agentID para o do servidor: " + serverAgentId);
                            agentID = serverAgentId;
                            // Salvar em agent_prefs.conf
                            saveAgentIdToPrefs(context, agentID);
                        }
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Erro ao parsear agent_id do servidor", e);
            }

                Log.d(TAG, "Agent ativado com sucesso no servidor");
                return true;
            } else {
                Log.w(TAG, "Falha ao ativar agent, status: " + responseCode);
                return false;
            }

        } catch (Exception e) {
            Log.e(TAG, "Erro ao ativar agent", e);
            return false;
        }
    }

    // Enviar log de atividade
    public static void logActivity(String eventType, String target, String details) {
        try {
            // Suprimir logs para domínios da API para evitar poluição
            if (target != null && (target.contains("domcustos.com") || target.contains("domagent"))) {
                return; // Não logar comunicações com a API
            }

            String url = API_BASE_URL + "/agent/log";
            HttpsURLConnection conn = null;

            JSONObject data = new JSONObject();
            data.put("agent_id", agentID);
            data.put("event_type", eventType);
            data.put("target", target);
            data.put("details", details);

            String jsonData = data.toString();

            URL apiUrl = new URL(url);
            conn = (HttpsURLConnection) apiUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            OutputStream os = conn.getOutputStream();
            os.write(jsonData.getBytes("UTF-8"));
            os.close();

            int responseCode = conn.getResponseCode();
            if (responseCode != 200 && responseCode != 201) {
                Log.w(TAG, "Log não enviado, status: " + responseCode);
            }

            conn.disconnect();

        } catch (Exception e) {
            Log.e(TAG, "Erro ao enviar log", e);
        }
    }

    // Cache dinâmico de bloqueios
    private static java.util.Set<String> dynamicBlockedSites = new java.util.HashSet<>();
    private static java.util.Set<String> dynamicBlockedApps = new java.util.HashSet<>();

    // Atualizar cache de bloqueio
    private static void updateBlockCache(Rules rules) {
        try {
            Logger.getLogger().logLine("Regras atualizadas: " + rules.blockedSites.size() + " sites, " + rules.blockedApps.size() + " apps");

            // Limpar caches antigos
            dynamicBlockedSites.clear();
            dynamicBlockedApps.clear();

            // Adicionar sites bloqueados dinamicamente
            for (String site : rules.blockedSites) {
                dynamicBlockedSites.add(site.toLowerCase());
                Logger.getLogger().logLine("Bloqueio dinâmico adicionado: " + site);
            }

            // Para apps, armazenar para possível bloqueio futuro
            for (String app : rules.blockedApps) {
                dynamicBlockedApps.add(app.toLowerCase());
                Logger.getLogger().logLine("Bloqueio app dinâmico: " + app);
            }

        } catch (Exception e) {
            Logger.getLogger().logLine("Erro ao atualizar cache: " + e.getMessage());
        }
    }

    // Verificar se site está bloqueado dinamicamente
    public static boolean isSiteBlocked(String site) {
        return dynamicBlockedSites.contains(site.toLowerCase());
    }

    // Verificar se app está bloqueado dinamicamente
    public static boolean isAppBlocked(String app) {
        return dynamicBlockedApps.contains(app.toLowerCase());
    }

    // Obter agentID
    public static String getAgentID() {
        return agentID;
    }
}