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
import java.util.Locale;
import android.content.SharedPreferences;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.io.File;
import java.io.FileInputStream;
import javax.net.ssl.HttpsURLConnection;
import android.provider.Settings;
import android.location.Location;
import android.location.LocationManager;
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
    private static boolean initialized = false;

    // Classe para regras
    public static class Rules {
        public List<String> blockedApps = new ArrayList<>();
        public List<String> blockedSites = new ArrayList<>();
    }

    // Salvar agentID em armazenamento interno (mais seguro que externo)
    private static void saveAgentIdToPrefs(android.content.Context context, String agentId) {
        try {
            SharedPreferences prefs = context.getSharedPreferences("domcustos_agent", android.content.Context.MODE_PRIVATE);
            prefs.edit().putString("agent_id", agentId).apply();

            java.io.File agentFile = new java.io.File(context.getFilesDir(), "agent.id");
            java.io.FileWriter writer = new java.io.FileWriter(agentFile, false);
            writer.write(agentId);
            writer.close();

            Log.d(TAG, "AgentID salvo em: " + agentFile.getAbsolutePath());
        } catch (Exception e) {
            Log.e(TAG, "Erro ao salvar agentID em armazenamento interno", e);
        }
    }

    private static String readAgentId(android.content.Context context) {
        try {
            SharedPreferences prefs = context.getSharedPreferences("domcustos_agent", android.content.Context.MODE_PRIVATE);
            String id = prefs.getString("agent_id", null);
            if (id != null && !id.trim().isEmpty()) {
                return id.trim();
            }

            java.io.File agentFile = new java.io.File(context.getFilesDir(), "agent.id");
            if (agentFile.exists()) {
                java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(agentFile));
                id = reader.readLine();
                reader.close();
                if (id != null && !id.trim().isEmpty()) {
                    return id.trim();
                }
            }

            // Migração: tentar arquivo legado em storage externo (uma única vez)
            java.io.File legacyFile = new java.io.File(android.os.Environment.getExternalStorageDirectory(), "DomCustosAgent/agent.id");
            if (legacyFile.exists()) {
                java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(legacyFile));
                id = reader.readLine();
                reader.close();
                if (id != null && !id.trim().isEmpty()) {
                    saveAgentIdToPrefs(context, id.trim());
                    return id.trim();
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro ao ler agentID", e);
        }
        return null;
    }

    // Gerar agentID usando ANDROID_ID diretamente (único por device)
    public static String generateHostID(android.content.Context context) {
        try {
            String androidId = Settings.Secure.getString(
                context.getContentResolver(),
                Settings.Secure.ANDROID_ID);
            Log.d(TAG, "ANDROID_ID obtido: " + androidId);
            if (androidId != null && !androidId.isEmpty() && !androidId.equals("9774d56d682e549c")) { // Evitar ID genérico
                // Usar primeiros 16 chars do ANDROID_ID
                String id = androidId.length() > 16 ? androidId.substring(0, 16) : androidId;
                Log.d(TAG, "AgentID gerado do ANDROID_ID: " + id);
                return id;
            } else {
                Log.w(TAG, "ANDROID_ID inválido, usando UUID");
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro ao obter ANDROID_ID", e);
        }
        // Fallback
        String uuid = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        Log.d(TAG, "AgentID gerado UUID: " + uuid);
        return uuid;
    }

    // Inicializar API e agendamento
    public static void initialize(android.content.Context context) {
        try {
            if (initialized) {
                return;
            }
            initialized = true;

            agentID = readAgentId(context);
            if (agentID == null || agentID.trim().isEmpty()) {
                Log.w(TAG, "AgentID não encontrado, usando default_agent temporário");
                agentID = "default_agent";
            } else {
                Log.d(TAG, "AgentID carregado: " + agentID);
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

            // Agendar heartbeat a cada 90 segundos
            scheduler.scheduleAtFixedRate(() -> {
                try {
                    sendHeartbeat(context);
                } catch (Exception e) {
                    Log.e(TAG, "Erro ao enviar heartbeat", e);
                }
            }, 0, 90, TimeUnit.SECONDS);

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
                String loaded = readAgentId(context);
                if (loaded != null && !loaded.trim().isEmpty()) {
                    agentID = loaded.trim();
                }
            }
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
            data.put("version", BuildConfig.VERSION_NAME);
            Log.d(TAG, "Enviando activate com agentID: " + agentID + ", os_type: android");

            String jsonData = data.toString();
            Log.d(TAG, "Enviando JSON: " + jsonData);

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

            Log.d(TAG, "Resposta do servidor activate: " + responseCode + " - " + response.toString());

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

            // Capturar estado atual para detectar mudanças relevantes
            java.util.Set<String> oldBlockedApps = new java.util.HashSet<>(dynamicBlockedApps);
            java.util.Set<String> oldBlockedSites = new java.util.HashSet<>(dynamicBlockedSites);

            // Limpar caches antigos
            dynamicBlockedSites.clear();
            dynamicBlockedApps.clear();

            // Adicionar sites bloqueados dinamicamente
            for (String site : rules.blockedSites) {
                if (site == null) {
                    continue;
                }
                String normalized = site.trim().toLowerCase(Locale.ROOT);
                if (normalized.startsWith("http://")) {
                    normalized = normalized.substring(7);
                } else if (normalized.startsWith("https://")) {
                    normalized = normalized.substring(8);
                }
                while (normalized.startsWith(".")) {
                    normalized = normalized.substring(1);
                }
                while (normalized.endsWith(".")) {
                    normalized = normalized.substring(0, normalized.length() - 1);
                }
                if (!normalized.isEmpty()) {
                    dynamicBlockedSites.add(normalized);
                    Logger.getLogger().logLine("Bloqueio dinâmico adicionado: " + normalized);
                }
            }

            // Para apps, armazenar para possível bloqueio futuro
            for (String app : rules.blockedApps) {
                if (app == null) {
                    continue;
                }
                String normalized = app.trim().toLowerCase(Locale.ROOT);
                if (!normalized.isEmpty()) {
                    dynamicBlockedApps.add(normalized);
                    Logger.getLogger().logLine("Bloqueio app dinâmico: " + normalized);
                }
            }

            if (!oldBlockedApps.equals(dynamicBlockedApps) || !oldBlockedSites.equals(dynamicBlockedSites)) {
                try {
                    DNSFilterService.onReload();
                } catch (Exception e) {
                    Logger.getLogger().logLine("Erro ao aplicar novas regras no VPN: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            Logger.getLogger().logLine("Erro ao atualizar cache: " + e.getMessage());
        }
    }

    // Verificar se site está bloqueado dinamicamente
    public static boolean isSiteBlocked(String site) {
        if (site == null) {
            return false;
        }
        String host = site.trim().toLowerCase(Locale.ROOT);
        if (host.isEmpty()) {
            return false;
        }
        if (dynamicBlockedSites.contains(host)) {
            return true;
        }
        int idx = host.indexOf('.');
        while (idx != -1) {
            String suffix = host.substring(idx + 1);
            if (dynamicBlockedSites.contains(suffix)) {
                return true;
            }
            idx = host.indexOf('.', idx + 1);
        }
        return false;
    }

    // Verificar se app está bloqueado dinamicamente
    public static boolean isAppBlocked(String app) {
        if (app == null) {
            return false;
        }
        return dynamicBlockedApps.contains(app.trim().toLowerCase(Locale.ROOT));
    }

    public static java.util.List<String> getBlockedApps() {
        return new java.util.ArrayList<>(dynamicBlockedApps);
    }

    // Obter localização atual
    private static Location getCurrentLocation(android.content.Context context) {
        try {
            LocationManager locationManager = (LocationManager) context.getSystemService(android.content.Context.LOCATION_SERVICE);
            if (locationManager != null) {
                // Tentar GPS primeiro
                Location location = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER);
                if (location == null) {
                    // Fallback para network
                    location = locationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                }
                return location;
            }
        } catch (SecurityException e) {
            Log.w(TAG, "Permissão de localização não concedida", e);
        } catch (Exception e) {
            Log.e(TAG, "Erro ao obter localização", e);
        }
        return null;
    }

    // Enviar heartbeat para o servidor
    private static void sendHeartbeat(android.content.Context context) {
        try {
            String url = API_BASE_URL + "/agent/heartbeat/" + agentID;
            HttpsURLConnection conn = null;

            JSONObject data = new JSONObject();
            data.put("version", BuildConfig.VERSION_NAME); // Versão do app
            data.put("os", "android");

            // Tentar obter hostname e IP local
            try {
                data.put("hostname", java.net.InetAddress.getLocalHost().getHostName());
                data.put("last_local_ip", java.net.InetAddress.getLocalHost().getHostAddress());
            } catch (Exception e) {
                data.put("hostname", "unknown");
                data.put("last_local_ip", "unknown");
            }

            // Obter localização
            try {
                Location location = getCurrentLocation(context);
                if (location != null) {
                    data.put("latitude", location.getLatitude());
                    data.put("longitude", location.getLongitude());
                    Log.d(TAG, "Localização incluída no heartbeat: " + location.getLatitude() + ", " + location.getLongitude());
                } else {
                    data.put("latitude", JSONObject.NULL);
                    data.put("longitude", JSONObject.NULL);
                    Log.d(TAG, "Localização não disponível para heartbeat");
                }
            } catch (Exception e) {
                Log.e(TAG, "Erro ao adicionar localização no heartbeat", e);
                data.put("latitude", JSONObject.NULL);
                data.put("longitude", JSONObject.NULL);
            }

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
            if (responseCode != 200) {
                Log.w(TAG, "Heartbeat falhou, status: " + responseCode);
            } else {
                Log.d(TAG, "Heartbeat enviado com sucesso");
            }

            conn.disconnect();

        } catch (Exception e) {
            Log.e(TAG, "Erro ao enviar heartbeat", e);
        }
    }

    // Obter agentID
    public static String getAgentID() {
        return agentID;
    }
}
