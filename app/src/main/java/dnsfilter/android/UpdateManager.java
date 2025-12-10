package dnsfilter.android;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import util.Logger;

public class UpdateManager {

    private static final String TAG = "UpdateManager";
    private Context context;

    public UpdateManager(Context context) {
        this.context = context;
    }

    public boolean checkForUpdate(String updateUrl) {
        try {
            URL url = new URL(updateUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                InputStream inputStream = connection.getInputStream();
                String jsonResponse = readStream(inputStream);
                inputStream.close();

                JSONObject json = new JSONObject(jsonResponse);
                String latestVersion = json.getString("version");
                String apkUrl = json.getString("apk_url");
                String checksum = json.getString("checksum");

                String currentVersion = getCurrentVersion();
                if (isNewerVersion(latestVersion, currentVersion)) {
                    Logger.getLogger().logLine("Nova versão disponível: " + latestVersion);
                    return downloadAndInstall(apkUrl, checksum);
                } else {
                    Logger.getLogger().logLine("Versão atual é a mais recente: " + currentVersion);
                }
            } else {
                Logger.getLogger().logLine("Erro ao verificar update: HTTP " + responseCode);
            }
        } catch (Exception e) {
            Logger.getLogger().logException(e);
        }
        return false;
    }

    private String getCurrentVersion() {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return packageInfo.versionName;
        } catch (PackageManager.NameNotFoundException e) {
            Logger.getLogger().logException(e);
            return "0.0.0";
        }
    }

    private boolean isNewerVersion(String latest, String current) {
        // Comparação simples de versões (assumindo formato x.y.z)
        String[] latestParts = latest.split("\\.");
        String[] currentParts = current.split("\\.");

        for (int i = 0; i < Math.min(latestParts.length, currentParts.length); i++) {
            int latestNum = Integer.parseInt(latestParts[i]);
            int currentNum = Integer.parseInt(currentParts[i]);
            if (latestNum > currentNum) return true;
            if (latestNum < currentNum) return false;
        }
        return latestParts.length > currentParts.length;
    }

    private boolean downloadAndInstall(String apkUrl, String expectedChecksum) {
        try {
            File apkFile = new File(context.getCacheDir(), "update.apk");
            downloadFile(apkUrl, apkFile);

            if (verifyChecksum(apkFile, expectedChecksum)) {
                Logger.getLogger().logLine("Checksum verificado. Instalando APK...");
                installApk(apkFile);
                return true;
            } else {
                Logger.getLogger().logLine("Checksum inválido. Abortando instalação.");
                apkFile.delete();
            }
        } catch (Exception e) {
            Logger.getLogger().logException(e);
        }
        return false;
    }

    private void downloadFile(String url, File file) throws IOException {
        URL downloadUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) downloadUrl.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(30000);
        connection.setReadTimeout(30000);

        try (InputStream input = connection.getInputStream();
             FileOutputStream output = new FileOutputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }
    }

    private boolean verifyChecksum(File file, String expectedChecksum) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (FileInputStream fis = new FileInputStream(file);
                 BufferedInputStream bis = new BufferedInputStream(fis)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = bis.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }
            String calculatedChecksum = bytesToHex(digest.digest());
            return calculatedChecksum.equalsIgnoreCase(expectedChecksum);
        } catch (NoSuchAlgorithmException | IOException e) {
            Logger.getLogger().logException(e);
            return false;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void installApk(File apkFile) {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        Uri apkUri = Uri.fromFile(apkFile);
        intent.setDataAndType(apkUri, "application/vnd.android.package-archive");
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }

    private String readStream(InputStream inputStream) throws IOException {
        StringBuilder sb = new StringBuilder();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = inputStream.read(buffer)) != -1) {
            sb.append(new String(buffer, 0, length));
        }
        return sb.toString();
    }
}