package dnsfilter.android;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.SystemClock;

import dnsfilter.DNSFilterManager;
import util.Logger;

public class UpdateService extends Service {

    private static final String TAG = "UpdateService";
    private static final long UPDATE_INTERVAL = 24 * 60 * 60 * 1000; // 24 horas em ms

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Logger.getLogger().logLine("UpdateService iniciado");

        try {
            // Agendar check periódico se não estiver agendado
            scheduleUpdateCheck();

            // Executar check imediato se solicitado
            if (intent != null && "CHECK_NOW".equals(intent.getAction())) {
                performUpdateCheck();
            }
        } catch (Exception e) {
            Logger.getLogger().logException(e);
        }

        return START_STICKY;
    }

    private void scheduleUpdateCheck() {
        AlarmManager alarmManager = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
        Intent intent = new Intent(this, UpdateService.class);
        intent.setAction("CHECK_NOW");

        PendingIntent pendingIntent = PendingIntent.getService(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0));

        // Agendar para daqui a 24h, repetindo
        long triggerAtMillis = SystemClock.elapsedRealtime() + UPDATE_INTERVAL;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            alarmManager.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAtMillis, pendingIntent);
        } else {
            alarmManager.setExact(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAtMillis, pendingIntent);
        }
    }

    private void performUpdateCheck() {
        try {
            Logger.getLogger().logLine("Executando check de update");
            String updateUrl = DNSFilterManager.getInstance().getConfig().getProperty("updateUrl", "https://files.domcustos.com.br/updates/version.txt");
            UpdateManager updateManager = new UpdateManager(this);
            updateManager.checkForUpdate(updateUrl);
        } catch (Exception e) {
            Logger.getLogger().logException(e);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Logger.getLogger().logLine("UpdateService destruído");
    }
}