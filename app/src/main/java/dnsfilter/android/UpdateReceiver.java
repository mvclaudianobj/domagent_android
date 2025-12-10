package dnsfilter.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import util.Logger;

public class UpdateReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_PACKAGE_REPLACED.equals(intent.getAction())) {
            String packageName = intent.getData().getSchemeSpecificPart();
            if (packageName.equals(context.getPackageName())) {
                Logger.getLogger().logLine("App atualizado. Reiniciando serviços...");

                // Reiniciar DNSFilterService
                Intent serviceIntent = new Intent(context, DNSFilterService.class);
                context.startService(serviceIntent);

                // Relançar activity principal
                Intent activityIntent = new Intent(context, DNSProxyActivity.class);
                activityIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(activityIntent);
            }
        }
    }
}