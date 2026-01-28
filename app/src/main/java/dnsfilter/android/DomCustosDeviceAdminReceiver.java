package dnsfilter.android;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;
import util.Logger;

public class DomCustosDeviceAdminReceiver extends DeviceAdminReceiver {
    @Override
    public void onEnabled(Context context, Intent intent) {
        Logger.getLogger().logLine("Device Admin habilitado");
    }

    @Override
    public void onDisabled(Context context, Intent intent) {
        Logger.getLogger().logLine("Device Admin desabilitado");
    }
}
