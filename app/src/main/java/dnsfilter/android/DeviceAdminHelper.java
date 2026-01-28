package dnsfilter.android;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.UserManager;
import util.Logger;

public class DeviceAdminHelper {
    private DeviceAdminHelper() {}

    public static ComponentName getAdminComponent(Context context) {
        return new ComponentName(context, DomCustosDeviceAdminReceiver.class);
    }

    public static boolean isAdminActive(Context context) {
        DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        return dpm != null && dpm.isAdminActive(getAdminComponent(context));
    }

    public static boolean isDeviceOwner(Context context) {
        DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        return dpm != null && dpm.isDeviceOwnerApp(context.getPackageName());
    }

    public static void requestAdmin(Activity activity) {
        Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
        intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, getAdminComponent(activity));
        intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Necessário para impedir desativação e fortalecer a proteção do DomCustos.");
        activity.startActivity(intent);
    }

    public static void applyOwnerPolicies(Context context) {
        DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (dpm == null) {
            return;
        }
        ComponentName admin = getAdminComponent(context);
        if (!dpm.isDeviceOwnerApp(context.getPackageName())) {
            Logger.getLogger().logLine("Device owner não configurado; políticas avançadas não aplicadas");
            return;
        }
        try {
            dpm.setUninstallBlocked(admin, context.getPackageName(), true);
        } catch (Exception e) {
            Logger.getLogger().logException(e);
        }
        try {
            dpm.addUserRestriction(admin, UserManager.DISALLOW_APPS_CONTROL);
            dpm.addUserRestriction(admin, UserManager.DISALLOW_UNINSTALL_APPS);
        } catch (Exception e) {
            Logger.getLogger().logException(e);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                dpm.setAlwaysOnVpnPackage(admin, context.getPackageName(), true);
            } catch (Exception e) {
                Logger.getLogger().logException(e);
            }
        }
    }
}
