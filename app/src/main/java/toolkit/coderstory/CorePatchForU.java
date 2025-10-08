package toolkit.coderstory;

import android.util.Log;

import java.lang.reflect.InvocationTargetException;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class CorePatchForU extends CorePatchForT {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws IllegalAccessException, InvocationTargetException, InstantiationException {
        super.handleLoadPackage(loadPackageParam);
        var utilClass = findClass("com.android.server.pm.ReconcilePackageUtils", loadPackageParam.classLoader);
        if (utilClass != null) {
            try {
                deoptimizeMethod(utilClass, "reconcilePackages");
            } catch (Throwable e) {
                XposedBridge.log("E/" + MainHook.TAG + " deoptimizing failed" + Log.getStackTraceString(e));
            }
        }

        // https://cs.android.com/android/platform/superproject/+/android-14.0.0_r60:frameworks/base/services/core/java/com/android/server/pm/ReconcilePackageUtils.java;l=61;bpv=1;bpt=0
        setStaticBooleanField(utilClass, "ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS", true);

        // ee11a9c (Rename AndroidPackageApi to AndroidPackage)
        findAndHookMethod("com.android.server.pm.PackageManagerServiceUtils", loadPackageParam.classLoader,
                "checkDowngrade",
                "com.android.server.pm.pkg.AndroidPackage",
                "android.content.pm.PackageInfoLite",
                new ReturnConstant(null));
        findAndHookMethod("com.android.server.pm.ScanPackageUtils", loadPackageParam.classLoader,
                "assertMinSignatureSchemeIsValid",
                "com.android.server.pm.pkg.AndroidPackage", int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        param.setResult(null);
                    }
                });

        var ntService = XposedHelpers.findClassIfExists("com.nothing.server.ex.NtConfigListServiceImpl",
                loadPackageParam.classLoader);
        if (ntService != null) {
            findAndHookMethod(ntService, "isInstallingAppForbidden", java.lang.String.class,
                    new ReturnConstant(false));

            findAndHookMethod(ntService, "isStartingAppForbidden", java.lang.String.class,
                    new ReturnConstant(false));
        }
    }

    @Override
    Class<?> getParsedPackage(ClassLoader classLoader) {
        var clazz = XposedHelpers.findClassIfExists("com.android.internal.pm.parsing.pkg.ParsedPackage", classLoader);
        return clazz != null ? clazz : XposedHelpers.findClassIfExists("com.android.server.pm.parsing.pkg.ParsedPackage", classLoader);
    }

    @Override
    Class<?> getIsVerificationEnabledClass(ClassLoader classLoader) {
        return XposedHelpers.findClass("com.android.server.pm.VerifyingSession", classLoader);
    }
}
