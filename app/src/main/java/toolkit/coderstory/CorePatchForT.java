package toolkit.coderstory;

import android.content.pm.Signature;

import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class CorePatchForT extends CorePatchForS implements IXposedHookZygoteInit {
    private static final String TAG = "CorePatchForT";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws IllegalAccessException, InvocationTargetException, InstantiationException {
        super.handleLoadPackage(loadPackageParam);
        var checkDowngrade = XposedHelpers.findMethodExactIfExists("com.android.server.pm.PackageManagerServiceUtils", loadPackageParam.classLoader,
                "checkDowngrade",
                "com.android.server.pm.parsing.pkg.AndroidPackage",
                "android.content.pm.PackageInfoLite");
        if (checkDowngrade != null) {
            XposedBridge.hookMethod(checkDowngrade, new ReturnConstant(prefs, "downgrade", null));
        }

        Class<?> signingDetails = getSigningDetails(loadPackageParam.classLoader);
        //New package has a different signature
        //处理覆盖安装但签名不一致
        hookAllMethods(signingDetails, "checkCapability", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                // Don't handle PERMISSION & AUTH
                // Or applications will have all privileged permissions
                // https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/android/content/pm/PackageParser.java;l=5947?q=CertCapabilities
                // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/accounts/AccountManagerService.java;l=5867
                if (prefs.getBoolean("digestCreak", true)) {
                    if ((Integer) param.args[1] != 4 && (Integer) param.args[1] != 16) {
                        param.setResult(true);
                    }
                }
            }
        });

        Class<?> ParsedPackage = getParsedPackage(loadPackageParam.classLoader);
        findAndHookMethod("com.android.server.pm.InstallPackageHelper", loadPackageParam.classLoader,
                "doesSignatureMatchForPermissions", String.class,
                ParsedPackage, int.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (prefs.getBoolean("digestCreak", true) && prefs.getBoolean("UsePreSig", false)) {
                            //If we decide to crack this then at least make sure they are same apks, avoid another one that tries to impersonate.
                            if (param.getResult().equals(false)) {
                                String pPname = (String) XposedHelpers.callMethod(param.args[1], "getPackageName");
                                if (pPname.contentEquals((String) param.args[0])) {
                                    param.setResult(true);
                                }
                            }
                        }
                    }
                });

        var assertMinSignatureSchemeIsValid = XposedHelpers.findMethodExactIfExists("com.android.server.pm.ScanPackageUtils", loadPackageParam.classLoader,
                "assertMinSignatureSchemeIsValid",
                "com.android.server.pm.parsing.pkg.AndroidPackage", int.class);
        if (assertMinSignatureSchemeIsValid != null) {
            XposedBridge.hookMethod(assertMinSignatureSchemeIsValid, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (prefs.getBoolean("authcreak", false)) {
                        param.setResult(null);
                    }
                }
            });
        }

        Class<?> strictJarVerifier = findClass("android.util.jar.StrictJarVerifier", loadPackageParam.classLoader);
        if (strictJarVerifier != null) {
            XposedBridge.hookAllConstructors(strictJarVerifier, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (prefs.getBoolean("authcreak", false)) {
                        XposedHelpers.setBooleanField(param.thisObject, "signatureSchemeRollbackProtectionsEnforced", false);
                    }
                }
            });
        }

        // ensure verifySignatures success
        // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/pm/PackageManagerServiceUtils.java;l=621;drc=2e50991320cbef77d3e8504a4b284adae8c2f4d2
        var utils = XposedHelpers.findClassIfExists("com.android.server.pm.PackageManagerServiceUtils", loadPackageParam.classLoader);
        if (utils != null) {
            deoptimizeMethod(utils, "canJoinSharedUserId");
        }
    }

    Class<?> getParsedPackage(ClassLoader classLoader) {
        return XposedHelpers.findClassIfExists("com.android.server.pm.parsing.pkg.ParsedPackage", classLoader);
    }

    Class<?> getSigningDetails(ClassLoader classLoader) {
        return XposedHelpers.findClassIfExists("android.content.pm.SigningDetails", classLoader);
    }

    @Override
    protected void dumpSigningDetails(Object signingDetails, PrintWriter pw) {
        var i = 0;
        for (var sign : (Signature[]) XposedHelpers.callMethod(signingDetails, "getSignatures")) {
            i++;
            pw.println(i + ": " + sign.toCharsString());
        }
    }

    @Override
    protected Object SharedUserSetting_packages(Object sharedUser) {
        return XposedHelpers.getObjectField(sharedUser, "mPackages");
    }

    @Override
    protected Object SigningDetails_mergeLineageWith(Object self, Object other) {
        return XposedHelpers.callMethod(self, "mergeLineageWith", other, 2 /*MERGE_RESTRICTED_CAPABILITY*/);
    }

    @Override
    Class<?> getIsVerificationEnabledClass(ClassLoader classLoader) {
        return XposedHelpers.findClass("com.android.server.pm.VerificationParams", classLoader);
    }

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        XposedBridge.log(TAG + ": Initializing in Zygote");

        try {
            Class<?> appOpsServiceClass = XposedHelpers.findClass(
                    "com.android.server.appop.AppOpsService",
                    null
            );

            Class<?> verificationResultClass = XposedHelpers.findClass(
                    "com.android.server.appop.AppOpsService$PackageVerificationResult",
                    null
            );

            Class<?> restrictionBypassClass = XposedHelpers.findClass(
                    "android.app.AppOpsManager.RestrictionBypass",
                    null
            );

            Class<?> utilsClass = XposedHelpers.findClass(
                    "com.android.server.pm.PackageManagerServiceUtils",
                    null
            );

            Class<?> permissionManagerServiceImplClass = XposedHelpers.findClass(
                    "com.android.server.pm.permission.PermissionManagerServiceImpl",
                    null
            );

            XposedBridge.log(TAG + ": Found all required classes in Zygote");

            XposedHelpers.findAndHookMethod(permissionManagerServiceImplClass, "checkPrivilegedPermissionAllowlist",
                    "com.android.server.pm.parsing.pkg.AndroidPackage", "com.android.server.pm.pkg.PackageStateInternal", "com.android.server.pm.permission.Permission",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            param.setResult(true);
                        }
                    });


            XposedHelpers.findAndHookMethod(utilsClass, "canJoinSharedUserId",
                    "android.content.pm.SigningDetails", "android.content.pm.SigningDetails",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            param.setResult(true);
                        }
                    });

            XposedHelpers.findAndHookMethod(appOpsServiceClass, "verifyAndGetBypass",
                    int.class, String.class, String.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            // Всегда возвращаем new PackageVerificationResult(null, true)
                            Object bypassResult = createPackageVerificationResult(
                                    verificationResultClass, restrictionBypassClass);
                            param.setResult(bypassResult);

                            String packageName = (String) param.args[1];
                            XposedBridge.log(TAG + ": Forced PackageVerificationResult(null, true) for: " + packageName);
                        }
                    });
            XposedBridge.log(TAG + ": Successfully hooked verifyAndGetBypass in Zygote");
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": Error hooking in Zygote: " + e.getMessage());
        }
    }

    private Object createPackageVerificationResult(Class<?> verificationResultClass,
                                                   Class<?> restrictionBypassClass) {
        try {
            Constructor<?> constructor = verificationResultClass.getDeclaredConstructor(
                    restrictionBypassClass,
                    boolean.class
            );

            constructor.setAccessible(true);
            Object result = constructor.newInstance(null, true);

            XposedBridge.log(TAG + ": Successfully created PackageVerificationResult(null, true)");
            return result;

        } catch (Exception e) {
            XposedBridge.log(TAG + ": Error creating PackageVerificationResult: " + e.getMessage());
            return tryAlternativeCreation(verificationResultClass, restrictionBypassClass);
        }
    }

    private Object tryAlternativeCreation(Class<?> verificationResultClass,
                                          Class<?> restrictionBypassClass) {
        try {
            Constructor<?>[] constructors = verificationResultClass.getDeclaredConstructors();

            for (Constructor<?> constructor : constructors) {
                try {
                    constructor.setAccessible(true);
                    Class<?>[] paramTypes = constructor.getParameterTypes();
                    Object[] params = new Object[paramTypes.length];

                    for (int i = 0; i < paramTypes.length; i++) {
                        if (paramTypes[i] == boolean.class) {
                            params[i] = true;
                        } else if (paramTypes[i] == restrictionBypassClass) {
                            params[i] = null;
                        } else {
                            params[i] = null;
                        }
                    }

                    Object result = constructor.newInstance(params);
                    XposedBridge.log(TAG + ": Created with alternative constructor: " + constructor);
                    return result;

                } catch (Exception e) {
                    continue;
                }
            }

            throw new RuntimeException("No working constructor found");

        } catch (Exception e) {
            XposedBridge.log(TAG + ": All creation attempts failed: " + e.getMessage());
            return null;
        }
    }
}
