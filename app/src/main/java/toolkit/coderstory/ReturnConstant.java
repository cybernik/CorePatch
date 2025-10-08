package toolkit.coderstory;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;

public class ReturnConstant extends XC_MethodHook {
    private final Object value;

    public ReturnConstant(Object value) {
        this.value = value;
    }

    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        param.setResult(value);
    }
}
