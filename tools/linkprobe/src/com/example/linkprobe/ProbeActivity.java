package com.example.linkprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

/**
 * Untrusted third-party caller. Takes a URI on its own command line and hands it
 * to another app, either through an explicit component or as a plain implicit VIEW.
 *
 *   am start -n com.example.linkprobe/.ProbeActivity --es uri <uri> [--es mode implicit]
 *   extras: uri (required), mode = "explicit" (default) | "implicit",
 *           pkg, act  (target component for explicit mode)
 */
public class ProbeActivity extends Activity {

    private static final String TAG = "LinkProbe";

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        Intent in = getIntent();
        String raw = in == null ? null : in.getStringExtra("uri");
        String mode = in == null ? null : in.getStringExtra("mode");
        String pkg = in == null ? null : in.getStringExtra("pkg");
        String act = in == null ? null : in.getStringExtra("act");

        if (raw == null) {
            Log.i(TAG, "usage: --es uri <uri> [--es mode implicit|explicit] [--es pkg P] [--es act A]");
            finish();
            return;
        }
        if (pkg == null) pkg = "com.facebook.aura";
        if (act == null) act = "com.facebook.aura.main.AuraDeeplinkHandlerActivity";

        Intent out = new Intent(Intent.ACTION_VIEW, Uri.parse(raw));
        out.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (!"implicit".equals(mode)) {
            out.setComponent(new ComponentName(pkg, act));
        }

        Log.i(TAG, "caller_uid=" + android.os.Process.myUid()
                + " caller_pkg=" + getPackageName()
                + " mode=" + (mode == null ? "explicit" : mode)
                + " uri=" + raw);
        try {
            startActivity(out);
            Log.i(TAG, "startActivity=ok component=" + out.getComponent());
        } catch (Exception e) {
            Log.i(TAG, "startActivity=failed " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        finish();
    }
}
