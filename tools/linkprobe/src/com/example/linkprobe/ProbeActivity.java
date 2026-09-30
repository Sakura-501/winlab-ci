package com.example.linkprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

/**
 * Untrusted third-party caller. Requests no permission at all.
 *
 *   am start -n com.example.linkprobe/.ProbeActivity --es mode <m> [extras]
 *
 * mode=explicit|implicit : ACTION_VIEW of --es uri, optionally at --es pkg/--es act
 * mode=send              : ACTION_SEND carrying --es text plus an image attachment
 *                          from this app's own content provider, targeted at
 *                          --es pkg/--es act
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
        String text = in == null ? null : in.getStringExtra("text");

        if (mode == null) mode = "explicit";
        if (pkg == null) pkg = "com.facebook.aura";
        if (act == null) act = "com.facebook.aura.main.AuraDeeplinkHandlerActivity";

        Log.i(TAG, "caller_uid=" + android.os.Process.myUid()
                + " caller_pkg=" + getPackageName() + " mode=" + mode);

        try {
            Intent out;
            if ("send".equals(mode)) {
                out = new Intent(Intent.ACTION_SEND);
                out.setType("image/*");
                if (text != null) out.putExtra(Intent.EXTRA_TEXT, text);
                out.putExtra(Intent.EXTRA_STREAM,
                        Uri.parse("content://com.example.linkprobe.img/shot.png"));
                out.setComponent(new ComponentName(pkg, act));
            } else {
                if (raw == null) {
                    Log.i(TAG, "usage: --es uri <uri> [--es mode explicit|implicit] "
                            + "[--es pkg P --es act A]");
                    finish();
                    return;
                }
                out = new Intent(Intent.ACTION_VIEW, Uri.parse(raw));
                if (!"implicit".equals(mode)) out.setComponent(new ComponentName(pkg, act));
            }
            out.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            out.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(out);
            Log.i(TAG, "startActivity=ok component=" + out.getComponent()
                    + " action=" + out.getAction());
        } catch (Exception e) {
            Log.i(TAG, "startActivity=failed " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        finish();
    }
}
