package com.example.linkprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

/**
 * Untrusted third-party caller (no <uses-permission> at all). Drives each of the three
 * independent Muse entry points from one binary and self-reports whether the dispatch worked,
 * so a missing read is never mistaken for a denied request.
 *
 *   am start -n com.example.linkprobe/.ProbeActivity --es mode <view|assist|assistapp|send|sendfile|processtext> [options]
 *
 * options: --es uri <uri> --es text <t> --es type <mime> --es pkg <p> --es act <fqcn>
 *          --es token <ASSIST_INVOCATION_TOKEN value>
 */
public class ProbeActivity extends Activity {

    private static final String TAG = "LinkProbe";
    private static final String AURA = "com.facebook.aura";
    private static final String DEEPLINK_ACTIVITY = "com.facebook.aura.main.AuraDeeplinkHandlerActivity";
    private static final String MAIN_ACTIVITY = "com.facebook.aura.main.AuraMainActivity";
    private static final String SHARE_ACTIVITY = "com.facebook.aura.share.AuraShareIntentHandlerActivity";
    private static final String EXTRA_ASSIST_QUERY = "com.facebook.aura.extra.ASSIST_QUERY";
    private static final String EXTRA_ASSIST_TOKEN = "com.facebook.aura.extra.ASSIST_INVOCATION_TOKEN";
    private static final String EXTRA_PROCESS_TEXT = "android.intent.extra.PROCESS_TEXT";

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        Intent in = getIntent();
        String mode = s(in, "mode", "view");
        String uri = s(in, "uri", null);
        String text = s(in, "text", null);
        String type = s(in, "type", null);
        String pkg = s(in, "pkg", AURA);
        String act = s(in, "act", null);
        String token = s(in, "token", null);

        Intent out = new Intent();
        out.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        String label;

        switch (mode) {
            case "assist":
                out.setAction(Intent.ACTION_ASSIST);
                out.setPackage(pkg);
                if (text != null) out.putExtra(EXTRA_ASSIST_QUERY, text);
                if (token != null) out.putExtra(EXTRA_ASSIST_TOKEN, token);
                label = "ACTION_ASSIST (exported on " + MAIN_ACTIVITY + ")";
                break;
            case "assistapp":
                out.setAction("com.facebook.aura.action.ASSIST");
                out.setPackage(pkg);
                if (text != null) out.putExtra(EXTRA_ASSIST_QUERY, text);
                if (token != null) out.putExtra(EXTRA_ASSIST_TOKEN, token);
                label = "com.facebook.aura.action.ASSIST";
                break;
            case "send":
            case "sendfile":
                out.setAction(Intent.ACTION_SEND);
                out.setClassName(pkg, act == null ? SHARE_ACTIVITY : act);
                out.setType(type == null ? ("sendfile".equals(mode) ? "application/octet-stream" : "image/png"));
                if (uri != null) {
                    out.putExtra(Intent.EXTRA_STREAM, Uri.parse(uri));
                    out.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                }
                if (text != null) out.putExtra(Intent.EXTRA_TEXT, text);
                label = "ACTION_SEND -> " + (act == null ? SHARE_ACTIVITY : act);
                break;
            case "processtext":
                out.setAction("android.intent.action.PROCESS_TEXT");
                out.setPackage(pkg);
                if (text != null) out.putExtra(EXTRA_PROCESS_TEXT, text);
                label = "ACTION_PROCESS_TEXT";
                break;
            case "implicit":
                out.setAction(Intent.ACTION_VIEW);
                out.setData(Uri.parse(uri));
                label = "implicit ACTION_VIEW";
                break;
            case "view":
            default:
                out.setAction(Intent.ACTION_VIEW);
                out.setData(Uri.parse(uri));
                out.setClassName(pkg, act == null ? DEEPLINK_ACTIVITY : act);
                label = "ACTION_VIEW -> " + out.getComponent();
                break;
        }

        Log.i(TAG, "PROBE mode=" + mode + " caller_uid=" + android.os.Process.myUid()
                + " caller_pkg=" + getPackageName() + " via=" + label
                + " text=" + text + " uri=" + uri);
        try {
            startActivity(out);
            Log.i(TAG, "DISPATCH_OK mode=" + mode + " component=" + out.getComponent()
                    + " action=" + out.getAction());
        } catch (Exception e) {
            Log.i(TAG, "DISPATCH_FAIL mode=" + mode + " " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        }
        finish();
    }

    private static String s(Intent i, String k, String dflt) {
        String v = i == null ? null : i.getStringExtra(k);
        return v == null ? dflt : v;
    }
}
