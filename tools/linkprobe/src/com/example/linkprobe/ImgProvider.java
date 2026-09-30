package com.example.linkprobe;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import java.io.FileNotFoundException;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Base64;
import java.util.Locale;

/**
 * Serves files from this app's own private directory so the probe can hand the target app a
 * readable content:// attachment URI while requesting no storage permission at all.
 *
 *   content://com.example.linkprobe.img/<name>      -> filesDir/<name>
 *   content://com.example.linkprobe.img/shot.png    -> synthesised 1x1 PNG (default)
 *
 * Corpus files are placed into filesDir with `adb shell run-as com.example.linkprobe ...`.
 */
public class ImgProvider extends ContentProvider {

    private static final String PNG_B64 =
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC";

    /** Resolve the requested name inside filesDir only; never escape it. */
    private File resolve(Uri uri) {
        File root = getContext().getFilesDir().getAbsoluteFile();
        String last = uri == null ? null : uri.getLastPathSegment();
        if (last == null || last.isEmpty()) return null;
        if (last.contains("/") || last.contains("..")) return null;
        File f = new File(root, last).getAbsoluteFile();
        if (!f.getPath().startsWith(root.getPath() + File.separator)) return null;
        return f.exists() ? f : null;
    }

    private File defaultPng() {
        File f = new File(getContext().getFilesDir(), "shot.png");
        if (!f.exists()) {
            try (FileOutputStream os = new FileOutputStream(f)) {
                os.write(Base64.getDecoder().decode(PNG_B64));
            } catch (Exception e) {
                return null;
            }
        }
        return f;
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File f = resolve(uri);
        if (f == null) f = defaultPng();
        if (f == null) throw new FileNotFoundException("no such probe attachment");
        // Proves whether the target app actually consumed the attachment bytes, so that
        // "no crash across the corpus" is a reading rather than a vacuous zero.
        android.util.Log.i("LinkProbe", "OPENFILE name=" + f.getName() + " bytes=" + f.length()
                + " mode=" + mode + " callingPackage=" + getCallingPackage()
                + " callingUid=" + android.os.Binder.getCallingUid());
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri u, String[] p, String s, String[] sa, String so) { return null; }

    @Override
    public String getType(Uri u) {
        String n = u == null ? "" : u.getLastPathSegment();
        android.util.Log.i("LinkProbe", "GETTYPE uri=" + u + " callingPackage=" + getCallingPackage()
                + " callingUid=" + android.os.Binder.getCallingUid());
        if (n == null) return "application/octet-stream";
        String e = n.contains(".") ? n.substring(n.lastIndexOf('.') + 1).toLowerCase(Locale.US) : "";
        switch (e) {
            case "jpg": case "jpeg": return "image/jpeg";
            case "png":              return "image/png";
            case "gif":              return "image/gif";
            case "bmp":              return "image/bmp";
            case "webp":             return "image/webp";
            case "tif": case "tiff": return "image/tiff";
            default:                 return "application/octet-stream";
        }
    }

    @Override
    public Uri insert(Uri u, ContentValues cv) { return null; }

    @Override
    public int delete(Uri u, String s, String[] sa) { return 0; }

    @Override
    public int update(Uri u, ContentValues cv, String s, String[] sa) { return 0; }
}
