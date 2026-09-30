package com.example.linkprobe;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Base64;

/**
 * Serves a tiny real PNG so the probe can hand the target app a readable
 * content:// attachment URI without needing any storage permission.
 */
public class ImgProvider extends ContentProvider {

    private static final String AUTH = "com.example.linkprobe.img";
    // 1x1 opaque PNG
    private static final String PNG_B64 =
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC";

    private File png() {
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
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        File f = png();
        if (f == null) return null;
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri u, String[] p, String s, String[] sa, String so) { return null; }

    @Override
    public String getType(Uri u) { return "image/png"; }

    @Override
    public Uri insert(Uri u, ContentValues cv) { return null; }

    @Override
    public int delete(Uri u, String s, String[] sa) { return 0; }

    @Override
    public int update(Uri u, ContentValues cv, String s, String[] sa) { return 0; }
}
