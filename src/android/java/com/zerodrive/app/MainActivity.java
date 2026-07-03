package com.zerodrive.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DecimalFormat;

public class MainActivity extends Activity {
    static {
        System.loadLibrary("zerodrive");
    }

    private static native void nativeInit();
    private static native String nativeStartDaemon(String mnemonic);
    private static native String nativeListDrives();
    private static native String nativeListFiles(String drive);
    private static native boolean nativeCreateDrive(String name);
    private static native boolean nativeDeleteDrive(String name);
    private static native boolean nativeDeleteFile(String drive, String file);
    private static native String nativeUploadFile(String drive, String filePath);
    private static native String nativeDownloadFile(String drive, String fileName, String destPath);

    private static final int FILE_PICK_REQUEST = 100;
    private static final long MAX_UPLOAD_SIZE = 500 * 1024 * 1024;

    private LinearLayout root;
    private View setupView, loadingView, mainView, filesView;
    private TextView statusText, loadingText;
    private LinearLayout drivesList, filesList;
    private TextView filesTitle;
    private String currentDrive;
    private String pendingUploadDrive;
    private File tempDir;
    private Handler uiHandler;
    private Button setupBtn;
    private EditText mnemonicInput;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
            getWindow().setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            );
        }
        nativeInit();
        uiHandler = new Handler(Looper.getMainLooper());
        tempDir = new File(getFilesDir(), "temp");
        tempDir.mkdirs();
        cleanupTempFiles();
        buildUI();
    }

    private void cleanupTempFiles() {
        File[] files = tempDir.listFiles();
        if (files != null) {
            for (File f : files) {
                f.delete();
            }
        }
    }

    // ── UI BUILDING ──

    private void buildUI() {
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0D1117);

        setupView = buildSetupView();
        loadingView = buildLoadingView();
        mainView = buildMainView();
        filesView = buildFilesView();

        root.addView(setupView);
        root.addView(loadingView);
        root.addView(mainView);
        root.addView(filesView);
        setContentView(root);

        showOnly(setupView);
    }

    private View buildSetupView() {
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 64, 32, 32);
        ll.setGravity(Gravity.CENTER);

        TextView title = new TextView(this);
        title.setText("ZeroDrive");
        title.setTextSize(28);
        title.setTextColor(0xFF58A6FF);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 16);
        ll.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Enter your 24-word BIP-39 mnemonic");
        subtitle.setTextSize(14);
        subtitle.setTextColor(0xFF8B949E);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, 0, 0, 24);
        ll.addView(subtitle);

        mnemonicInput = new EditText(this);
        mnemonicInput.setHint("Paste your seed phrase...");
        mnemonicInput.setTextColor(0xFFE6EDF3);
        mnemonicInput.setHintTextColor(0xFF484F58);
        mnemonicInput.setBackgroundColor(0xFF161B22);
        mnemonicInput.setPadding(16, 16, 16, 16);
        mnemonicInput.setMinLines(3);
        mnemonicInput.setSingleLine(false);
        ll.addView(mnemonicInput);

        setupBtn = new Button(this);
        setupBtn.setText("Unlock");
        setupBtn.setBackgroundColor(0xFF238636);
        setupBtn.setTextColor(0xFFFFFFFF);
        setupBtn.setTextSize(16);
        setupBtn.setPadding(0, 14, 0, 14);
        setupBtn.setOnClickListener(v -> doSetup());
        ll.addView(setupBtn);

        TextView hint = new TextView(this);
        hint.setText("The daemon will start in the background. This may take a moment.");
        hint.setTextSize(12);
        hint.setTextColor(0xFF484F58);
        hint.setGravity(Gravity.CENTER);
        hint.setPadding(0, 16, 0, 0);
        ll.addView(hint);

        return ll;
    }

    private void doSetup() {
        String mnemonic = mnemonicInput.getText().toString().trim();
        if (mnemonic.isEmpty()) { toast("Enter your seed phrase"); return; }
        mnemonicInput.setText("");
        setupBtn.setEnabled(false);
        setupBtn.setText("Starting...");
        showOnly(loadingView);
        new Thread(() -> {
            String result = nativeStartDaemon(mnemonic);
            uiHandler.post(() -> {
                try {
                    org.json.JSONObject r = new org.json.JSONObject(result);
                    if (r.optBoolean("ok", false)) {
                        toast("Daemon started");
                        refreshDrives();
                    } else {
                        toast(r.optString("error", "Failed to start daemon"));
                        setupBtn.setEnabled(true);
                        setupBtn.setText("Unlock");
                        showOnly(setupView);
                    }
                } catch (Exception e) {
                    toast("Failed to start daemon");
                    setupBtn.setEnabled(true);
                    setupBtn.setText("Unlock");
                    showOnly(setupView);
                }
            });
        }).start();
    }

    private View buildLoadingView() {
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setGravity(Gravity.CENTER);
        ll.setPadding(32, 64, 32, 32);

        ProgressBar bar = new ProgressBar(this);
        bar.setIndeterminate(true);
        ll.addView(bar);

        loadingText = new TextView(this);
        loadingText.setText("Starting daemon...");
        loadingText.setTextSize(16);
        loadingText.setTextColor(0xFF8B949E);
        loadingText.setGravity(Gravity.CENTER);
        loadingText.setPadding(0, 24, 0, 0);
        ll.addView(loadingText);

        statusText = loadingText;
        return ll;
    }

    private View buildMainView() {
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);

        TextView header = new TextView(this);
        header.setText("ZeroDrive");
        header.setTextSize(22);
        header.setTextColor(0xFF58A6FF);
        header.setPadding(24, 48, 24, 8);
        ll.addView(header);

        drivesList = new LinearLayout(this);
        drivesList.setOrientation(LinearLayout.VERTICAL);
        drivesList.setPadding(16, 8, 16, 8);

        ScrollView sv = new ScrollView(this);
        sv.addView(drivesList);
        sv.setLayoutParams(new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        ll.addView(sv);

        LinearLayout bottom = new LinearLayout(this);
        bottom.setOrientation(LinearLayout.HORIZONTAL);
        bottom.setPadding(16, 12, 16, 24);
        bottom.setBackgroundColor(0xFF161B22);

        Button newDrive = new Button(this);
        newDrive.setText("+ New Drive");
        newDrive.setBackgroundColor(0xFF238636);
        newDrive.setTextColor(0xFFFFFFFF);
        newDrive.setPadding(16, 10, 16, 10);
        newDrive.setOnClickListener(v -> promptCreateDrive());
        bottom.addView(newDrive);

        Button refresh = new Button(this);
        refresh.setText("Refresh");
        refresh.setBackgroundColor(0xFF21262D);
        refresh.setTextColor(0xFF58A6FF);
        refresh.setPadding(16, 10, 16, 10);
        refresh.setOnClickListener(v -> {
            loadingText.setText("Syncing with Nostr...");
            showOnly(loadingView);
            refreshDrives();
        });
        bottom.addView(refresh);

        ll.addView(bottom);
        return ll;
    }

    private View buildFilesView() {
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setPadding(16, 48, 16, 8);

        Button back = new Button(this);
        back.setText("\u2190 Back");
        back.setBackgroundColor(0xFF21262D);
        back.setTextColor(0xFF58A6FF);
        back.setPadding(12, 8, 12, 8);
        back.setOnClickListener(v -> navigateBack());
        header.addView(back);

        filesTitle = new TextView(this);
        filesTitle.setTextSize(20);
        filesTitle.setTextColor(0xFFE6EDF3);
        filesTitle.setPadding(16, 0, 0, 0);
        header.addView(filesTitle);

        ll.addView(header);

        filesList = new LinearLayout(this);
        filesList.setOrientation(LinearLayout.VERTICAL);
        filesList.setPadding(16, 8, 16, 8);

        ScrollView sv = new ScrollView(this);
        sv.addView(filesList);
        sv.setLayoutParams(new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        ll.addView(sv);

        LinearLayout bottom = new LinearLayout(this);
        bottom.setOrientation(LinearLayout.HORIZONTAL);
        bottom.setPadding(16, 12, 16, 24);
        bottom.setBackgroundColor(0xFF161B22);

        Button upload = new Button(this);
        upload.setText("Upload File");
        upload.setBackgroundColor(0xFF238636);
        upload.setTextColor(0xFFFFFFFF);
        upload.setPadding(16, 10, 16, 10);
        upload.setOnClickListener(v -> pickFile());
        bottom.addView(upload);

        Button delDrive = new Button(this);
        delDrive.setText("Delete Drive");
        delDrive.setBackgroundColor(0xFFDA3633);
        delDrive.setTextColor(0xFFFFFFFF);
        delDrive.setPadding(16, 10, 16, 10);
        delDrive.setOnClickListener(v -> confirmDeleteDrive());
        bottom.addView(delDrive);

        ll.addView(bottom);
        return ll;
    }

    // ── NAVIGATION ──

    @Override
    public void onBackPressed() {
        if (filesView.getVisibility() == View.VISIBLE) {
            navigateBack();
        } else if (mainView.getVisibility() == View.VISIBLE) {
            super.onBackPressed();
        } else {
            super.onBackPressed();
        }
    }

    private void navigateBack() {
        refreshDrives();
    }

    // ── SCREEN MANAGEMENT ──

    private void showOnly(View v) {
        setupView.setVisibility(v == setupView ? View.VISIBLE : View.GONE);
        loadingView.setVisibility(v == loadingView ? View.VISIBLE : View.GONE);
        mainView.setVisibility(v == mainView ? View.VISIBLE : View.GONE);
        filesView.setVisibility(v == filesView ? View.VISIBLE : View.GONE);
    }

    // ── DRIVE OPERATIONS ──

    private void refreshDrives() {
        loadingText.setText("Syncing with Nostr...");
        showOnly(loadingView);
        new Thread(() -> {
            String json = nativeListDrives();
            uiHandler.post(() -> {
                renderDrives(json);
                showOnly(mainView);
            });
        }).start();
    }

    private void renderDrives(String json) {
        drivesList.removeAllViews();
        try {
            String error = extractError(json);
            if (error != null) {
                addErrorState(drivesList, "Error: " + error, this::refreshDrives);
                return;
            }
            org.json.JSONArray arr = new org.json.JSONArray(json);
            if (arr.length() == 0) {
                addEmptyText(drivesList, "No drives yet. Create one to get started.");
                return;
            }
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject d = arr.getJSONObject(i);
                addDriveCard(d.getString("name"), d.getInt("file_count"));
            }
        } catch (Exception e) {
            addErrorState(drivesList, "Error loading drives", this::refreshDrives);
        }
    }

    private String extractError(String json) {
        try {
            org.json.JSONObject obj = new org.json.JSONObject(json);
            if (obj.has("error")) return obj.getString("error");
        } catch (Exception ignored) {}
        return null;
    }

    private void addDriveCard(String name, int fileCount) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setBackgroundColor(0xFF161B22);
        card.setPadding(16, 16, 16, 16);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, 8);
        card.setLayoutParams(lp);
        card.setOnClickListener(v -> openDrive(name));

        TextView nameTv = new TextView(this);
        nameTv.setText(name);
        nameTv.setTextSize(16);
        nameTv.setTextColor(0xFFE6EDF3);
        nameTv.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        card.addView(nameTv);

        TextView countTv = new TextView(this);
        countTv.setText(fileCount + " file" + (fileCount != 1 ? "s" : ""));
        countTv.setTextSize(13);
        countTv.setTextColor(0xFF8B949E);
        card.addView(countTv);

        drivesList.addView(card);
    }

    private void openDrive(String name) {
        currentDrive = name;
        filesTitle.setText(name);
        showOnly(filesView);
        refreshFiles();
    }

    private void promptCreateDrive() {
        EditText input = new EditText(this);
        input.setHint("Drive name");
        new AlertDialog.Builder(this)
            .setTitle("Create Drive")
            .setView(input)
            .setPositiveButton("Create", (d, w) -> {
                String name = input.getText().toString().trim();
                if (name.isEmpty()) { toast("Enter a name"); return; }
                new Thread(() -> {
                    boolean ok = nativeCreateDrive(name);
                    uiHandler.post(() -> {
                        if (ok) { toast("Drive created"); refreshDrives(); }
                        else toast("Failed to create drive");
                    });
                }).start();
            })
            .setNegativeButton("Cancel", null)
            .show();
    }

    private void confirmDeleteDrive() {
        new AlertDialog.Builder(this)
            .setTitle("Delete Drive")
            .setMessage("Delete \"" + currentDrive + "\"? This cannot be undone.")
            .setPositiveButton("Delete", (d, w) -> {
                new Thread(() -> {
                    boolean ok = nativeDeleteDrive(currentDrive);
                    uiHandler.post(() -> {
                        if (ok) { toast("Drive deleted"); refreshDrives(); showOnly(mainView); }
                        else toast("Failed to delete drive");
                    });
                }).start();
            })
            .setNegativeButton("Cancel", null)
            .show();
    }

    // ── FILE OPERATIONS ──

    private void refreshFiles() {
        filesList.removeAllViews();
        addEmptyText(filesList, "Loading files...");
        new Thread(() -> {
            String json = nativeListFiles(currentDrive);
            uiHandler.post(() -> renderFiles(json));
        }).start();
    }

    private void renderFiles(String json) {
        filesList.removeAllViews();
        try {
            String error = extractError(json);
            if (error != null) {
                addErrorState(filesList, "Error: " + error, this::refreshFiles);
                return;
            }
            org.json.JSONArray arr = new org.json.JSONArray(json);
            if (arr.length() == 0) {
                addEmptyText(filesList, "No files in this drive.");
                return;
            }
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject f = arr.getJSONObject(i);
                addFileRow(f.getString("name"), f.optLong("size", 0));
            }
        } catch (Exception e) {
            addErrorState(filesList, "Error loading files", this::refreshFiles);
        }
    }

    private void addFileRow(String name, long size) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setBackgroundColor(0xFF161B22);
        row.setPadding(16, 12, 16, 12);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, 6);
        row.setLayoutParams(lp);

        LinearLayout info = new LinearLayout(this);
        info.setOrientation(LinearLayout.VERTICAL);
        info.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));

        TextView nameTv = new TextView(this);
        nameTv.setText(name);
        nameTv.setTextSize(14);
        nameTv.setTextColor(0xFFE6EDF3);
        info.addView(nameTv);

        TextView sizeTv = new TextView(this);
        sizeTv.setText(formatSize(size));
        sizeTv.setTextSize(12);
        sizeTv.setTextColor(0xFF8B949E);
        info.addView(sizeTv);

        row.addView(info);

        Button dlBtn = new Button(this);
        dlBtn.setText("\u2913");
        dlBtn.setTextSize(18);
        dlBtn.setBackgroundColor(0xFF1F6FEB);
        dlBtn.setTextColor(0xFFFFFFFF);
        dlBtn.setPadding(12, 8, 12, 8);
        dlBtn.setOnClickListener(v -> downloadFile(name));
        row.addView(dlBtn);

        Button delBtn = new Button(this);
        delBtn.setText("\u2716");
        delBtn.setTextSize(16);
        delBtn.setBackgroundColor(0xFFDA3633);
        delBtn.setTextColor(0xFFFFFFFF);
        delBtn.setPadding(12, 8, 12, 8);
        delBtn.setOnClickListener(v -> confirmDeleteFile(name));
        row.addView(delBtn);

        filesList.addView(row);
    }

    private void confirmDeleteFile(String name) {
        new AlertDialog.Builder(this)
            .setTitle("Delete File")
            .setMessage("Delete \"" + name + "\"?")
            .setPositiveButton("Delete", (d, w) -> {
                new Thread(() -> {
                    boolean ok = nativeDeleteFile(currentDrive, name);
                    uiHandler.post(() -> {
                        if (ok) { toast("File deleted"); refreshFiles(); }
                        else toast("Failed to delete file");
                    });
                }).start();
            })
            .setNegativeButton("Cancel", null)
            .show();
    }

    // ── UPLOAD ──

    private void pickFile() {
        if (currentDrive == null) {
            toast("No drive selected");
            return;
        }
        pendingUploadDrive = currentDrive;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, FILE_PICK_REQUEST);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_PICK_REQUEST && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) uploadFromUri(uri);
        }
    }

    private void uploadFromUri(Uri uri) {
        String fileName = getFileName(uri);
        long fileSize = getFileSize(uri);
        if (fileSize > MAX_UPLOAD_SIZE) {
            toast("File too large (max 500MB)");
            return;
        }

        ProgressDialog progress = new ProgressDialog(this);
        progress.setMessage("Uploading " + fileName + "...");
        progress.setCancelable(false);
        progress.setIndeterminate(true);
        progress.show();

        new Thread(() -> {
            try {
                File tmp = new File(tempDir, "upload_" + System.nanoTime() + "_" + sanitizeFileName(fileName));
                try (InputStream is = getContentResolver().openInputStream(uri);
                     FileOutputStream os = new FileOutputStream(tmp)) {
                    byte[] buf = new byte[65536];
                    int n;
                    long total = 0;
                    while ((n = is.read(buf)) != -1) {
                        os.write(buf, 0, n);
                        total += n;
                    }
                }
                String result = nativeUploadFile(pendingUploadDrive, tmp.getAbsolutePath());
                tmp.delete();
                org.json.JSONObject r = new org.json.JSONObject(result);
                uiHandler.post(() -> {
                    progress.dismiss();
                    if (r.optBoolean("ok", false)) {
                        toast("Uploaded " + r.optString("name"));
                        refreshFiles();
                    } else {
                        toast("Upload failed: " + r.optString("error"));
                    }
                });
            } catch (Exception e) {
                uiHandler.post(() -> {
                    progress.dismiss();
                    toast("Upload error: " + e.getMessage());
                });
            }
        }).start();
    }

    private long getFileSize(Uri uri) {
        long size = -1;
        try (android.database.Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.SIZE);
                if (idx >= 0) size = c.getLong(idx);
            }
        } catch (Exception ignored) {}
        return size;
    }

    private String getFileName(Uri uri) {
        String name = "file";
        try (android.database.Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) name = c.getString(idx);
            }
        } catch (Exception ignored) {}
        if (name == null || name.isEmpty()) name = "file";
        return name;
    }

    private String sanitizeFileName(String name) {
        return name.replaceAll("[/\\\\:\0]", "_");
    }

    // ── DOWNLOAD ──

    private void downloadFile(String fileName) {
        ProgressDialog progress = new ProgressDialog(this);
        progress.setMessage("Downloading " + fileName + "...");
        progress.setCancelable(false);
        progress.setIndeterminate(true);
        progress.show();

        new Thread(() -> {
            try {
                File out = new File(tempDir, "dl_" + System.nanoTime() + "_" + sanitizeFileName(fileName));
                String result = nativeDownloadFile(currentDrive, fileName, out.getAbsolutePath());
                org.json.JSONObject r = new org.json.JSONObject(result);
                uiHandler.post(() -> {
                    progress.dismiss();
                    if (r.optBoolean("ok", false)) {
                        toast("Downloaded " + fileName);
                        shareFile(out, fileName);
                    } else {
                        toast("Download failed: " + r.optString("error"));
                    }
                });
            } catch (Exception e) {
                uiHandler.post(() -> {
                    progress.dismiss();
                    toast("Download error: " + e.getMessage());
                });
            }
        }).start();
    }

    private void shareFile(File file, String fileName) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                ContentValues values = new ContentValues();
                values.put(MediaStore.Downloads.DISPLAY_NAME, fileName);
                values.put(MediaStore.Downloads.MIME_TYPE, "*/*");
                Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
                if (uri != null) {
                    try (InputStream is = new FileInputStream(file);
                         OutputStream os = getContentResolver().openOutputStream(uri)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = is.read(buf)) != -1) os.write(buf, 0, n);
                    }
                    Intent share = new Intent(Intent.ACTION_SEND);
                    share.setType("*/*");
                    share.putExtra(Intent.EXTRA_STREAM, uri);
                    share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    startActivity(Intent.createChooser(share, "Share " + fileName));
                    return;
                }
            } catch (Exception e) {
                toast("Share failed: " + e.getMessage());
            }
        }
        toast("Downloaded: " + fileName);
    }

    // ── UTILITY ──

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    private void addEmptyText(LinearLayout parent, String msg) {
        TextView tv = new TextView(this);
        tv.setText(msg);
        tv.setTextSize(14);
        tv.setTextColor(0xFF484F58);
        tv.setGravity(Gravity.CENTER);
        tv.setPadding(0, 48, 0, 0);
        parent.addView(tv);
    }

    private void addErrorState(LinearLayout parent, String msg, Runnable retry) {
        parent.removeAllViews();
        TextView tv = new TextView(this);
        tv.setText(msg);
        tv.setTextSize(14);
        tv.setTextColor(0xFFF85149);
        tv.setGravity(Gravity.CENTER);
        tv.setPadding(0, 48, 0, 16);
        parent.addView(tv);

        if (retry != null) {
            Button retryBtn = new Button(this);
            retryBtn.setText("Retry");
            retryBtn.setBackgroundColor(0xFF21262D);
            retryBtn.setTextColor(0xFF58A6FF);
            retryBtn.setPadding(32, 10, 32, 10);
            retryBtn.setGravity(Gravity.CENTER);
            retryBtn.setOnClickListener(v -> retry.run());
            LinearLayout wrapper = new LinearLayout(this);
            wrapper.setGravity(Gravity.CENTER);
            wrapper.addView(retryBtn);
            parent.addView(wrapper);
        }
    }

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp - 1) + "iB";
        DecimalFormat fmt = new DecimalFormat("#,##0.#");
        return fmt.format(bytes / Math.pow(1024, exp)) + " " + pre;
    }
}
