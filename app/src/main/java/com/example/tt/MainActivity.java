package com.example.tt;

import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'tt' library on application startup.
    static {
        System.loadLibrary("tt");
    }

    private static final int PICK_TXT_FILE = 1;
    private static final int CREATE_FILE = 2;

    private WebView webView;
    private Button selectFileButton;
    private Button saveFileButton;
    private String fileContent = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webView);
        selectFileButton = findViewById(R.id.button_select_file);
        saveFileButton = findViewById(R.id.button_save_file);

        // Cấu hình WebView cho phép cuộn ngang
        webView.setHorizontalScrollBarEnabled(true);
        WebSettings webSettings = webView.getSettings();
        webSettings.setLoadWithOverviewMode(true);
        webSettings.setUseWideViewPort(true);
        webView.setInitialScale(200);

        // Khi bấm nút, mở bộ chọn file
        selectFileButton.setOnClickListener(v -> openFilePicker());

        saveFileButton.setOnClickListener(v -> showSaveDialog());
    }

    private void openFilePicker() {
        // Mở bộ chọn file
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("text/plain");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(intent, PICK_TXT_FILE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_TXT_FILE && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                // Đọc nội dung của file được chọn và hiển thị trong WebView
                readTextFile(uri);

                Toast.makeText(this, stringFromJNI(), Toast.LENGTH_SHORT).show();
                // Hiển thị nút lưu file sau khi chọn file thành công
                saveFileButton.setVisibility(Button.VISIBLE);

            }
        } else if (requestCode == CREATE_FILE && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                saveTextFile(uri);

                // Sau khi lưu xong, ẩn nút lưu và xóa nội dung WebView
                saveFileButton.setVisibility(Button.GONE);
                webView.loadData("", "text/html", "UTF-8"); // Xóa nội dung WebView
            }
        }
    }

    private void readTextFile(Uri uri) {
        try {
            InputStream inputStream = getContentResolver().openInputStream(uri);
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
            reader.close();

            fileContent = stringBuilder.toString();
            String formattedText = "<pre>" + fileContent + "</pre>";
            // Hiển thị nội dung trong WebView
            webView.loadDataWithBaseURL(null, formattedText, "text/html", "UTF-8", null);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Hiển thị dialog để người dùng nhập tên file mới
    private void showSaveDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Nhập tên file mới");

        final EditText input = new EditText(this);
        input.setHint("Tên file");
        builder.setView(input);

        builder.setPositiveButton("Lưu", (dialog, which) -> {
            String fileName = input.getText().toString();
            if (!fileName.endsWith(".txt")) {
                fileName += ".txt";
            }
            createNewFile(fileName);
        });
        builder.setNegativeButton("Hủy", (dialog, which) -> dialog.cancel());

        builder.show();
    }

    // Mở bộ chọn vị trí lưu file
    private void createNewFile(String fileName) {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TITLE, fileName);
        startActivityForResult(intent, CREATE_FILE);
    }

    // Lưu nội dung vào file mới
    private void saveTextFile(Uri uri) {
        try {
            OutputStream outputStream = getContentResolver().openOutputStream(uri);
            if (outputStream != null) {
                outputStream.write(fileContent.getBytes());
                outputStream.close();
                Toast.makeText(this, "File đã được lưu", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "Lưu file thất bại", Toast.LENGTH_SHORT).show();
        }
    }

    public native String stringFromJNI();

    public native byte[] encrypt(byte[] plaintext, byte[] key, byte[] iv);
    public native byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv);
}


//import androidx.appcompat.app.AppCompatActivity;
//
//import android.os.Bundle;
//import android.widget.TextView;
//
//import com.example.tt.databinding.ActivityMainBinding;
//
//public class MainActivity extends AppCompatActivity {
//
//    // Used to load the 'tt' library on application startup.
//    static {
//        System.loadLibrary("tt");
//    }
//
//    private ActivityMainBinding binding;
//
//    @Override
//    protected void onCreate(Bundle savedInstanceState) {
//        super.onCreate(savedInstanceState);
//
//        binding = ActivityMainBinding.inflate(getLayoutInflater());
//        setContentView(binding.getRoot());
//
//        // Example of a call to a native method
//        TextView tv = binding.sampleText;
//        tv.setText(stringFromJNI());
//    }
//
//    /**
//     * A native method that is implemented by the 'tt' native library,
//     * which is packaged with this application.
//     */
//    public native String stringFromJNI();
//}