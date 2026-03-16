package com.babasitaram.pro

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.*

class BackupActivity : AppCompatActivity() {

    private lateinit var btnExport: Button
    private lateinit var btnImport: Button
    private lateinit var btnBack: ImageButton
    private lateinit var tvStatus: TextView
    private lateinit var progressBackup: ProgressBar
    private lateinit var tvInfo: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    companion object {
        private const val REQ_IMPORT = 1001
        private const val REQ_EXPORT = 1002
    }

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        setContentView(R.layout.activity_backup)

        btnExport     = findViewById(R.id.btnExport)
        btnImport     = findViewById(R.id.btnImport)
        btnBack       = findViewById(R.id.btnBack)
        tvStatus      = findViewById(R.id.tvStatus)
        progressBackup = findViewById(R.id.progressBackup)
        tvInfo        = findViewById(R.id.tvInfo)

        tvInfo.text = """📦 BSR Pro Backup Format (.bsrpro)

• Sirf BabaSitaRam Pro Extension ya APK mein khulega
• Doosre kisi bhi app mein nahi khulega
• AES-256-GCM encrypted — Master Password zaroori
• 5-layer security verification"""

        btnBack.setOnClickListener { finish() }

        btnExport.setOnClickListener {
            val date = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date())
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_TITLE, "BSR-PRO-v5-$date.bsrpro")
            }
            startActivityForResult(intent, REQ_EXPORT)
        }

        btnImport.setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
                putExtra(Intent.EXTRA_MIME_TYPES, arrayOf(
                    "application/octet-stream", "application/json", "text/plain", "*/*"
                ))
            }
            startActivityForResult(intent, REQ_IMPORT)
        }
    }

    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        super.onActivityResult(req, res, data)
        if (res != Activity.RESULT_OK || data?.data == null) return
        val uri = data.data!!
        when (req) {
            REQ_EXPORT -> doExport(uri)
            REQ_IMPORT -> promptImportPassword(uri)
        }
    }

    private fun doExport(uri: Uri) {
        showLoading("Exporting...")
        scope.launch {
            try {
                val master = withContext(Dispatchers.IO) {
                    AppPrefs.getMasterForBio(this@BackupActivity)
                } ?: run {
                    showError("Master Password se login karein pehle")
                    return@launch
                }

                val json = withContext(Dispatchers.IO) {
                    BackupManager.exportBackup(this@BackupActivity, master)
                }

                withContext(Dispatchers.IO) {
                    contentResolver.openOutputStream(uri)?.use { out ->
                        out.write(json.toByteArray(Charsets.UTF_8))
                    }
                }

                val count = VaultManager.getPasswords().size
                showSuccess("✓ $count passwords exported!\n.bsrpro file saved")

            } catch (e: Exception) {
                showError("Export failed: ${e.message}")
            }
        }
    }

    private fun promptImportPassword(uri: Uri) {
        // Read file first to check if it's BSR format
        val layout = layoutInflater.inflate(R.layout.dialog_import_backup, null)
        val tvFileInfo = layout.findViewById<TextView>(R.id.tvFileInfo)
        val etPassword = layout.findViewById<EditText>(R.id.etImportPassword)
        val tvErr = layout.findViewById<TextView>(R.id.tvImportError)

        // Quick pre-check
        scope.launch {
            try {
                val content = withContext(Dispatchers.IO) { readUri(uri) }
                val preview = content.take(200)

                if (!preview.contains("BSR-VAULT") && !preview.contains("VaultX-Proprietary") &&
                    !preview.contains("BabaSitaRam Pro")) {
                    handler.post {
                        tvFileInfo.text = "⚠️ Yeh BSR Pro ki backup file nahi lagti!\n\nFile check karo."
                        tvFileInfo.setTextColor(0xFFf87171.toInt())
                    }
                } else {
                    handler.post {
                        tvFileInfo.text = "✓ BSR Pro backup file detected"
                        tvFileInfo.setTextColor(0xFF34d399.toInt())
                    }
                }

                handler.post {
                    val dialog = androidx.appcompat.app.AlertDialog.Builder(this@BackupActivity)
                        .setTitle("Import Backup")
                        .setView(layout)
                        .setPositiveButton("Import") { _, _ -> }
                        .setNegativeButton("Cancel", null)
                        .create()

                    dialog.show()
                    dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE)
                        .setOnClickListener {
                            val pw = etPassword.text.toString()
                            if (pw.isEmpty()) {
                                tvErr.text = "Master Password zaroori hai"
                                tvErr.visibility = View.VISIBLE
                                return@setOnClickListener
                            }
                            dialog.dismiss()
                            doImport(uri, content, pw)
                        }
                }
            } catch (e: Exception) {
                showError("File read error: ${e.message}")
            }
        }
    }

    private fun doImport(uri: Uri, content: String, masterPassword: String) {
        showLoading("Verifying & importing...")
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                BackupManager.importBackup(this@BackupActivity, content, masterPassword)
            }

            when (result) {
                is BackupManager.ImportResult.Success -> {
                    val data = result.data
                    var added = 0
                    withContext(Dispatchers.IO) {
                        data.passwords.forEach { entry ->
                            val exists = VaultManager.getPasswords().any {
                                it.site == entry.site && it.username == entry.username
                            }
                            if (!exists) {
                                VaultManager.add(this@BackupActivity, entry)
                                added++
                            }
                        }
                    }
                    showSuccess("✓ Import successful!\n$added new passwords added\n(Duplicates skipped)")
                }
                is BackupManager.ImportResult.Error -> {
                    showError(result.message)
                }
            }
        }
    }

    private fun readUri(uri: Uri): String {
        val sb = StringBuilder()
        contentResolver.openInputStream(uri)?.use { input ->
            BufferedReader(InputStreamReader(input)).use { reader ->
                reader.lineSequence().forEach { sb.append(it) }
            }
        }
        return sb.toString()
    }

    private fun showLoading(msg: String) {
        progressBackup.visibility = View.VISIBLE
        tvStatus.text = msg
        tvStatus.setTextColor(0xFF94a3b8.toInt())
        tvStatus.visibility = View.VISIBLE
        btnExport.isEnabled = false
        btnImport.isEnabled = false
    }

    private fun showSuccess(msg: String) {
        progressBackup.visibility = View.GONE
        tvStatus.text = msg
        tvStatus.setTextColor(0xFF34d399.toInt())
        tvStatus.visibility = View.VISIBLE
        btnExport.isEnabled = true
        btnImport.isEnabled = true
    }

    private fun showError(msg: String) {
        progressBackup.visibility = View.GONE
        tvStatus.text = msg
        tvStatus.setTextColor(0xFFf87171.toInt())
        tvStatus.visibility = View.VISIBLE
        btnExport.isEnabled = true
        btnImport.isEnabled = true
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}
