package com.babasitaram.pro

import android.content.Intent
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager

class SettingsActivity : AppCompatActivity() {

    private lateinit var switchBiometric: Switch
    private lateinit var spinnerAutoLock: Spinner
    private lateinit var spinnerClipClear: Spinner
    private lateinit var btnChangeMaster: Button
    private lateinit var btnResetVault: Button
    private lateinit var btnBack: ImageButton
    private lateinit var tvVersion: TextView

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        setContentView(R.layout.activity_settings)

        switchBiometric   = findViewById(R.id.switchBiometric)
        spinnerAutoLock   = findViewById(R.id.spinnerAutoLock)
        spinnerClipClear  = findViewById(R.id.spinnerClipClear)
        btnChangeMaster   = findViewById(R.id.btnChangeMaster)
        btnResetVault     = findViewById(R.id.btnResetVault)
        btnBack           = findViewById(R.id.btnBack)
        tvVersion         = findViewById(R.id.tvVersion)

        tvVersion.text = "BabaSitaRam Pro v5.4"
        btnBack.setOnClickListener { finish() }

        // Biometric
        val canBio = BiometricManager.from(this).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        ) == BiometricManager.BIOMETRIC_SUCCESS

        switchBiometric.isEnabled = canBio
        switchBiometric.isChecked = AppPrefs.getBiometric(this)
        if (!canBio) switchBiometric.text = "Biometric (device pe available nahi)"

        switchBiometric.setOnCheckedChangeListener { _, checked ->
            if (checked && AppPrefs.getMasterForBio(this) == null) {
                switchBiometric.isChecked = false
                Toast.makeText(this, "Pehle Master Password se login karein", Toast.LENGTH_SHORT).show()
                return@setOnCheckedChangeListener
            }
            AppPrefs.setBiometric(this, checked)
            Toast.makeText(this, if (checked) "Biometric ON" else "Biometric OFF", Toast.LENGTH_SHORT).show()
        }

        // Auto-lock spinner
        val lockOpts = arrayOf("Never", "1 minute", "5 minutes", "15 minutes", "30 minutes", "1 hour")
        val lockVals = intArrayOf(0, 1, 5, 15, 30, 60)
        spinnerAutoLock.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, lockOpts)
        val curLock = AppPrefs.getAutoLock(this)
        spinnerAutoLock.setSelection(lockVals.indexOfFirst { it == curLock }.coerceAtLeast(0))
        spinnerAutoLock.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: AdapterView<*>?, v: android.view.View?, pos: Int, id: Long) {
                AppPrefs.setAutoLock(this@SettingsActivity, lockVals[pos])
            }
            override fun onNothingSelected(p: AdapterView<*>?) {}
        }

        // Clipboard clear spinner
        val clipOpts = arrayOf("Never", "15 seconds", "30 seconds", "1 minute", "2 minutes")
        val clipVals = intArrayOf(0, 15, 30, 60, 120)
        spinnerClipClear.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, clipOpts)
        val curClip = AppPrefs.getClipClear(this)
        spinnerClipClear.setSelection(clipVals.indexOfFirst { it == curClip }.coerceAtLeast(0))
        spinnerClipClear.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: AdapterView<*>?, v: android.view.View?, pos: Int, id: Long) {
                AppPrefs.setClipClear(this@SettingsActivity, clipVals[pos])
            }
            override fun onNothingSelected(p: AdapterView<*>?) {}
        }

        // Change master password
        btnChangeMaster.setOnClickListener { showChangeMasterDialog() }

        // Reset vault
        // Backup button
        findViewById<Button>(R.id.btnBackupRestore)?.setOnClickListener {
            startActivity(Intent(this, BackupActivity::class.java))
        }

        btnResetVault.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("⚠️ Reset Vault")
                .setMessage("Saara data permanently delete ho jayega. Koi backup nahi bachega.\n\nKya aap 100% sure hain?")
                .setPositiveButton("RESET KARO") { _, _ ->
                    VaultManager.resetAll(this)
                    AppPrefs.clearBioCache(this)
                    startActivity(Intent(this, LoginActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
                    finish()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun showChangeMasterDialog() {
        val layout = layoutInflater.inflate(R.layout.dialog_change_master, null)
        val etOld  = layout.findViewById<EditText>(R.id.etOldMaster)
        val etNew  = layout.findViewById<EditText>(R.id.etNewMaster)
        val etConf = layout.findViewById<EditText>(R.id.etConfirmMaster)
        val tvErr  = layout.findViewById<TextView>(R.id.tvMasterError)

        AlertDialog.Builder(this)
            .setTitle("Change Master Password")
            .setView(layout)
            .setPositiveButton("Change") { _, _ ->  }
            .setNegativeButton("Cancel", null)
            .create().also { dlg ->
                dlg.show()
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    val old  = etOld.text.toString()
                    val newP = etNew.text.toString()
                    val conf = etConf.text.toString()
                    tvErr.visibility = android.view.View.GONE
                    when {
                        !VaultManager.verifyMaster(this, old)  -> { tvErr.text = "Purana password galat hai"; tvErr.visibility = android.view.View.VISIBLE }
                        newP.length < 6 -> { tvErr.text = "Naya password 6+ chars ka hona chahiye"; tvErr.visibility = android.view.View.VISIBLE }
                        newP != conf     -> { tvErr.text = "Naya password match nahi kar raha"; tvErr.visibility = android.view.View.VISIBLE }
                        else -> {
                            val passwords = VaultManager.getPasswords()
                            VaultManager.setupMaster(this, newP)
                            VaultManager.unlock(this, newP)
                            passwords.forEach { VaultManager.add(this, it) }
                            AppPrefs.saveMasterForBio(this, newP)
                            Toast.makeText(this, "✓ Master Password change ho gaya", Toast.LENGTH_SHORT).show()
                            dlg.dismiss()
                        }
                    }
                }
            }
    }
}
