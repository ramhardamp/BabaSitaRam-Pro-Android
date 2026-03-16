package com.babasitaram.pro

import android.content.*
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.security.SecureRandom

class GeneratorActivity : AppCompatActivity() {
    private lateinit var tvPassword: TextView
    private lateinit var seekLength: SeekBar
    private lateinit var tvLength: TextView
    private lateinit var cbUpper: CheckBox
    private lateinit var cbLower: CheckBox
    private lateinit var cbNumbers: CheckBox
    private lateinit var cbSymbols: CheckBox
    private lateinit var btnGenerate: Button
    private lateinit var btnCopy: Button
    private lateinit var btnUse: Button
    private lateinit var strengthBar: ProgressBar
    private lateinit var tvStrength: TextView
    private lateinit var btnBack: ImageButton
    private val rng = SecureRandom()

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        setContentView(R.layout.activity_generator)
        tvPassword   = findViewById(R.id.tvGeneratedPassword)
        seekLength   = findViewById(R.id.seekLength)
        tvLength     = findViewById(R.id.tvLength)
        cbUpper      = findViewById(R.id.cbUppercase)
        cbLower      = findViewById(R.id.cbLowercase)
        cbNumbers    = findViewById(R.id.cbNumbers)
        cbSymbols    = findViewById(R.id.cbSymbols)
        btnGenerate  = findViewById(R.id.btnGenerate)
        btnCopy      = findViewById(R.id.btnCopy)
        btnUse       = findViewById(R.id.btnUsePassword)
        strengthBar  = findViewById(R.id.strengthBar)
        tvStrength   = findViewById(R.id.tvStrength)
        btnBack      = findViewById(R.id.btnBack)

        seekLength.max = 48
        seekLength.progress = 16
        tvLength.text = "16"

        seekLength.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(s: SeekBar?, v: Int, u: Boolean) {
                val len = v + 8
                tvLength.text = "$len"
                if (tvPassword.text.isNotEmpty()) generate()
            }
            override fun onStartTrackingTouch(s: SeekBar?) {}
            override fun onStopTrackingTouch(s: SeekBar?) {}
        })

        btnGenerate.setOnClickListener { generate() }
        btnCopy.setOnClickListener {
            val pw = tvPassword.text.toString()
            if (pw.isEmpty()) return@setOnClickListener
            val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Password", pw))
            Toast.makeText(this, "Password copied!", Toast.LENGTH_SHORT).show()
        }
        btnBack.setOnClickListener { finish() }
        btnUse.setOnClickListener {
            val pw = tvPassword.text.toString()
            if (pw.isNotEmpty()) {
                val intent = Intent(this, AddEditActivity::class.java)
                intent.putExtra("generated_pw", pw)
                startActivity(intent)
                finish()
            }
        }
        btnBack.setOnClickListener { finish() }
        generate()
    }

    private fun generate() {
        val len = seekLength.progress + 8
        var chars = ""
        if (cbUpper.isChecked)   chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if (cbLower.isChecked)   chars += "abcdefghijklmnopqrstuvwxyz"
        if (cbNumbers.isChecked) chars += "0123456789"
        if (cbSymbols.isChecked) chars += "!@#\$%^&*()_+-=[]{}|;:,.<>?"
        if (chars.isEmpty())     chars = "abcdefghijklmnopqrstuvwxyz"

        val pw = (1..len).map { chars[rng.nextInt(chars.length)] }.joinToString("")
        tvPassword.text = pw

        // Update strength
        val sc = VaultManager.strengthScore(pw)
        strengthBar.progress = sc
        val (label, color) = when {
            sc >= 80 -> "Strong 💪" to 0xFF34d399.toInt()
            sc >= 60 -> "Good 👍"   to 0xFF4f8ef7.toInt()
            sc >= 40 -> "Fair ⚠️"   to 0xFFfbbf24.toInt()
            else     -> "Weak ❌"   to 0xFFf87171.toInt()
        }
        tvStrength.text = label
        tvStrength.setTextColor(color)
        strengthBar.progressTintList = android.content.res.ColorStateList.valueOf(color)
    }
}
