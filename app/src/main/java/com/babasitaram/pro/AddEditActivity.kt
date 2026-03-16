package com.babasitaram.pro

import android.os.Bundle
import android.text.*
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.security.SecureRandom

class AddEditActivity : AppCompatActivity() {
    private var editId: String? = null
    private lateinit var etSite: EditText
    private lateinit var etUrl: EditText
    private lateinit var etUser: EditText
    private lateinit var etPass: EditText
    private lateinit var etNotes: EditText
    private lateinit var spinCat: Spinner
    private lateinit var btnSave: Button
    private lateinit var btnGen: Button
    private lateinit var btnBack: ImageButton
    private lateinit var tvTitle: TextView
    private lateinit var strengthBar: ProgressBar
    private lateinit var tvStrength: TextView
    private val cats = arrayOf("Banking","Social","Email","Work","Shopping","Games","Other")

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        setContentView(R.layout.activity_add_edit)
        etSite  = findViewById(R.id.etSite)
        etUrl   = findViewById(R.id.etUrl)
        etUser  = findViewById(R.id.etUsername)
        etPass  = findViewById(R.id.etPassword)
        etNotes = findViewById(R.id.etNotes)
        spinCat = findViewById(R.id.spinnerCategory)
        btnSave = findViewById(R.id.btnSave)
        btnGen  = findViewById(R.id.btnGenerate)
        btnBack = findViewById(R.id.btnBack)
        tvTitle = findViewById(R.id.tvTitle)
        strengthBar = findViewById(R.id.strengthBar)
        tvStrength  = findViewById(R.id.tvStrength)

        spinCat.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, cats)

        // Load existing
        editId = intent.getStringExtra("id")
        editId?.let { id ->
            VaultManager.getPasswords().find { it.id == id }?.let { e ->
                tvTitle.text = "Edit Password"
                etSite.setText(e.site); etUrl.setText(e.url)
                etUser.setText(e.username); etPass.setText(e.password)
                etNotes.setText(e.notes)
                spinCat.setSelection(cats.indexOf(e.category).coerceAtLeast(0))
            }
        }

        // Pre-fill generated password
        intent.getStringExtra("generated_pw")?.let { etPass.setText(it) }

        etPass.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { updateStrength(s.toString()) }
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
        })

        btnGen.setOnClickListener {
            val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#\$%^&*"
            val pw = (1..16).map { chars[SecureRandom().nextInt(chars.length)] }.joinToString("")
            etPass.setText(pw)
        }

        btnSave.setOnClickListener { save() }
        btnBack.setOnClickListener { finish() }
    }

    private fun updateStrength(pw: String) {
        val sc = VaultManager.strengthScore(pw)
        strengthBar.progress = sc
        val (label, color) = when {
            sc >= 80 -> "Strong 💪" to 0xFF34d399.toInt()
            sc >= 60 -> "Good 👍"   to 0xFF4f8ef7.toInt()
            sc >= 40 -> "Fair ⚠️"   to 0xFFfbbf24.toInt()
            else     -> "Weak ❌"   to 0xFFf87171.toInt()
        }
        tvStrength.text = label; tvStrength.setTextColor(color)
        strengthBar.progressTintList = android.content.res.ColorStateList.valueOf(color)
    }

    private fun save() {
        val site = etSite.text.toString().trim()
        val user = etUser.text.toString().trim()
        val pass = etPass.text.toString()
        if (site.isEmpty()) { Toast.makeText(this,"Site name zaroori hai",Toast.LENGTH_SHORT).show(); return }
        if (user.isEmpty()) { Toast.makeText(this,"Username zaroori hai",Toast.LENGTH_SHORT).show(); return }
        if (pass.isEmpty()) { Toast.makeText(this,"Password zaroori hai",Toast.LENGTH_SHORT).show(); return }

        val entry = PasswordEntry(id = editId ?: java.util.UUID.randomUUID().toString(),
            site = site, url = etUrl.text.toString().trim(),
            username = user, password = pass, notes = etNotes.text.toString().trim(),
            category = spinCat.selectedItem.toString(),
            isFavorite = VaultManager.getPasswords().find { it.id == editId }?.isFavorite ?: false)

        if (editId != null) VaultManager.update(this, entry)
        else VaultManager.add(this, entry)

        Toast.makeText(this, "✓ Saved!", Toast.LENGTH_SHORT).show()
        finish()
    }
}
