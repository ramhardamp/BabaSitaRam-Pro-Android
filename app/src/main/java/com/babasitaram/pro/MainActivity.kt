package com.babasitaram.pro

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

class MainActivity : AppCompatActivity() {

    private lateinit var rv: RecyclerView
    private lateinit var etSearch: EditText
    private lateinit var fab: com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
    private lateinit var tvEmpty: TextView
    private lateinit var tvCount: TextView
    private lateinit var chipAll: TextView
    private lateinit var chipFav: TextView
    private lateinit var chipBanking: TextView
    private lateinit var chipSocial: TextView
    private lateinit var chipEmail: TextView
    private var adapter: PwAdapter? = null
    private var currentFilter = "All"
    private val handler = Handler(Looper.getMainLooper())
    private var clipClearRunnable: Runnable? = null

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        setContentView(R.layout.activity_main)

        if (!VaultManager.isUnlocked) { goLogin(); return }

        rv           = findViewById(R.id.rvPasswords)
        etSearch     = findViewById(R.id.etSearch)
        fab          = findViewById(R.id.fabAdd)
        tvEmpty      = findViewById(R.id.tvEmpty)
        tvCount      = findViewById(R.id.tvCount)
        chipAll      = findViewById(R.id.chipAll)
        chipFav      = findViewById(R.id.chipFav)
        chipBanking  = findViewById(R.id.chipBanking)
        chipSocial   = findViewById(R.id.chipSocial)
        chipEmail    = findViewById(R.id.chipEmail)

        setupRv()
        setupSearch()
        setupChips()
        fab.setOnClickListener { startActivity(Intent(this, AddEditActivity::class.java)) }
        findViewById<ImageButton>(R.id.btnSettings)?.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
        findViewById<ImageButton>(R.id.btnGenerator)?.setOnClickListener {
            startActivity(Intent(this, GeneratorActivity::class.java))
        }
        render()
    }

    override fun onResume() {
        super.onResume()
        if (!VaultManager.isUnlocked) { goLogin(); return }
        if (AppPrefs.isSessionExpired(this)) { VaultManager.lock(); goLogin(); return }
        AppPrefs.setLastActive(this)
        render()
    }

    override fun onPause() {
        super.onPause()
        AppPrefs.setLastActive(this)
    }

    private fun setupRv() {
        rv.layoutManager = LinearLayoutManager(this)
        rv.addItemDecoration(DividerItemDecoration(this, DividerItemDecoration.VERTICAL))
        adapter = PwAdapter(
            onEdit   = { startActivity(Intent(this, AddEditActivity::class.java).putExtra("id", it.id)) },
            onDelete = { confirmDelete(it) },
            onCopyU  = { copy("Username", it.username) },
            onCopyP  = { copy("Password", it.password) },
            onFav    = { VaultManager.toggleFav(this, it.id); render() },
            onShow   = { showDetail(it) }
        )
        rv.adapter = adapter
    }

    private fun setupSearch() {
        etSearch.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { render() }
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
        })
    }

    private fun setupChips() {
        val chips = listOf(
            chipAll to "All", chipFav to "Favorites",
            chipBanking to "Banking", chipSocial to "Social", chipEmail to "Email"
        )
        chips.forEach { (chip, filter) ->
            chip.setOnClickListener {
                currentFilter = filter
                chips.forEach { (c, _) -> c.isSelected = false }
                chip.isSelected = true
                render()
            }
        }
        chipAll.isSelected = true
    }

    private fun render() {
        val q = etSearch.text.toString().trim()
        val list: List<PasswordEntry> = when {
            q.isNotEmpty()               -> VaultManager.search(q)
            currentFilter == "Favorites" -> VaultManager.getFavorites()
            currentFilter == "All"       -> VaultManager.getPasswords()
            else                         -> VaultManager.getByCategory(currentFilter)
        }
        val sorted = list.sortedWith(
            compareByDescending<PasswordEntry> { it.isFavorite }.thenBy { it.site.lowercase() }
        )
        adapter?.submit(sorted)
        val total = VaultManager.getPasswords().size
        tvCount.text = if (q.isNotEmpty() || currentFilter != "All") "${list.size}/$total" else "$total passwords"
        tvEmpty.visibility = if (sorted.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun confirmDelete(e: PasswordEntry) {
        AlertDialog.Builder(this)
            .setTitle("Delete?")
            .setMessage("\"${e.site}\" delete karna chahte ho?")
            .setPositiveButton("Delete") { _, _ -> VaultManager.delete(this, e.id); render(); toast("Deleted") }
            .setNegativeButton("Cancel", null).show()
    }

    private fun showDetail(e: PasswordEntry) {
        AlertDialog.Builder(this)
            .setTitle(e.site)
            .setMessage("Username: ${e.username}\nPassword: ${e.password}\n\nURL: ${e.url}\nNotes: ${e.notes}")
            .setPositiveButton("Copy Password") { _, _ -> copy("Password", e.password) }
            .setNeutralButton("Copy Username") { _, _ -> copy("Username", e.username) }
            .setNegativeButton("Close", null).show()
    }

    private fun copy(label: String, text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        val secs = AppPrefs.getClipClear(this)
        toast("$label copied!" + if (secs > 0) " (${secs}s mein clear hoga)" else "")
        if (secs > 0) {
            clipClearRunnable?.let { handler.removeCallbacks(it) }
            clipClearRunnable = Runnable {
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        cm.clearPrimaryClip()
                    } else {
                        cm.setPrimaryClip(ClipData.newPlainText("", ""))
                    }
                } catch (ex: Exception) { }
            }
            handler.postDelayed(clipClearRunnable!!, secs * 1000L)
        }
    }

    private fun goLogin() {
        startActivity(Intent(this, LoginActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        finish()
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}

// ── Adapter ──
class PwAdapter(
    private val onEdit:   (PasswordEntry) -> Unit,
    private val onDelete: (PasswordEntry) -> Unit,
    private val onCopyU:  (PasswordEntry) -> Unit,
    private val onCopyP:  (PasswordEntry) -> Unit,
    private val onFav:    (PasswordEntry) -> Unit,
    private val onShow:   (PasswordEntry) -> Unit
) : RecyclerView.Adapter<PwAdapter.VH>() {

    private var list: List<PasswordEntry> = emptyList()
    fun submit(l: List<PasswordEntry>) { list = l; notifyDataSetChanged() }

    inner class VH(v: View) : RecyclerView.ViewHolder(v) {
        val tvAvatar:    TextView     = v.findViewById(R.id.tvAvatar)
        val tvSite:      TextView     = v.findViewById(R.id.tvSite)
        val tvUser:      TextView     = v.findViewById(R.id.tvUser)
        val tvCat:       TextView     = v.findViewById(R.id.tvCategory)
        val tvStrength:  TextView     = v.findViewById(R.id.tvStrength)
        val btnFav:      ImageButton  = v.findViewById(R.id.btnFav)
        val btnCopyU:    ImageButton  = v.findViewById(R.id.btnCopyUser)
        val btnCopyP:    ImageButton  = v.findViewById(R.id.btnCopyPass)
        val btnEdit:     ImageButton  = v.findViewById(R.id.btnEdit)
        val btnDel:      ImageButton  = v.findViewById(R.id.btnDelete)
        val strengthBar: ProgressBar  = v.findViewById(R.id.strengthBar)
    }

    override fun onCreateViewHolder(p: ViewGroup, t: Int) =
        VH(LayoutInflater.from(p.context).inflate(R.layout.item_password, p, false))

    override fun getItemCount() = list.size

    override fun onBindViewHolder(h: VH, i: Int) {
        val e = list[i]
        h.tvSite.text   = e.site.ifEmpty { "Unknown" }
        h.tvUser.text   = e.username
        h.tvCat.text    = e.category
        h.tvAvatar.text = e.site.firstOrNull()?.uppercaseChar()?.toString() ?: "?"

        val sc = VaultManager.strengthScore(e.password)
        h.strengthBar.progress = sc
        val (sLabel, sColor) = when {
            sc >= 80 -> "Strong" to 0xFF34d399.toInt()
            sc >= 60 -> "Good"   to 0xFF4f8ef7.toInt()
            sc >= 40 -> "Fair"   to 0xFFfbbf24.toInt()
            else     -> "Weak"   to 0xFFf87171.toInt()
        }
        h.tvStrength.text = sLabel
        h.tvStrength.setTextColor(sColor)
        h.strengthBar.progressTintList =
            android.content.res.ColorStateList.valueOf(sColor)

        val catColors = mapOf(
            "Banking"  to 0xFF1565C0.toInt(),
            "Social"   to 0xFF6A1B9A.toInt(),
            "Email"    to 0xFFE65100.toInt(),
            "Work"     to 0xFF2E7D32.toInt(),
            "Shopping" to 0xFFC62828.toInt(),
            "Games"    to 0xFF1B5E20.toInt(),
            "Other"    to 0xFF37474F.toInt()
        )
        h.tvAvatar.setBackgroundColor(catColors[e.category] ?: 0xFF37474F.toInt())

        h.btnFav.alpha = if (e.isFavorite) 1f else 0.35f
        h.btnFav.setColorFilter(
            if (e.isFavorite) 0xFFfbbf24.toInt() else 0xFF94a3b8.toInt()
        )

        h.btnFav.setOnClickListener   { onFav(e) }
        h.btnCopyU.setOnClickListener { onCopyU(e) }
        h.btnCopyP.setOnClickListener { onCopyP(e) }
        h.btnEdit.setOnClickListener  { onEdit(e) }
        h.btnDel.setOnClickListener   { onDelete(e) }
        h.itemView.setOnClickListener        { onShow(e) }
        h.itemView.setOnLongClickListener    { onEdit(e); true }
    }
}
