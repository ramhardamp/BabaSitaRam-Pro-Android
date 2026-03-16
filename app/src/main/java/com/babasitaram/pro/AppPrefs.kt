package com.babasitaram.pro

import android.content.Context
import android.content.SharedPreferences

object AppPrefs {
    private const val FILE = "bsr_prefs"

    private fun p(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    // Biometric
    var biometricEnabled: Boolean = false
    fun setBiometric(ctx: Context, v: Boolean) { p(ctx).edit().putBoolean("bio", v).apply(); biometricEnabled = v }
    fun getBiometric(ctx: Context): Boolean { biometricEnabled = p(ctx).getBoolean("bio", false); return biometricEnabled }

    // Auto-lock timeout (minutes, 0=never)
    fun setAutoLock(ctx: Context, mins: Int) = p(ctx).edit().putInt("al", mins).apply()
    fun getAutoLock(ctx: Context): Int = p(ctx).getInt("al", 5)

    // Clipboard clear (seconds, 0=never)
    fun setClipClear(ctx: Context, secs: Int) = p(ctx).edit().putInt("cc", secs).apply()
    fun getClipClear(ctx: Context): Int = p(ctx).getInt("cc", 30)

    // Last active time
    fun setLastActive(ctx: Context) = p(ctx).edit().putLong("la", System.currentTimeMillis()).apply()
    fun isSessionExpired(ctx: Context): Boolean {
        val mins = getAutoLock(ctx)
        if (mins == 0) return false
        val last = p(ctx).getLong("la", 0L)
        return System.currentTimeMillis() - last > mins * 60 * 1000L
    }

    // Master for biometric (base64 obfuscated)
    fun saveMasterForBio(ctx: Context, master: String) {
        val enc = android.util.Base64.encodeToString(master.reversed().toByteArray(), android.util.Base64.NO_WRAP)
        ctx.getSharedPreferences("bsr_bio_cache", Context.MODE_PRIVATE).edit().putString("cm", enc).commit()
    }
    fun getMasterForBio(ctx: Context): String? {
        val enc = ctx.getSharedPreferences("bsr_bio_cache", Context.MODE_PRIVATE).getString("cm", null) ?: return null
        return try { String(android.util.Base64.decode(enc, android.util.Base64.NO_WRAP)).reversed() } catch (e: Exception) { null }
    }
    fun clearBioCache(ctx: Context) = ctx.getSharedPreferences("bsr_bio_cache", Context.MODE_PRIVATE).edit().clear().apply()
}
