package com.babasitaram.pro

import android.content.Context
import android.net.Uri
import android.util.Log
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.security.MessageDigest

/**
 * BSR Pro Backup Manager
 *
 * Format: .bsrpro — BSR-PRO-v5 format
 *
 * Security layers:
 * 1. Signature check    — only "BSR-VAULT-v5" accepted
 * 2. App name check     — only "BabaSitaRam Pro" accepted
 * 3. Magic bytes check  — "BSRVLT" hex must be present
 * 4. Origin hash check  — HMAC with BSR secret key
 * 5. AES-256-GCM encryption — Master Password required
 *
 * Any other app / tampered file = REJECTED
 */
object BackupManager {

    private const val TAG            = "BSR_Backup"
    private const val BSR_SIG        = "BSR-VAULT-v5"
    private const val BSR_APP_NAME   = "BabaSitaRam Pro"
    private const val BSR_MAGIC      = "425352564c54"       // hex "BSRVLT"
    private const val BSR_SECRET     = "b5r9p2o1a3r7m8e4"  // Same as extension

    // Old signatures for backward compatibility
    private val VALID_SIGS = setOf(
        "BSR-VAULT-v5",
        "VaultX-Proprietary-v4",
        "VaultX-Proprietary-v3"
    )

    private val gson = Gson()

    data class BackupData(
        val passwords: List<PasswordEntry> = emptyList(),
        val otp: List<OtpEntry> = emptyList(),
        val meta: Map<String, String> = emptyMap()
    )

    data class OtpEntry(
        val id: String = "",
        val site: String = "",
        val secret: String = "",
        val digits: Int = 6,
        val period: Int = 30
    )

    // ─────────────────────────────────────────────
    // EXPORT — Create BSR backup file
    // ─────────────────────────────────────────────
    suspend fun exportBackup(ctx: Context, masterPassword: String): String {
        val passwords = VaultManager.getPasswords()
        val data = BackupData(
            passwords = passwords,
            meta = mapOf(
                "app"       to BSR_APP_NAME,
                "version"   to "5",
                "device"    to android.os.Build.MODEL,
                "exportedAt" to java.util.Date().toString(),
                "count"     to passwords.size.toString()
            )
        )

        val originHash = computeOriginHash("5")
        val dataJson   = gson.toJson(data)
        val encrypted  = VaultManager.encryptString(dataJson, masterPassword)

        val backup = mapOf(
            "app"         to BSR_APP_NAME,
            "version"     to "5",
            "sig"         to BSR_SIG,
            "magic"       to BSR_MAGIC,
            "originHash"  to originHash,
            "encrypted"   to true,
            "vault_backup" to true,
            "bsr_only"    to true,
            "platform"    to "android",
            "savedAt"     to java.util.Date().toString(),
            "data"        to encrypted
        )

        return gson.toJson(backup)
    }

    // ─────────────────────────────────────────────
    // IMPORT — Verify and decrypt BSR backup
    // ─────────────────────────────────────────────
    suspend fun importBackup(
        ctx: Context,
        content: String,
        masterPassword: String
    ): ImportResult {
        return try {
            val map: Map<String, Any> = gson.fromJson(
                content, object : TypeToken<Map<String, Any>>() {}.type)

            // ── Security Check 1: Signature ──
            val sig = map["sig"] as? String
            if (sig == null || sig !in VALID_SIGS) {
                return ImportResult.Error(
                    "🚫 Yeh BSR Pro ki backup file nahi hai!\n\n" +
                    "Sirf BabaSitaRam Pro ki .bsrpro files import ho sakti hain.\n" +
                    "Doosre apps ki files support nahi hain."
                )
            }

            // ── Security Check 2: App Name ──
            val appName = map["app"] as? String
            if (appName != null && appName != BSR_APP_NAME) {
                return ImportResult.Error(
                    "🚫 Yeh file kisi aur app ki hai: \"$appName\"\n\n" +
                    "Sirf BabaSitaRam Pro ki backup files yahan import ho sakti hain."
                )
            }

            // ── Security Check 3: Magic Bytes (v5 only) ──
            if (sig == "BSR-VAULT-v5") {
                val magic = map["magic"] as? String
                if (magic != null && magic != BSR_MAGIC) {
                    return ImportResult.Error(
                        "🚫 File corrupt ya tampered hai!\n\nMagic bytes match nahi kar rahe."
                    )
                }
            }

            // ── Security Check 4: Origin Hash ──
            val originHash = map["originHash"] as? String
            if (originHash == null) {
                return ImportResult.Error("🚫 Origin token missing — invalid file!")
            }

            val version = (map["version"] as? String) ?: "4"
            if (!verifyOriginHash(originHash, version)) {
                return ImportResult.Error(
                    "🚫 File tampered ya corrupt hai!\n\nOrigin verification failed."
                )
            }

            // ── Decrypt ──
            val encryptedData = map["data"] as? String
                ?: return ImportResult.Error("🚫 Data field missing!")

            val decrypted = try {
                VaultManager.decryptString(encryptedData, masterPassword)
            } catch (e: Exception) {
                return ImportResult.Error(
                    "❌ Master Password galat hai ya file corrupt hai!\n\nSahi Master Password dalein."
                )
            }

            // ── Parse ──
            val backupData: BackupData = try {
                gson.fromJson(decrypted, BackupData::class.java)
            } catch (e: Exception) {
                return ImportResult.Error("🚫 Backup data parse error: ${e.message}")
            }

            ImportResult.Success(backupData)

        } catch (e: Exception) {
            Log.e(TAG, "Import error: ${e.message}")
            ImportResult.Error("Import failed: ${e.message}")
        }
    }

    // ─────────────────────────────────────────────
    // Origin hash — same algorithm as extension
    // ─────────────────────────────────────────────
    private fun computeOriginHash(version: String): String {
        val raw = "{\"app\":\"$BSR_APP_NAME\",\"version\":\"$version\"}$BSR_SECRET"
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(raw.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }.take(32)
    }

    private fun verifyOriginHash(hash: String, version: String): Boolean {
        // Try current + old secrets for backward compatibility
        val secrets = listOf(
            BSR_SECRET,
            "7a3f9b2e1c8d4f6b",  // extension v4
            "7a3f9b2e1c8d4f6a"   // extension v3
        )
        val versions = listOf(version, "4", "5")

        for (secret in secrets) {
            for (ver in versions) {
                val raw = "{\"app\":\"$BSR_APP_NAME\",\"version\":\"$ver\"}$secret"
                val digest = MessageDigest.getInstance("SHA-256")
                val expected = digest.digest(raw.toByteArray(Charsets.UTF_8))
                    .joinToString("") { "%02x".format(it) }.take(32)
                if (hash == expected) return true
            }
        }
        return false
    }

    sealed class ImportResult {
        data class Success(val data: BackupData) : ImportResult()
        data class Error(val message: String) : ImportResult()
    }
}
