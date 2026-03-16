package com.babasitaram.pro.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.*
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.babasitaram.pro.LoginActivity
import com.babasitaram.pro.PasswordEntry
import com.babasitaram.pro.R
import com.babasitaram.pro.VaultManager

class BSRAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
            ?: run { callback.onSuccess(null); return }

        val parser = StructureParser(structure)
        parser.parse()

        val usernameIds: List<AutofillId> = parser.usernameIds
        val passwordIds: List<AutofillId> = parser.passwordIds

        if (usernameIds.isEmpty() && passwordIds.isEmpty()) {
            callback.onSuccess(null); return
        }

        // Vault locked — show auth prompt
        if (!VaultManager.isUnlocked) {
            val authIntent = Intent(this, LoginActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                putExtra("from_autofill", true)
            }
            val pending = PendingIntent.getActivity(
                this, 0, authIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
                setTextViewText(R.id.tvAutofillSite, "🔐 BSR Pro — Unlock to fill")
                setTextViewText(R.id.tvAutofillUser, "Tap to unlock vault")
            }
            val datasetBuilder = Dataset.Builder()
            usernameIds.forEach { id -> datasetBuilder.setValue(id, null, presentation) }
            passwordIds.forEach { id -> datasetBuilder.setValue(id, null, presentation) }
            val response = FillResponse.Builder()
                .addDataset(datasetBuilder.setAuthentication(pending.intentSender).build())
                .build()
            callback.onSuccess(response)
            return
        }

        // Find matching passwords
        val appId     = structure.activityComponent?.packageName ?: ""
        val webDomain = parser.webDomain ?: ""
        val query     = webDomain.ifEmpty { appId }

        val matches: List<PasswordEntry> = VaultManager.getPasswordsForUrl(query).ifEmpty {
            VaultManager.searchPasswords(appId.substringAfterLast('.'))
        }

        if (matches.isEmpty()) { callback.onSuccess(null); return }

        val responseBuilder = FillResponse.Builder()
        matches.take(5).forEach { entry ->
            val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
                setTextViewText(R.id.tvAutofillSite, "🔐 ${entry.site}")
                setTextViewText(R.id.tvAutofillUser, entry.username)
            }
            val datasetBuilder = Dataset.Builder()
            // explicit type annotation fixes forEach ambiguity
            usernameIds.forEach { id: AutofillId ->
                datasetBuilder.setValue(id, AutofillValue.forText(entry.username), presentation)
            }
            passwordIds.forEach { id: AutofillId ->
                datasetBuilder.setValue(id, AutofillValue.forText(entry.password), presentation)
            }
            responseBuilder.addDataset(datasetBuilder.build())
        }
        callback.onSuccess(responseBuilder.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onSuccess()
    }
}

// ── Structure Parser ──
class StructureParser(private val structure: AssistStructure) {

    val usernameIds = mutableListOf<AutofillId>()
    val passwordIds = mutableListOf<AutofillId>()
    var webDomain: String? = null

    fun parse() {
        for (i in 0 until structure.windowNodeCount) {
            parseNode(structure.getWindowNodeAt(i).rootViewNode)
        }
    }

    private fun parseNode(node: AssistStructure.ViewNode) {
        node.webDomain?.let { if (webDomain == null) webDomain = it }

        val autofillId = node.autofillId ?: run {
            for (i in 0 until node.childCount) parseNode(node.getChildAt(i))
            return
        }

        val hints       = node.autofillHints ?: emptyArray()
        val inputType   = node.inputType
        val viewId      = node.idEntry?.lowercase() ?: ""
        val hint        = node.hint?.lowercase() ?: ""
        val contentDesc = node.contentDescription?.toString()?.lowercase() ?: ""

        val isPassword = hints.any { it == android.view.View.AUTOFILL_HINT_PASSWORD }
            || (inputType and android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD) != 0
            || (inputType and android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) != 0
            || (inputType and android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) != 0
            || viewId.contains("pass") || hint.contains("pass")
            || contentDesc.contains("pass") || viewId.contains("pwd")

        val isUsername = !isPassword && (
            hints.any {
                it == android.view.View.AUTOFILL_HINT_USERNAME ||
                it == android.view.View.AUTOFILL_HINT_EMAIL_ADDRESS ||
                it == android.view.View.AUTOFILL_HINT_PHONE
            }
            || (inputType and android.text.InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS) != 0
            || (inputType and android.text.InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) != 0
            || viewId.contains("user") || viewId.contains("email")
            || viewId.contains("login") || viewId.contains("mobile")
            || viewId.contains("phone")
            || hint.contains("user") || hint.contains("email")
            || hint.contains("mobile") || hint.contains("phone")
        )

        when {
            isPassword -> passwordIds.add(autofillId)
            isUsername -> usernameIds.add(autofillId)
        }

        for (i in 0 until node.childCount) parseNode(node.getChildAt(i))
    }
}
