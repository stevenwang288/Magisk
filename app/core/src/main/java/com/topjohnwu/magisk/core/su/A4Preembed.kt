package com.topjohnwu.magisk.core.su

import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import com.topjohnwu.magisk.core.data.magiskdb.PolicyDao
import com.topjohnwu.magisk.core.model.su.SuPolicy
import java.security.MessageDigest

/**
 * Pre-embed the trusted A4 installer app ([com.installer.tool]) into the Magisk superuser list.
 *
 * Trust is bound to the Alpha release signing certificate (SHA-256), not just the package name,
 * so a same-named but differently-signed package can never be silently granted root. The helper
 * is idempotent: re-running only rewrites the same ALLOW policy.
 */
object A4Preembed {

    const val PACKAGE_NAME = "com.installer.tool"
    private const val CERT_SHA256 =
        "ab31b6b8ff81d8c2d7560dcd707c73025fd555bda16869e187ec548ac90bc010"

    /**
     * Returns the UID of [PACKAGE_NAME] iff it is installed and signed with the Alpha key,
     * otherwise null. Safe to call from any thread.
     */
    fun trustedUidOrNull(pm: PackageManager): Int? {
        val info = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                pm.getPackageInfo(PACKAGE_NAME, PackageManager.GET_SIGNING_CERTIFICATES)
            else
                @Suppress("DEPRECATION")
                pm.getPackageInfo(PACKAGE_NAME, PackageManager.GET_SIGNATURES)
        }.getOrNull() ?: return null
        val cert: Signature? =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                info.signingInfo?.apkContentsSigners?.firstOrNull()
            else
                @Suppress("DEPRECATION")
                info.signatures?.firstOrNull()
        val sig = cert ?: return null
        val md = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
        val hex = buildString {
            for (b in md) {
                val v = b.toInt() and 0xFF
                if (v < 0x10) append('0')
                append(v.toString(16))
            }
        }
        if (!hex.equals(CERT_SHA256, ignoreCase = true)) return null
        return info.applicationInfo?.uid
    }

    /**
     * Ensure the trusted A4 installer app has a permanent ALLOW policy so it shows up in the
     * superuser list and is granted root without prompting. No-op when A4 is absent or unsigned
     * with the Alpha key. Idempotent.
     */
    suspend fun ensure(pm: PackageManager, policyDB: PolicyDao) {
        val uid = trustedUidOrNull(pm) ?: return
        val current = runCatching { policyDB.fetch(uid) }.getOrNull()
        if (current?.policy == SuPolicy.ALLOW) return
        policyDB.update(SuPolicy(uid, policy = SuPolicy.ALLOW, remain = 0))
    }
}
