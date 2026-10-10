package io.knightrasp.playintegrity

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest

/**
 * Klien Play Integrity (opsional).
 *
 * Verdict Play Integrity **hanya dapat diverifikasi di server**, jadi gateway ini hanya
 * mengambil token; aplikasi host wajib mengirim token tersebut ke backend-nya yang
 * lalu memanggil Google Play Integrity API untuk decrypt + verifikasi. Jangan
 * mempercayai keputusan apa pun di sisi klien.
 *
 * Syarat operasional:
 * - Aplikasi terdistribusi lewat Google Play, dan nomor Google Cloud project sudah
 *   terhubung ke aplikasi di Play Console.
 * - Gunakan `nonce` acak per permintaan (server yang membuat dan memverifikasi) untuk
 *   mencegah replay.
 *
 * Contoh alur:
 * ```
 * val gateway = PlayIntegrityGateway(context, cloudProjectNumber = 123456789012L)
 * gateway.requestToken(nonce = serverNonce) { token, error ->
 *     if (token != null) backend.verifyLogin(token) else log(error)
 * }
 * ```
 */
class PlayIntegrityGateway(
    context: Context,
    private val cloudProjectNumber: Long,
) {
    private val manager: IntegrityManager = IntegrityManagerFactory.create(context.applicationContext)

    /**
     * Meminta integrity token. Callback dipanggil di main thread (mengikuti perilaku
     * task Play Core).
     */
    fun requestToken(nonce: String? = null, callback: TokenCallback) {
        val builder = IntegrityTokenRequest.builder()
            .setCloudProjectNumber(cloudProjectNumber)
        nonce?.let { builder.setNonce(it) }

        manager.requestIntegrityToken(builder.build())
            .addOnSuccessListener { response -> callback.onResult(response.token(), null) }
            .addOnFailureListener { error -> callback.onResult(null, error) }
    }

    /** Callback Java-friendly: tepat salah satu dari [token]/[error] berisi nilai. */
    fun interface TokenCallback {
        fun onResult(token: String?, error: Throwable?)
    }
}
