package io.knightrasp.playintegrity

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest

/**
 * Play Integrity client (optional).
 *
 * A Play Integrity verdict **can only be verified on the server**, so this gateway only
 * obtains the token; the host app must send that token to its backend, which
 * then calls the Google Play Integrity API to decrypt + verify. Do not
 * trust any verdict on the client side.
 *
 * Operational requirements:
 * - The app is distributed through Google Play, and the Google Cloud project number is
 *   linked to the app in the Play Console.
 * - Use a random `nonce` per request (created and verified by the server) to
 *   prevent replay.
 *
 * Example flow:
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
     * Requests an integrity token. The callback is invoked on the main thread (following
     * Play Core task behavior).
     */
    fun requestToken(nonce: String? = null, callback: TokenCallback) {
        val builder = IntegrityTokenRequest.builder()
            .setCloudProjectNumber(cloudProjectNumber)
        nonce?.let { builder.setNonce(it) }

        manager.requestIntegrityToken(builder.build())
            .addOnSuccessListener { response -> callback.onResult(response.token(), null) }
            .addOnFailureListener { error -> callback.onResult(null, error) }
    }

    /** Java-friendly callback: exactly one of [token]/[error] holds a value. */
    fun interface TokenCallback {
        fun onResult(token: String?, error: Throwable?)
    }
}
