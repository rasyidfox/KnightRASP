package io.knightrasp.internal

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import io.knightrasp.Rasp
import io.knightrasp.core.RaspRuntimeImpl
import io.knightrasp.nativebridge.JniBridge
import io.knightrasp.probe.android.AndroidProbes

/**
 * Attaches the default [RaspRuntimeImpl] to [Rasp] when the app process starts.
 *
 * This provider is registered in the `rasp` module manifest and runs before
 * `Application.onCreate`, so consumer apps do not need to do it themselves.
 * The provider exposes no data (all contract methods return empty
 * values).
 */
class KnightRASPInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val appContext = context?.applicationContext ?: return false
        val probes = AndroidProbes(appContext, JniBridge.createOrNull())
        Rasp.attachRuntime(RaspRuntimeImpl(probes, DefaultChecks.list(probes)))
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
