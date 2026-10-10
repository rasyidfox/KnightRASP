package io.knightrasp.internal

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import io.knightrasp.Rasp
import io.knightrasp.core.RaspRuntimeImpl
import io.knightrasp.nativebridge.NativeProbeImpl
import io.knightrasp.probe.android.AndroidProbes

/**
 * Menyambungkan [RaspRuntimeImpl] default ke [Rasp] saat proses aplikasi dimulai.
 *
 * Provider ini didaftarkan di manifest modul `rasp` dan berjalan sebelum
 * `Application.onCreate`, jadi aplikasi konsumen tidak perlu melakukannya sendiri.
 * Provider tidak mengekspos data apa pun (semua method kontrak mengembalikan nilai
 * kosong).
 */
class KnightRASPInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val appContext = context?.applicationContext ?: return false
        val probes = AndroidProbes(appContext, NativeProbeImpl.createOrNull())
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
