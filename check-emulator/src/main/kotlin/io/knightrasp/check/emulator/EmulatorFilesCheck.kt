package io.knightrasp.check.emulator

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.FileProbe

/** File device khas emulator QEMU/Genymotion. */
class EmulatorFilesCheck(private val files: FileProbe) : RaspCheck {

    override val id = "emulator.files"
    override val category = Category.EMULATOR
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val found = EMULATOR_PATHS.filter(files::exists)
        return if (found.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(found.map { Evidence(id, CONFIDENCE, it) })
        }
    }

    companion object {
        const val CONFIDENCE = 0.5f

        val EMULATOR_PATHS = listOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
            "/sys/qemu_trace",
            "/system/bin/qemud",
        )
    }
}
