package io.knightrasp.internal

import io.knightrasp.check.RaspCheck
import io.knightrasp.check.debug.DebuggerFlagCheck
import io.knightrasp.check.debug.NativeDebuggerCheck
import io.knightrasp.check.debug.TracerPidCheck
import io.knightrasp.check.emulator.EmulatorFilesCheck
import io.knightrasp.check.emulator.EmulatorPropsCheck
import io.knightrasp.check.environment.AdbEnabledCheck
import io.knightrasp.check.environment.AccessibilityServicesCheck
import io.knightrasp.check.environment.DeveloperOptionsCheck
import io.knightrasp.check.environment.MockLocationCheck
import io.knightrasp.check.hook.FridaMapsCheck
import io.knightrasp.check.hook.FridaThreadsCheck
import io.knightrasp.check.hook.NativeHookCheck
import io.knightrasp.check.integrity.InstallerCheck
import io.knightrasp.check.integrity.NativeTextIntegrityCheck
import io.knightrasp.check.integrity.SdkLibraryOriginCheck
import io.knightrasp.check.integrity.SignatureCheck
import io.knightrasp.check.root.MagiskArtifactsCheck
import io.knightrasp.check.root.SuBinaryCheck
import io.knightrasp.check.root.TestKeysCheck
import io.knightrasp.check.virtualization.ClonerPackagesCheck
import io.knightrasp.check.virtualization.SuspiciousProcessNameCheck
import io.knightrasp.probe.Probes

/** Default check list along with its registration order. */
object DefaultChecks {

    fun list(probes: Probes): List<RaspCheck> = listOf(
        // Root
        SuBinaryCheck(probes.file),
        MagiskArtifactsCheck(probes.file, probes.packages),
        TestKeysCheck(probes.system),
        // Debug
        DebuggerFlagCheck(probes.system),
        TracerPidCheck(probes.proc),
        NativeDebuggerCheck(probes.native),
        // Emulator
        EmulatorPropsCheck(probes.system),
        EmulatorFilesCheck(probes.file),
        // Environment
        DeveloperOptionsCheck(probes.settings),
        AdbEnabledCheck(probes.settings),
        MockLocationCheck(probes.settings),
        AccessibilityServicesCheck(probes.system),
        // Hook
        FridaThreadsCheck(probes.proc),
        FridaMapsCheck(probes.proc),
        NativeHookCheck(probes.native),
        // Integrity
        SignatureCheck(probes.packages),
        InstallerCheck(probes.packages),
        NativeTextIntegrityCheck(probes.native),
        SdkLibraryOriginCheck(probes.proc, probes.packages, probes.native),
        // Virtualization
        ClonerPackagesCheck(probes.packages),
        SuspiciousProcessNameCheck(probes.proc),
    )
}
