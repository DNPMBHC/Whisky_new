// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation

/// The guest display policy is independent of the host window's point size and DPI.
public enum UnifiedDisplayPolicy: Equatable, Sendable {
    case automatic
    case fixed(width: Int, height: Int)

    public static func fixedResolution(_ value: String) -> UnifiedDisplayPolicy? {
        let parts = value.lowercased().replacingOccurrences(of: "×", with: "x").split(separator: "x")
        guard parts.count == 2, let width = Int(parts[0]), let height = Int(parts[1]),
              GuestDisplayResolutionPolicy.allowedWidthRange.contains(width),
              GuestDisplayResolutionPolicy.allowedHeightRange.contains(height) else { return nil }
        return .fixed(width: width, height: height)
    }
}

/// DirectX translation backend & optional host MetalFX upscaling for the Windows container.
public enum ContainerGraphicsBackend: String, CaseIterable, Codable, Equatable, Sendable {
    case dxmt
    case d3dMetal
    case dxmtMetalFXQuality
    case dxmtMetalFXPerformance

    public var displayName: String {
        switch self {
        case .dxmt: return "DXMT（原生）"
        case .d3dMetal: return "D3DMetal（Apple 官方，抗扣帧）"
        case .dxmtMetalFXQuality: return "DXMT + MetalFX 1.25×（画质超分）"
        case .dxmtMetalFXPerformance: return "DXMT + MetalFX 1.50×（性能超分）"
        }
    }

    public var utmBackendValue: String {
        switch self {
        case .d3dMetal: return "d3dmetal"
        case .dxmt, .dxmtMetalFXQuality, .dxmtMetalFXPerformance: return "dxmt"
        }
    }

    public var metalFXUpscaleFactor: String {
        switch self {
        case .dxmtMetalFXQuality: return "1.25"
        case .dxmtMetalFXPerformance: return "1.50"
        case .dxmt, .d3dMetal: return "0"
        }
    }
}

/// Host Metal scanout presentation architecture for the Windows container.
public enum ContainerDisplayPresentMode: String, CaseIterable, Codable, Equatable, Sendable {
    case ringMailbox = "ring"
    case immediateZeroCopy = "immediate"
    case legacy

    public var displayName: String {
        switch self {
        case .ringMailbox: return "Ring Mailbox 3槽独立队列（推荐，零撕裂解耦 VSync）"
        case .immediateZeroCopy: return "Immediate 极限零拷贝（最低延迟，允许轻微撕裂）"
        case .legacy: return "Legacy 兼容模式"
        }
    }
}

/// An immutable snapshot: callers cannot change a running launch by changing preferences.
public struct UnifiedLaunchSettings: Equatable, Sendable {
    public let presetTier: PerformancePresetTier
    public let enableMouseCoalescing: Bool
    public let blockAccidentalShortcuts: Bool
    public let enableKeyMapping: Bool
    public let enablePersistentCache: Bool
    public let enablePerformanceTelemetryLogging: Bool
    public let displayPolicy: UnifiedDisplayPolicy
    public let virtualCPUCount: Int?
    public let memoryMiB: Int?
    public let graphicsBackend: ContainerGraphicsBackend
    public let displayPresentMode: ContainerDisplayPresentMode
    public let enableHVFTSO: Bool
    public let enableNeptuneProfiler: Bool
    public let enableRawMouseInput: Bool

    public init(
        presetTier: PerformancePresetTier = .balanced,
        enableMouseCoalescing: Bool = true,
        blockAccidentalShortcuts: Bool = true,
        enableKeyMapping: Bool = true,
        enablePersistentCache: Bool = true,
        enablePerformanceTelemetryLogging: Bool = false,
        displayPolicy: UnifiedDisplayPolicy = .automatic,
        virtualCPUCount: Int? = nil,
        memoryMiB: Int? = nil,
        graphicsBackend: ContainerGraphicsBackend = .dxmt,
        displayPresentMode: ContainerDisplayPresentMode = .ringMailbox,
        enableHVFTSO: Bool = false,
        enableNeptuneProfiler: Bool = false,
        enableRawMouseInput: Bool = true
    ) {
        self.presetTier = presetTier
        self.enableMouseCoalescing = enableMouseCoalescing
        self.blockAccidentalShortcuts = blockAccidentalShortcuts
        self.enableKeyMapping = enableKeyMapping
        self.enablePersistentCache = enablePersistentCache
        self.enablePerformanceTelemetryLogging = enablePerformanceTelemetryLogging
        self.displayPolicy = displayPolicy
        self.virtualCPUCount = virtualCPUCount
        self.memoryMiB = memoryMiB
        self.graphicsBackend = graphicsBackend
        self.displayPresentMode = displayPresentMode
        self.enableHVFTSO = enableHVFTSO
        self.enableNeptuneProfiler = enableNeptuneProfiler
        self.enableRawMouseInput = enableRawMouseInput
    }

    /// Legacy values remain readable; an absent resource key means keep the VM configuration.
    public static func load(defaults: UserDefaults = .standard) -> UnifiedLaunchSettings {
        let tier = defaults.string(forKey: "unifiedSelectedTier")
            .flatMap(PerformancePresetTier.from(rawOrLegacy:)) ?? .balanced
        let display: UnifiedDisplayPolicy
        if defaults.string(forKey: "unifiedDisplayMode") == "fixed" {
            display = UnifiedDisplayPolicy.fixedResolution(
                defaults.string(forKey: "unifiedRecommendedResolution") ?? "1920x1080"
            ) ?? .automatic
        } else {
            display = .automatic
        }
        let backend = defaults.string(forKey: "unifiedContainerGraphicsBackend")
            .flatMap(ContainerGraphicsBackend.init(rawValue:)) ?? .dxmt
        let presentMode = defaults.string(forKey: "unifiedContainerDisplayPresentMode")
            .flatMap(ContainerDisplayPresentMode.init(rawValue:)) ?? .ringMailbox
        return UnifiedLaunchSettings(
            presetTier: tier,
            enableMouseCoalescing: defaults.object(forKey: "unifiedEnableMouseCoalescing") as? Bool ?? true,
            blockAccidentalShortcuts: defaults.object(forKey: "unifiedBlockAccidentalShortcuts") as? Bool ?? true,
            enableKeyMapping: defaults.object(forKey: "unifiedEnableKeyMapping") as? Bool ?? true,
            enablePersistentCache: defaults.object(forKey: "unifiedEnablePersistentCache") as? Bool ?? true,
            enablePerformanceTelemetryLogging: defaults.object(
                forKey: "unifiedEnablePerformanceTelemetryLogging"
            ) as? Bool ?? false,
            displayPolicy: display,
            virtualCPUCount: boundedPersistedInteger("unifiedRecommendedVCPU", maximum: 1024, defaults: defaults),
            memoryMiB: boundedPersistedInteger("unifiedRecommendedRAMMiB", maximum: 1_048_576, defaults: defaults),
            graphicsBackend: backend,
            displayPresentMode: presentMode,
            enableHVFTSO: defaults.object(forKey: "unifiedEnableHVFTSO") as? Bool ?? false,
            enableNeptuneProfiler: defaults.object(forKey: "unifiedEnableNeptuneProfiler") as? Bool ?? false,
            enableRawMouseInput: defaults.object(forKey: "unifiedEnableRawMouseInput") as? Bool ?? true
        )
    }

    private static func boundedPersistedInteger(
        _ key: String, maximum: Int, defaults: UserDefaults
    ) -> Int? {
        guard let value = defaults.object(forKey: key) as? Int else { return nil }
        return min(max(value, 1), maximum)
    }

    /// Validated RAM tiers across all Apple Silicon Macs (8 GiB to 128+ GiB).
    public static func supportedContainerMemoryOptionsGiB(for hardware: HardwareProfileSnapshot) -> [Int] {
        HardwareAutoTuner.safeMemoryOptionsGiB(for: hardware).filter { [4, 6, 8, 10, 12, 16, 20].contains($0) }
    }

    public static func containerPreset(
        _ tier: PerformancePresetTier, hardware: HardwareProfileSnapshot
    ) -> (virtualCPUCount: Int, memoryMiB: Int) {
        let cpu = HardwareAutoTuner.safeVCPUOptions(for: hardware)
        let memory = supportedContainerMemoryOptionsGiB(for: hardware)
        let recommendedCPU = HardwareAutoTuner.recommendedVCPUCount(for: hardware)
        let recommendedRAM = HardwareAutoTuner.recommendedMemoryGiB(for: hardware)
        switch tier {
        case .lowSpecCompatible:
            return (cpu.first ?? 2, (memory.first ?? 4) * 1024)
        case .balanced:
            return (
                cpu.min(by: { abs($0 - recommendedCPU) < abs($1 - recommendedCPU) }) ?? 2,
                (memory.min(by: { abs($0 - recommendedRAM) < abs($1 - recommendedRAM) }) ?? 4) * 1024
            )
        case .maxPerformance:
            return (cpu.last ?? 2, (memory.last ?? 6) * 1024)
        }
    }

    public func resolved(for entry: UnifiedGameEntry, hardware: HardwareProfileSnapshot) -> UnifiedLaunchSettings {
        guard entry.engineKind == .antiCheatVM, entry.inheritsGlobalPerformanceSettings == false else { return self }
        let resources = Self.containerPreset(entry.presetTier, hardware: hardware)
        return UnifiedLaunchSettings(
            presetTier: entry.presetTier, enableMouseCoalescing: enableMouseCoalescing,
            blockAccidentalShortcuts: blockAccidentalShortcuts, enableKeyMapping: enableKeyMapping,
            enablePersistentCache: enablePersistentCache,
            enablePerformanceTelemetryLogging: enablePerformanceTelemetryLogging,
            displayPolicy: displayPolicy,
            virtualCPUCount: resources.virtualCPUCount, memoryMiB: resources.memoryMiB,
            graphicsBackend: graphicsBackend,
            displayPresentMode: displayPresentMode,
            enableHVFTSO: enableHVFTSO,
            enableNeptuneProfiler: enableNeptuneProfiler,
            enableRawMouseInput: enableRawMouseInput
        )
    }

    /// The helper consumes these names. The mouse setting batches events, never changes USB polling.
    public var containerEnvironment: [String: String] {
        // When Raw Input (GCMouse) + CSInput lock-free adaptive coalescing is enabled, disable the
        // legacy 1.5ms main-thread timer so motion dispatches with 0us idle latency.
        let legacyTimerUs = (!enableRawMouseInput && enableMouseCoalescing) ? "1500" : "0"
        // Adaptive virgl hostmem across all Apple Silicon Macs: 2G (8 GiB), 4G (12-18 GiB), 8G (24+ GiB)
        let hostmemSize = HardwareAutoTuner.recommendedVirglHostmem(
            forPhysicalMemoryBytes: ProcessInfo.processInfo.physicalMemory
        )
        var env: [String: String] = [
            "UTM_MOUSE_COALESCE_US": legacyTimerUs,
            "UTM_RAW_MOUSE_INPUT": enableRawMouseInput ? "1" : "0",
            "UTM_GAME_SHELL_KEY_GUARD": blockAccidentalShortcuts ? "1" : "0",
            "UTM_BLOCK_WIN_KEY": enableKeyMapping ? "1" : "0",
            "UTM_DXMT_SHADER_CACHE_ENABLED": enablePersistentCache ? "1" : "0",
            "UTM_KEEP_CURSOR_VISIBLE_ON_INHIBIT": "1",
            "UTM_PURE_RELATIVE_MOUSE": "1",
            "UTM_METAL_DRAWABLE_COUNT": "3",
            "UTM_MAX_INFLIGHT_FRAMES": "3",
            "UTM_DIRECTX_BACKEND": graphicsBackend.utmBackendValue,
            "UTM_DXMT_METALFX_FACTOR": graphicsBackend.metalFXUpscaleFactor,
            "UTM_DISPLAY_PRESENT_MODE": displayPresentMode.rawValue,
            "UTM_HVF_TSO": enableHVFTSO ? "1" : "0",
            "UTM_HVF_KERNEL_IRQCHIP": "1",
            "UTM_DISABLE_USB_REDIR": "1",
            "UTM_DISABLE_SCREENSHOT": "1",
            "UTM_VIRGL_HOSTMEM": hostmemSize,
            "UTM_QCOW2_L2_CACHE": "1",
            "UTM_PER_DISK_IOTHREAD": "1"
        ]
        if enableNeptuneProfiler || enablePerformanceTelemetryLogging {
            env["UTM_NPT_PROFILE_PERIOD_MS"] = "5000"
            env["UTM_NEPTUNE_PROFILE_LOG"] = GameTelemetryCollector
                .neptuneProfileLogURL()
                .path(percentEncoded: false)
        }
        return env
    }

    func applyingWineCachePolicy(to environment: [String: String]) -> [String: String] {
        var result = environment
        result["DXMT_SHADER_CACHE"] = enablePersistentCache ? "1" : "0"
        result["DXVK_STATE_CACHE"] = enablePersistentCache ? "1" : "0"
        if !enablePersistentCache {
            result.removeValue(forKey: "DXMT_SHADER_CACHE_PATH")
            result.removeValue(forKey: "DXVK_STATE_CACHE_PATH")
        }
        return result
    }
}
