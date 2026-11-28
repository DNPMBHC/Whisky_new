// SPDX-License-Identifier: GPL-3.0-or-later
// End-to-end automated Windows 11 ARM64 container deployment, v3.3 debloat injection, and offline qcow2 compaction.

import Combine
import Foundation

/// Orchestrates zero-redistribution Windows 11 ARM64 installation, v3.3 guest debloat/optimization,
/// and offline sparse qcow2 compaction for new and existing managed containers.
public final class ContainerAutoDeployService: ObservableObject, @unchecked Sendable {
    @Published public private(set) var steps: [AutoDeployStepReport]
    @Published public private(set) var isRunning: Bool = false
    @Published public private(set) var downloadProgress: WindowsImageDownloadProgress?
    @Published public private(set) var lastReport: AutoDeployReport?

    private let configuration: UnifiedOrchestratorConfiguration
    private let fileManager: FileManager
    private let commandRunner: UnifiedRuntimeOrchestrator.CommandRunner
    private let hardwareProfileProvider: @Sendable () -> HardwareProfileSnapshot
    private let bootstrapService: WindowsImageBootstrapService
    private let diskCompactor: ContainerDiskCompactor
    private let provisioningService: ContainerProvisioningService

    public init(
        configuration: UnifiedOrchestratorConfiguration = UnifiedOrchestratorConfiguration(),
        fileManager: FileManager = .default,
        commandRunner: UnifiedRuntimeOrchestrator.CommandRunner? = nil,
        hardwareProfileProvider: (@Sendable () -> HardwareProfileSnapshot)? = nil,
        bootstrapService: WindowsImageBootstrapService? = nil,
        diskCompactor: ContainerDiskCompactor? = nil,
        provisioningService: ContainerProvisioningService? = nil
    ) {
        let runner: UnifiedRuntimeOrchestrator.CommandRunner = commandRunner ?? { exe, args, env in
            try await OrchestratorProcessRunner.run(executable: exe, arguments: args, environment: env)
        }
        let hwProvider = hardwareProfileProvider ?? { HardwareAutoTuner().detectHardwareProfile() }
        self.configuration = configuration
        self.fileManager = fileManager
        self.commandRunner = runner
        self.hardwareProfileProvider = hwProvider
        let resolved = UnifiedRuntimeDiscovery.resolve(configuration: configuration, fileManager: fileManager)
        let helperApp = resolved.containerHelperBinaryPath.map {
            URL(filePath: $0).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().path(percentEncoded: false)
        }
        self.bootstrapService = bootstrapService ?? WindowsImageBootstrapService(commandRunner: runner)
        self.diskCompactor = diskCompactor ?? ContainerDiskCompactor(
            helperAppPath: helperApp, pythonExecutablePath: resolved.pythonExecutablePath, commandRunner: runner
        )
        self.provisioningService = provisioningService ?? ContainerProvisioningService(
            configuration: configuration, fileManager: fileManager,
            commandRunner: runner, hardwareProfileProvider: hwProvider
        )
        self.steps = Self.initialSteps()
    }

    /// Creates a compliant `.utm` container skeleton with sparse `qcow2` disk and mounted install media.
    public func createContainerSkeleton(
        at bundleURL: URL, diskSizeGiB: Int = 64, windowsISOURL: URL,
        bootstrapISOURL: URL, settings: UnifiedLaunchSettings = UnifiedLaunchSettings()
    ) async throws -> String {
        let standardized = bundleURL.standardizedFileURL
        guard standardized.pathExtension.lowercased() == "utm" else {
            throw UnifiedOrchestrationError.backendUnavailable("目标容器目录必须以 .utm 结尾。")
        }
        guard !ContainerProvisioningPipeline.isProtectedBundle(standardized, fileManager: fileManager) else {
            throw UnifiedOrchestrationError.backendUnavailable("目标名称不可使用受保护母盘或冷备名称。")
        }
        guard !fileManager.fileExists(atPath: standardized.path(percentEncoded: false)) else {
            throw UnifiedOrchestrationError.backendUnavailable("目标位置已存在同名容器，请更换名称或目录。")
        }
        let dataDir = standardized.appending(path: "Data", directoryHint: .isDirectory)
        try fileManager.createDirectory(at: dataDir, withIntermediateDirectories: true)
        do {
            let vmUUID = UUID().uuidString.uppercased()
            let diskUUID = UUID().uuidString.uppercased()
            try await diskCompactor.createSparseQCow2(
                at: dataDir.appending(path: "\(diskUUID).qcow2"), sizeGiB: diskSizeGiB
            )
            try await ContainerBootstrapPreflight.stageMediaFile(
                from: windowsISOURL,
                to: dataDir.appending(path: ContainerAutoDeployConfigBuilder.windowsInstallFilename),
                fileManager: fileManager, commandRunner: commandRunner
            )
            try await ContainerBootstrapPreflight.stageMediaFile(
                from: bootstrapISOURL,
                to: dataDir.appending(path: ContainerAutoDeployConfigBuilder.bootstrapFilename),
                fileManager: fileManager, commandRunner: commandRunner
            )
            let hardware = hardwareProfileProvider()
            let preset = UnifiedLaunchSettings.containerPreset(settings.presetTier, hardware: hardware)
            let cpuCount = settings.virtualCPUCount ?? preset.virtualCPUCount
            let fpsLimit = min(ContainerProvisioningConstants.fpsLimitDefault, max(60, hardware.displayRefreshRateHz))
            let queues = HardwareAutoTuner.recommendedVirtIOBlockQueues(forVCPUCount: cpuCount)
            let spec = ContainerAutoDeployConfigBuilder.Spec(
                vmUUID: vmUUID, diskUUID: diskUUID,
                containerName: standardized.deletingPathExtension().lastPathComponent,
                cpuCount: cpuCount, memoryMiB: settings.memoryMiB ?? preset.memoryMiB,
                fpsLimit: fpsLimit, virtioBlkQueues: queues
            )
            try ContainerAutoDeployConfigBuilder.writeSkeletonConfigAndMetadata(
                spec: spec, bundleURL: standardized, fileManager: fileManager
            )
            return vmUUID
        } catch {
            try? fileManager.removeItem(at: standardized)
            throw error
        }
    }

    public func ejectInstallMedia(in bundleURL: URL) throws {
        try ContainerAutoDeployConfigBuilder.ejectInstallMedia(in: bundleURL, fileManager: fileManager)
    }
    public func compactExistingContainer(at bundlePath: String) async throws -> ContainerDiskCompactionReport {
        try await diskCompactor.compactContainerSystemDisk(bundlePath: bundlePath, fileManager: fileManager)
    }
    public func deployNewContainer(request: AutoDeployRequest) async throws -> AutoDeployReport {
        await MainActor.run {
            self.isRunning = true
            self.downloadProgress = nil
            self.steps = Self.initialSteps()
        }
        defer {
            Task { @MainActor in
                self.isRunning = false
                self.downloadProgress = nil
            }
        }

        let resolved = UnifiedRuntimeDiscovery.resolve(configuration: configuration, fileManager: fileManager)
        let bundleURL = normalizedBundleURL(for: request)
        let bundlePath = bundleURL.path(percentEncoded: false)
        var currentSteps = Self.initialSteps()

        let isoURL = try await executeStage(
            .prepareWindowsImage, containerPath: bundlePath, steps: &currentSteps,
            runningDetail: "正在校验目标磁盘空间与官方 Windows 11 ARM64 镜像…"
        ) {
            let minFree: Int64 = request.minimumISOSizeBytes >= 1_073_741_824
                ? ContainerBootstrapPreflight.minimumNewContainerFreeBytes : 64 * 1_048_576
            try ContainerBootstrapPreflight.validateStorageTarget(
                directory: request.destinationDirectory, minimumFreeBytes: minFree, fileManager: self.fileManager
            )
            return try await self.prepareImage(request: request)
        }

        let bootstrapISO = try await executeStage(
            .buildBootstrapMedia, containerPath: bundlePath, steps: &currentSteps,
            runningDetail: "正在匹配镜像语言、准备 VirtIO 驱动并生成引导介质…"
        ) { try await self.buildBootstrapMedia(request: request, windowsISO: isoURL, resolved: resolved) }
        defer { try? fileManager.removeItem(at: bootstrapISO) }

        let vmUUID = try await executeStage(
            .createContainerSkeleton, containerPath: bundlePath, steps: &currentSteps,
            runningDetail: "正在创建 UEFI/TPM 2.0 容器与 \(request.diskSizeGiB) GiB 稀疏系统盘…"
        ) {
            let uuid = try await self.createContainerSkeleton(
                at: bundleURL, diskSizeGiB: request.diskSizeGiB,
                windowsISOURL: isoURL, bootstrapISOURL: bootstrapISO, settings: request.launchSettings
            )
            return (uuid, "容器骨架与稀疏系统盘创建完成（UUID: \(uuid.prefix(8))…）。")
        }

        let compaction = try await runInstallOptimizeAndCompact(
            bundleURL: bundleURL, vmUUID: vmUUID, resolved: resolved, request: request, steps: &currentSteps
        )
        return await finalizeReport(
            containerPath: bundlePath, vmUUID: vmUUID, steps: currentSteps, compaction: compaction
        )
    }
}

private extension ContainerAutoDeployService {
    func runInstallOptimizeAndCompact(
        bundleURL: URL, vmUUID: String, resolved: ResolvedRuntimePaths,
        request: AutoDeployRequest, steps: inout [AutoDeployStepReport]
    ) async throws -> ContainerDiskCompactionReport {
        let bundlePath = bundleURL.path(percentEncoded: false)
        _ = try await executeStage(
            .runUnattendedInstall, containerPath: bundlePath, steps: &steps,
            runningDetail: "已启动无人值守安装，等待 Windows 首登、驱动与 QGA 就绪…"
        ) {
            try await self.runUnattendedInstall(
                bundlePath: bundlePath, vmUUID: vmUUID, resolved: resolved, request: request
            )
            return ((), "Windows 11 ARM64 安装完成，QGA 与首次驱动注入已就绪。")
        }

        _ = try await executeStage(
            .injectOptimizationAndTrim, containerPath: bundlePath, steps: &steps,
            runningDetail: "正在执行 v3.3 精简（移除云同步/CompactOS/MPO与透明修复/高清模式/全屏光标桥接）…"
        ) {
            try await self.runProvisioningWithRebootRetry(
                bundlePath: bundlePath, vmUUID: vmUUID, resolved: resolved, request: request
            )
            return ((), "v3.3 系统精简、清晰渲染、全屏光标桥接与图形网络核验全部通过。")
        }

        return try await executeStage(
            .compactAndRegister, containerPath: bundlePath, steps: &steps,
            runningDetail: "正在优雅关机、卸载安装介质并执行离线 qcow2 磁盘瘦身…"
        ) {
            if let control = self.resolvedControlBinary(resolved: resolved) {
                try await ContainerBootstrapPreflight.gracefulShutdownAndWait(
                    controlBinary: control, vmUUID: vmUUID,
                    pollIntervalSeconds: request.pollIntervalSeconds, commandRunner: self.commandRunner
                )
            }
            try self.ejectInstallMedia(in: bundleURL)
            let report = try await self.diskCompactor.compactContainerSystemDisk(
                bundlePath: bundlePath, fileManager: self.fileManager
            )
            let msg = String(
                format: "已卸载安装镜像并瘦身：%.1f GiB → %.1f GiB（英文镜像联网后可在游戏库一键补齐中文输入法）。",
                report.beforeGiB, report.afterGiB
            )
            return (report, msg)
        }
    }

    static func initialSteps() -> [AutoDeployStepReport] {
        AutoDeployStage.allCases.map { AutoDeployStepReport(stage: $0, state: .pending, detail: "等待执行") }
    }

    func normalizedBundleURL(for request: AutoDeployRequest) -> URL {
        let trimmed = request.containerName.trimmingCharacters(in: .whitespacesAndNewlines)
        let baseName = trimmed.isEmpty ? "malt-win11-arm64" : trimmed
        let finalName = baseName.lowercased().hasSuffix(".utm") ? baseName : "\(baseName).utm"
        return request.destinationDirectory.standardizedFileURL.appending(path: finalName, directoryHint: .isDirectory)
    }

    func prepareImage(request: AutoDeployRequest) async throws -> (URL, String) {
        switch request.imageSource {
        case let .localISO(url):
            let res = try bootstrapService.validateWindowsARM64ISO(
                at: url, minimumSizeBytes: request.minimumISOSizeBytes, fileManager: fileManager
            )
            let sizeGiB = String(format: "%.2f", Double(res.sizeBytes) / 1_073_741_824.0)
            return (res.isoURL, "本地镜像校验通过（\(res.formatSignature)，\(sizeGiB) GiB）。")
        case let .officialDownloadURL(url, expectedSHA256):
            let downloaded = try await bootstrapService.downloadOfficialISO(
                from: url, expectedSHA256: expectedSHA256, fileManager: fileManager
            ) { [weak self] progress in Task { @MainActor in self?.downloadProgress = progress } }
            return (downloaded, "官方 Windows 11 ARM64 镜像已下载并校验通过。")
        }
    }

    func runProvisioningWithRebootRetry(
        bundlePath: String, vmUUID: String, resolved: ResolvedRuntimePaths, request: AutoDeployRequest
    ) async throws {
        let report: ContainerProvisioningReport
        do {
            report = try await provisioningService.provisionAndOptimize(
                containerPath: bundlePath, settings: request.launchSettings
            )
        } catch {
            guard request.pollIntervalSeconds >= 1.0,
                  let control = resolvedControlBinary(resolved: resolved) else { throw error }
            await ContainerBootstrapPreflight.rebootAndWaitForLogon(
                controlBinary: control, vmUUID: vmUUID, commandRunner: commandRunner
            )
            report = try await provisioningService.provisionAndOptimize(
                containerPath: bundlePath, settings: request.launchSettings
            )
        }
        if !report.allPassed { throw UnifiedOrchestrationError.commandFailed("容器内 v3.3 精简优化未全部通过核验。") }
    }

    func buildBootstrapMedia(
        request: AutoDeployRequest, windowsISO: URL, resolved: ResolvedRuntimePaths
    ) async throws -> (URL, String) {
        let effectiveConfig = ContainerBootstrapPreflight.resolvedUnattendedConfig(
            request.unattendedConfig, for: windowsISO, fileManager: fileManager
        )
        let requireDrivers = request.minimumISOSizeBytes >= 1_073_741_824
        let driver = try await ContainerBootstrapPreflight.resolveDriverDirectory(
            explicit: request.driverDirectory, beside: windowsISO,
            autoDownload: request.autoDownloadDrivers && requireDrivers, requireDrivers: requireDrivers,
            bootstrapService: bootstrapService, fileManager: fileManager
        ) { [weak self] progress in Task { @MainActor in self?.downloadProgress = progress } }
        var optimizerFiles = [resolved.optimizerApplyScriptPath, resolved.optimizerProfilePath]
            .compactMap { $0 }.map { URL(filePath: $0) }
        if let bridge = ContainerProvisioningGuestExecutor.siblingCursorBridgeURL(
            nextTo: resolved.optimizerApplyScriptPath, fileManager: fileManager
        ) { optimizerFiles.append(bridge) }
        let tempISO = fileManager.temporaryDirectory.appending(path: "malt-bootstrap-\(UUID().uuidString).iso")
        let built = try await bootstrapService.buildBootstrapISO(
            outputURL: tempISO, config: effectiveConfig,
            driverDirectory: driver.url, optimizerFiles: optimizerFiles, fileManager: fileManager
        )
        return (built, "已生成 MALTBOOT（镜像语言 \(effectiveConfig.setupUILanguage)，\(driver.sourceLabel)）。")
    }

    func resolvedControlBinary(resolved: ResolvedRuntimePaths) -> String? {
        if let explicit = configuration.containerControlBinaryURL {
            let path = explicit.path(percentEncoded: false)
            return fileManager.isExecutableFile(atPath: path) ? path : nil
        }
        guard let helper = resolved.containerHelperBinaryPath else { return nil }
        let path = URL(filePath: helper).deletingLastPathComponent()
            .appending(path: "utmctl").path(percentEncoded: false)
        return fileManager.isExecutableFile(atPath: path) ? path : nil
    }

    func runUnattendedInstall(
        bundlePath: String, vmUUID: String, resolved: ResolvedRuntimePaths, request: AutoDeployRequest
    ) async throws {
        guard let helperBinary = resolved.containerHelperBinaryPath,
              let controlBinary = resolvedControlBinary(resolved: resolved) else {
            throw UnifiedOrchestrationError.backendUnavailable("缺少内嵌容器引擎或 utmctl，无法执行自动安装。")
        }
        let helperApp = URL(filePath: helperBinary)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .path(percentEncoded: false)
        _ = try await commandRunner(
            "/usr/bin/open", ["-a", helperApp, bundlePath], ["__DEMOAPP_TIMEOUT_SECONDS": "15"]
        )
        for attempt in 0..<5 {
            let started = try? await commandRunner(
                controlBinary, ["start", "--hide", vmUUID], ["__DEMOAPP_TIMEOUT_SECONDS": "20"]
            )
            if started?.exitCode == 0 { break }
            if attempt < 4 { try await Task.sleep(nanoseconds: 1_500_000_000) }
        }
        if request.pollIntervalSeconds >= 1.0 {
            await ContainerBootstrapPreflight.triggerOpticalBootKeypresses(commandRunner: commandRunner)
        }
        let deadline = Date().addingTimeInterval(max(1, request.installTimeoutSeconds))
        let pollNanos = UInt64(max(0.05, request.pollIntervalSeconds) * 1_000_000_000)
        while Date() < deadline {
            try Task.checkCancellation()
            let probe = try? await commandRunner(
                controlBinary,
                [
                    "exec", "--hide", vmUUID, "--cmd", "cmd.exe", "/c",
                    "if exist C:\\ProgramData\\Malt\\bootstrap.done echo MALT_BOOTSTRAP_DONE"
                ],
                ["__DEMOAPP_TIMEOUT_SECONDS": "10"]
            )
            if let probe {
                try ContainerGuestDispatcher.requireAutomationAccess(probe)
                if probe.exitCode == 0 && probe.stdout.contains("MALT_BOOTSTRAP_DONE") {
                    if request.pollIntervalSeconds >= 1.0 {
                        await ContainerBootstrapPreflight.waitForInteractiveUserLogon(
                            controlBinary: controlBinary, vmUUID: vmUUID, commandRunner: commandRunner
                        )
                    }
                    return
                }
            }
            try await Task.sleep(nanoseconds: pollNanos)
        }
        throw UnifiedOrchestrationError.commandFailed("等待 Windows 11 无人值守安装与来宾工具就绪超时。")
    }

    func updateStep(
        _ stage: AutoDeployStage, state: ProvisioningStepState, detail: String, in steps: inout [AutoDeployStepReport]
    ) async {
        if let idx = steps.firstIndex(where: { $0.stage == stage }) {
            steps[idx] = AutoDeployStepReport(stage: stage, state: state, detail: detail)
        }
        let snapshot = steps
        await MainActor.run { self.steps = snapshot }
    }

    func executeStage<Value>(
        _ stage: AutoDeployStage, containerPath: String, steps: inout [AutoDeployStepReport],
        runningDetail: String, operation: () async throws -> (Value, String)
    ) async throws -> Value {
        await updateStep(stage, state: .running, detail: runningDetail, in: &steps)
        do {
            let (value, detail) = try await operation()
            await updateStep(stage, state: .succeeded, detail: detail, in: &steps)
            return value
        } catch {
            let msg = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            await updateStep(stage, state: .failed, detail: msg, in: &steps)
            let rep = AutoDeployReport(
                containerPath: containerPath, vmUUID: "", steps: steps, compactionReport: nil, allPassed: false
            )
            await MainActor.run { self.lastReport = rep }
            throw error
        }
    }

    func finalizeReport(
        containerPath: String, vmUUID: String, steps: [AutoDeployStepReport], compaction: ContainerDiskCompactionReport
    ) async -> AutoDeployReport {
        let rep = AutoDeployReport(
            containerPath: containerPath, vmUUID: vmUUID, steps: steps, compactionReport: compaction, allPassed: true
        )
        await MainActor.run {
            self.lastReport = rep
            self.isRunning = false
        }
        return rep
    }
}
