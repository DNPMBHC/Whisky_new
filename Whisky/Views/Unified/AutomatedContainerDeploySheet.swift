// SPDX-License-Identifier: GPL-3.0-or-later
// Interactive modal sheet for one-click Windows 11 ARM64 container creation, v3.2 debloat, and disk compaction.

import AppKit
import SwiftUI
import UniformTypeIdentifiers
import WhiskyKit

/// Modal wizard guiding new users through legal Windows 11 ARM64 ISO selection/download,
/// unattended installation, v3.2 debloat/optimization injection, and offline sparse qcow2 compaction.
@MainActor
struct AutomatedContainerDeploySheet: View {
    enum SourceMode: String, CaseIterable, Identifiable {
        case localISO = "本地官方 ISO"
        case officialURL = "官方 HTTPS 直链"

        var id: String { rawValue }
    }

    @ObservedObject var orchestrator: UnifiedRuntimeOrchestrator
    @ObservedObject var preferences: UnifiedPreferencesModel
    let onDeployed: (AutoDeployReport) -> Void

    @Environment(\.dismiss) private var dismiss
    @StateObject private var deployService: ContainerAutoDeployService

    @State private var sourceMode: SourceMode = .localISO
    @State private var selectedISOURL: URL?
    @State private var officialURLString = ""
    @State private var expectedSHA256 = ""
    @State private var driverDirectoryURL: URL?
    @State private var autoDownloadDrivers = true
    @State private var detectedISOLanguage: String?
    @State private var destinationDirectoryURL: URL
    @State private var containerName = "malt-win11-arm64"
    @State private var diskSizeGiB = 64
    @State private var feedbackMessage: String?
    @State private var feedbackIsError = false
    private let hardwareSnapshot: HardwareProfileSnapshot

    init(
        orchestrator: UnifiedRuntimeOrchestrator,
        preferences: UnifiedPreferencesModel,
        onDeployed: @escaping (AutoDeployReport) -> Void
    ) {
        self.orchestrator = orchestrator
        self.preferences = preferences
        self.onDeployed = onDeployed
        self.hardwareSnapshot = HardwareAutoTuner().detectHardwareProfile()
        _deployService = StateObject(
            wrappedValue: ContainerAutoDeployService(configuration: orchestrator.configuration)
        )
        _driverDirectoryURL = State(
            initialValue: ContainerBootstrapPreflight.discoverLocalDriverSource(beside: nil)
        )
        let defaultDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
        _destinationDirectoryURL = State(
            initialValue: defaultDir.appending(path: "MaltContainers", directoryHint: .isDirectory)
        )
    }

    private var canStartDeploy: Bool {
        guard !deployService.isRunning else { return false }
        guard driverDirectoryURL != nil || autoDownloadDrivers else { return false }
        let trimmedName = containerName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else { return false }
        switch sourceMode {
        case .localISO:
            return selectedISOURL != nil
        case .officialURL:
            let trimmed = officialURLString.trimmingCharacters(in: .whitespacesAndNewlines)
            return URL(string: trimmed)?.scheme?.lowercased() == "https"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            headerSection
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    imageSourceSection
                    targetContainerSection
                    if deployService.isRunning || deployService.lastReport != nil {
                        AutoDeployProgressSection(deployService: deployService)
                    }
                    if let feedbackMessage {
                        AppStatusLabel(
                            text: feedbackMessage,
                            systemImage: feedbackIsError ? "exclamationmark.triangle" : "checkmark.circle",
                            tint: feedbackIsError ? .orange : .green
                        )
                        .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.trailing, 4)
            }
            Divider()
            footerActions
        }
        .padding(20)
        .frame(width: 620, height: 560)
    }

    private var headerSection: some View {
        let preset = UnifiedLaunchSettings.containerPreset(
            preferences.runtimeSettings.presetTier, hardware: hardwareSnapshot
        )
        let hostmem = HardwareAutoTuner.recommendedVirglHostmem(
            forPhysicalMemoryBytes: ProcessInfo.processInfo.physicalMemory
        )
        let chipLine = "当前本机自适应：\(hardwareSnapshot.chipName)（\(hardwareSnapshot.physicalMemoryGiB) GiB · "
            + "\(hardwareSnapshot.displayRefreshRateHz) Hz）→ \(preset.virtualCPUCount) vCPU / "
            + "\(preset.memoryMiB / 1024) GiB RAM / \(hostmem) 显存"
            + (detectedISOLanguage.map { " · 镜像语言 \($0)" } ?? "")
        return VStack(alignment: .leading, spacing: 6) {
            Text("一键创建并精简 Windows 11 ARM64 容器")
                .font(.title3.weight(.semibold))
            Text("Malt 不分发系统镜像，保留 Secure Boot / TPM 2.0，自动注入 VirtIO 驱动与 v3.3 优化（清晰渲染/全屏光标桥接/CompactOS）。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text(chipLine)
                .font(.caption2).foregroundStyle(.secondary)
            Link(destination: ContainerProvisioningService.officialWindowsARM64GuideURL()) {
                Label("打开微软官方 Windows 11 ARM64 下载页", systemImage: "arrow.up.right.square")
                    .font(.caption.weight(.medium))
            }
        }
    }

    private var imageSourceSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("1. 官方 Windows 11 ARM64 镜像来源")
                .font(.subheadline.weight(.medium))
            Picker("镜像来源", selection: $sourceMode) {
                ForEach(SourceMode.allCases) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(deployService.isRunning)

            if sourceMode == .localISO {
                HStack(spacing: 10) {
                    Text(selectedISOURL?.lastPathComponent ?? "尚未选择本地 .iso 镜像")
                        .font(.caption)
                        .foregroundStyle(selectedISOURL == nil ? .secondary : .primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("选择本地 ISO…", action: pickLocalISO)
                        .disabled(deployService.isRunning)
                }
                .padding(10)
                .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    TextField("粘贴微软官方 HTTPS .iso 下载直链", text: $officialURLString)
                        .textFieldStyle(.roundedBorder)
                        .disabled(deployService.isRunning)
                    TextField("可选：官方 SHA-256 校验值（留空跳过）", text: $expectedSHA256)
                        .textFieldStyle(.roundedBorder)
                        .disabled(deployService.isRunning)
                }
            }
        }
    }

    private var targetContainerSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("2. 容器保存位置与可选驱动包")
                .font(.subheadline.weight(.medium))
            HStack(spacing: 10) {
                TextField("容器名称", text: $containerName)
                    .textFieldStyle(.roundedBorder)
                    .disabled(deployService.isRunning)
                Picker("虚拟盘上限", selection: $diskSizeGiB) {
                    Text("64 GiB（推荐稀疏）").tag(64)
                    Text("96 GiB（稀疏）").tag(96)
                    Text("128 GiB（稀疏）").tag(128)
                }
                .frame(width: 170)
                .disabled(deployService.isRunning)
            }
            HStack(spacing: 10) {
                Text("保存目录：\(destinationDirectoryURL.lastPathComponent)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer()
                Button("更改目录…", action: pickDestinationDirectory)
                    .disabled(deployService.isRunning)
            }
            HStack(spacing: 10) {
                Text(driverDirectoryURL.map { "驱动包：\($0.lastPathComponent)" }
                     ?? (autoDownloadDrivers ? "将自动下载并缓存开源官方 VirtIO 驱动包" : "未选择 VirtIO / viogpu3d 驱动包"))
                    .font(.caption)
                    .foregroundStyle(driverDirectoryURL == nil && !autoDownloadDrivers ? .orange : .secondary)
                    .lineLimit(1)
                Spacer()
                if driverDirectoryURL != nil {
                    Button("清除") { driverDirectoryURL = nil }.disabled(deployService.isRunning)
                }
                Button("选择驱动包…", action: pickDriverDirectory).disabled(deployService.isRunning)
            }
            if driverDirectoryURL == nil {
                Toggle("自动下载开源官方 VirtIO / QGA 驱动包（推荐，首次下载后本地缓存）", isOn: $autoDownloadDrivers)
                    .font(.caption2).disabled(deployService.isRunning)
            }
        }
        .padding(12)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }

    private var footerActions: some View {
        HStack {
            Button(deployService.lastReport?.allPassed == true ? "完成" : "关闭") {
                dismiss()
            }
            .disabled(deployService.isRunning)
            Spacer()
            Button(action: startAutomatedDeploy) {
                HStack(spacing: 6) {
                    if deployService.isRunning {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "sparkles")
                    }
                    Text(deployService.isRunning ? "正在全自动部署…" : "开始一键创建与瘦身")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!canStartDeploy)
        }
    }
}

private extension AutomatedContainerDeploySheet {
    func pickLocalISO() {
        let panel = NSOpenPanel()
        panel.title = "选择官方 Windows 11 ARM64 ISO 镜像"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if let isoType = UTType(filenameExtension: "iso") {
            panel.allowedContentTypes = [isoType]
        }
        if panel.runModal() == .OK, let url = panel.url {
            selectedISOURL = url
            detectedISOLanguage = ContainerBootstrapPreflight.detectSetupUILanguage(for: url)
            if driverDirectoryURL == nil {
                driverDirectoryURL = ContainerBootstrapPreflight.discoverLocalDriverSource(beside: url)
            }
        }
    }

    func pickDestinationDirectory() {
        let panel = NSOpenPanel()
        panel.title = "选择容器保存目录（建议使用高速 SSD）"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            destinationDirectoryURL = url
        }
    }

    func pickDriverDirectory() {
        let panel = NSOpenPanel()
        panel.title = "选择 VirtIO / viogpu3d / QGA 驱动目录或驱动 ISO"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        if let isoType = UTType(filenameExtension: "iso") {
            panel.allowedContentTypes = [isoType, .folder]
        }
        if panel.runModal() == .OK, let url = panel.url {
            driverDirectoryURL = url
        }
    }

    func startAutomatedDeploy() {
        feedbackMessage = nil
        feedbackIsError = false
        let imageSource: AutoDeployImageSource
        switch sourceMode {
        case .localISO:
            guard let isoURL = selectedISOURL else { return }
            imageSource = .localISO(isoURL)
        case .officialURL:
            let trimmed = officialURLString.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let remoteURL = URL(string: trimmed) else { return }
            let hash = expectedSHA256.trimmingCharacters(in: .whitespacesAndNewlines)
            imageSource = .officialDownloadURL(remoteURL, expectedSHA256: hash.isEmpty ? nil : hash)
        }

        let request = AutoDeployRequest(
            imageSource: imageSource,
            destinationDirectory: destinationDirectoryURL,
            containerName: containerName,
            diskSizeGiB: diskSizeGiB,
            driverDirectory: driverDirectoryURL,
            autoDownloadDrivers: autoDownloadDrivers,
            launchSettings: preferences.runtimeSettings
        )
        Task {
            do {
                let report = try await deployService.deployNewContainer(request: request)
                _ = try? await orchestrator.importPlayableContainer(
                    at: URL(filePath: report.containerPath), confirmedStopped: true
                )
                await MainActor.run {
                    feedbackIsError = false
                    if let compact = report.compactionReport {
                        let msg = String(
                            format: "容器创建与瘦身完成（%.1f GiB → %.1f GiB），已自动登记为当前受管容器。",
                            compact.beforeGiB, compact.afterGiB
                        )
                        feedbackMessage = msg
                    } else {
                        feedbackMessage = "容器创建与优化完成，已自动登记为当前受管容器。"
                    }
                    onDeployed(report)
                }
            } catch {
                await MainActor.run {
                    feedbackIsError = true
                    feedbackMessage = InstalledGameDiscoverySection.redactedMessage(error.localizedDescription)
                }
            }
        }
    }
}

@MainActor
private struct AutoDeployProgressSection: View {
    @ObservedObject var deployService: ContainerAutoDeployService

    private var completedCount: Int {
        deployService.steps.filter { $0.state == .succeeded || $0.state == .skipped }.count
    }

    private var progressFraction: Double {
        guard !deployService.steps.isEmpty else { return 0 }
        return Double(completedCount) / Double(deployService.steps.count)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("自动化部署进度").font(.subheadline.weight(.medium))
                Spacer()
                Text("\(completedCount) / \(deployService.steps.count)")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            ProgressView(value: progressFraction, total: 1.0).progressViewStyle(.linear)

            if let download = deployService.downloadProgress, download.expectedBytes > 0 {
                let receivedGiB = Double(download.receivedBytes) / 1_073_741_824.0
                let totalGiB = Double(download.expectedBytes) / 1_073_741_824.0
                VStack(alignment: .leading, spacing: 4) {
                    ProgressView(value: download.fractionCompleted, total: 1.0).progressViewStyle(.linear)
                    Text(String(format: "正在下载官方镜像：%.2f / %.2f GiB", receivedGiB, totalGiB))
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                ForEach(deployService.steps) { step in
                    HStack(alignment: .top, spacing: 8) {
                        stepIcon(for: step.state).padding(.top, 2)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(step.stage.displayTitle).font(.caption.weight(.semibold))
                            Text(InstalledGameDiscoverySection.redactedMessage(step.detail))
                                .font(.caption2).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                    }
                }
            }
            .padding(10)
            .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    @ViewBuilder
    private func stepIcon(for state: ProvisioningStepState) -> some View {
        switch state {
        case .pending: Image(systemName: "circle.dashed").foregroundStyle(.secondary)
        case .running: ProgressView().controlSize(.mini)
        case .succeeded, .skipped: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .failed: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        }
    }
}
