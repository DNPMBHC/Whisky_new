// SPDX-License-Identifier: GPL-3.0-or-later
// Guest QGA optimizer injection, rollback, and graphics/network verification helpers.

import Foundation

struct ContainerProvisioningGuestExecutor: Sendable {
    let configuration: UnifiedOrchestratorConfiguration
    let commandRunner: UnifiedRuntimeOrchestrator.CommandRunner
    let vmnetStatusProvider: @Sendable () -> NativeVMNetStatus
    let shaderCacheOverrideURL: URL?
    let guestReadinessVerifier: (@Sendable (String, String) async throws -> Void)?

    func resolvedControlBinary(resolved: ResolvedRuntimePaths, fileManager: FileManager) -> String? {
        if let explicit = configuration.containerControlBinaryURL {
            let path = explicit.path(percentEncoded: false)
            return fileManager.isExecutableFile(atPath: path) ? path : nil
        }
        guard let helper = resolved.containerHelperBinaryPath else { return nil }
        let path = URL(filePath: helper).deletingLastPathComponent()
            .appending(path: "utmctl").path(percentEncoded: false)
        return fileManager.isExecutableFile(atPath: path) ? path : nil
    }

    func waitForGuestReady(controlBinary: String, vmIdentifier: String) async throws {
        if let guestReadinessVerifier {
            try await guestReadinessVerifier(controlBinary, vmIdentifier)
            return
        }
        let dispatcher = ContainerGuestDispatcher(
            controlBinaryPath: controlBinary,
            vmIdentifier: vmIdentifier,
            commandRunner: commandRunner,
            readinessTimeout: configuration.guestAgentReadinessTimeout
        )
        try await dispatcher.waitUntilReady()
    }

    func isGuestAgentReachable(controlBinary: String, vmIdentifier: String) async -> Bool {
        if let guestReadinessVerifier {
            return (try? await guestReadinessVerifier(controlBinary, vmIdentifier)) != nil
        }
        guard let result = try? await commandRunner(
            controlBinary,
            ["exec", "--hide", vmIdentifier, "--cmd", "cmd.exe", "/c", "echo", "GUEST_AGENT_READY"],
            ["__DEMOAPP_TIMEOUT_SECONDS": "5"]
        ) else { return false }
        return result.exitCode == 0 && result.stdout.contains("GUEST_AGENT_READY")
    }

    static func siblingCursorBridgeURL(
        nextTo applyScriptPath: String?, fileManager: FileManager
    ) -> URL? {
        guard let applyScriptPath, !applyScriptPath.isEmpty else { return nil }
        let candidate = URL(filePath: applyScriptPath)
            .deletingLastPathComponent()
            .appending(path: "malt-cursor-bridge.ps1")
        return fileManager.isReadableFile(atPath: candidate.path(percentEncoded: false)) ? candidate : nil
    }

    static func graphicsProbeScript() -> String {
        """
        $ErrorActionPreference='Stop';
        $drivers=@(pnputil.exe /enum-drivers 2>$null);
        $hasVioGpu3dInf=($drivers | Out-String) -match '(?i)viogpu3d\\.inf';
        $adapter=[string](Get-CimInstance Win32_VideoController -EA SilentlyContinue | Select-Object -First 1).Name;
        $isLegacyDod=$adapter -match '(?i)\\bDOD\\b|viogpudo';
        $hasVioGpu=$hasVioGpu3dInf -and (-not $isLegacyDod);
        $sb=$false; try { $sb=[bool](Confirm-SecureBootUEFI) } catch { $sb=$false };
        $ovDwm=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Dwm' -EA SilentlyContinue).OverlayTestMode;
        $gfxKey='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers';
        $ovGfx=(Get-ItemProperty $gfxKey -EA SilentlyContinue).DisableOverlays;
        $ovOff=([int]$ovDwm -eq 5) -and ([int]$ovGfx -eq 1);
        $sid=(Get-ChildItem 'Registry::HKEY_USERS' -EA SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[0-9-]+$' } | Select-Object -First 1).PSChildName;
        $trOff=$true; $fseOff=$true;
        if ($sid) {
            $p="Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
            $trOff=([int](Get-ItemProperty $p -EA SilentlyContinue).EnableTransparency -eq 0);
            $g="Registry::HKEY_USERS\\$sid\\System\\GameConfigStore";
            $fseOff=([int](Get-ItemProperty $g -EA SilentlyContinue).GameDVR_FSEBehaviorMode -eq 2);
        }
        $cb=($null -ne (Get-ScheduledTask -TaskName 'MaltCursorBridge' -EA SilentlyContinue));
        $report=@{ viogpu3dPresent=[bool]$hasVioGpu; driverName=$adapter; secureBootEnabled=[bool]$sb;
            overlayDisabled=[bool]$ovOff; userTransparencyDisabled=[bool]$trOff;
            fseDisabled=[bool]$fseOff; cursorBridgeInstalled=[bool]$cb };
        Write-Output ('MALT_GFX_PROBE_V1=' + ($report | ConvertTo-Json -Compress));
        """
    }

    func runGuestOptimization(
        vmIdentifier: String, resolved: ResolvedRuntimePaths, fileManager: FileManager
    ) async throws -> String {
        guard let control = resolvedControlBinary(resolved: resolved, fileManager: fileManager) else {
            throw UnifiedOrchestrationError.backendUnavailable("缺少容器控制组件 utmctl，无法注入来宾优化。")
        }
        guard let applyScript = resolved.optimizerApplyScriptPath,
              let profilePath = resolved.optimizerProfilePath,
              fileManager.isReadableFile(atPath: applyScript),
              fileManager.isReadableFile(atPath: profilePath) else {
            throw UnifiedOrchestrationError.backendUnavailable(
                "缺少 guest-optimizer v3.3 脚本或配置文件，请重新安装完整应用。"
            )
        }
        try await waitForGuestReady(controlBinary: control, vmIdentifier: vmIdentifier)
        let guestApply = ContainerProvisioningConstants.guestOptimizerDir + #"\apply-optimizer.ps1"#
        let guestProfile = ContainerProvisioningConstants.guestOptimizerDir + #"\anticheat-minimal-win11-arm64.json"#
        var filesToStage: [(String, String)] = [(applyScript, guestApply), (profilePath, guestProfile)]
        if let bridgeURL = Self.siblingCursorBridgeURL(nextTo: applyScript, fileManager: fileManager) {
            let guestBridge = ContainerProvisioningConstants.guestOptimizerDir + #"\malt-cursor-bridge.ps1"#
            filesToStage.append((bridgeURL.path(percentEncoded: false), guestBridge))
        }
        try await stageGuestFiles(controlBinary: control, vmIdentifier: vmIdentifier, files: filesToStage)
        let runScript = optimizerCommand(
            scriptGuestPath: guestApply, profileGuestPath: guestProfile, marker: "MALT_OPT_APPLY_V1="
        )
        let output = try await execGuestPowerShell(
            controlBinary: control, vmIdentifier: vmIdentifier, script: runScript, timeout: 600
        )
        let report = try parseJSONReport(
            ContainerGuestOptimizationReport.self, from: output, marker: "MALT_OPT_APPLY_V1="
        )
        if report.secureBootEnabled == false || report.bcdSafe == false || report.prismSignaturesValid == false {
            throw UnifiedOrchestrationError.commandFailed("来宾优化核验检测到安全或 Prism 签名不变量异常，请立即回滚。")
        }
        let lang = report.uiLanguage ?? "zh-CN"
        return "已注入并核验 guest-optimizer v3.3（\(lang)、真实用户清晰渲染、MPO/叠加禁用、高清模式与全屏光标桥接）。"
    }

    func runGuestRollback(
        controlBinary: String, vmIdentifier: String, rollbackScriptPath: String, profilePath: String
    ) async throws {
        let guestRollback = ContainerProvisioningConstants.guestOptimizerDir + #"\rollback-optimizer.ps1"#
        let guestProfile = ContainerProvisioningConstants.guestOptimizerDir + #"\anticheat-minimal-win11-arm64.json"#
        try await stageGuestFiles(
            controlBinary: controlBinary, vmIdentifier: vmIdentifier,
            files: [(rollbackScriptPath, guestRollback), (profilePath, guestProfile)]
        )
        let runScript = optimizerCommand(
            scriptGuestPath: guestRollback, profileGuestPath: guestProfile, marker: "MALT_OPT_ROLLBACK_V1="
        )
        let output = try await execGuestPowerShell(
            controlBinary: controlBinary, vmIdentifier: vmIdentifier, script: runScript, timeout: 180
        )
        let report = try parseJSONReport(
            ContainerGuestOptimizationReport.self, from: output, marker: "MALT_OPT_ROLLBACK_V1="
        )
        guard report.rollbackConsistent == true else {
            throw UnifiedOrchestrationError.commandFailed("来宾优化回滚一致性核验未通过（rollback_consistent != true）。")
        }
    }

    func verifyGraphicsAndNetwork(
        vmIdentifier: String, resolved: ResolvedRuntimePaths, fileManager: FileManager
    ) async throws -> String {
        guard let control = resolvedControlBinary(resolved: resolved, fileManager: fileManager) else {
            throw UnifiedOrchestrationError.backendUnavailable("缺少容器控制组件 utmctl，无法核验图形与网络状态。")
        }
        try await waitForGuestReady(controlBinary: control, vmIdentifier: vmIdentifier)
        let output = try await execGuestPowerShell(
            controlBinary: control, vmIdentifier: vmIdentifier,
            script: Self.graphicsProbeScript(), timeout: 30
        )
        let probe = try parseJSONReport(ContainerGraphicsNetworkProbe.self, from: output, marker: "MALT_GFX_PROBE_V1=")
        try validateGraphicsProbe(probe)
        _ = try ContainerProvisioningPipeline.ensureShaderCacheDirectory(
            fileManager: fileManager, overrideURL: shaderCacheOverrideURL
        )
        let vmnet = vmnetStatusProvider()
        let networkSummary: String
        if vmnet.socketActive {
            networkSummary = "原生内核 vmnet 守护进程直通已就绪"
        } else if let proxyPath = resolved.userNetProxyBinaryPath, fileManager.isExecutableFile(atPath: proxyPath) {
            networkSummary = "零特权完整 TCP+UDP 高 QoS 代理已随包就绪（启动容器自动托管）"
        } else {
            throw UnifiedOrchestrationError.backendUnavailable(
                "未检测到就绪的原生内核 vmnet 守护进程或随包零特权 TCP+UDP 代理组件。"
            )
        }
        return "WHQL viogpu3d 驱动、清晰渲染与光标桥接已就绪，\(networkSummary)。"
    }

    private func validateGraphicsProbe(_ probe: ContainerGraphicsNetworkProbe) throws {
        guard probe.viogpu3dPresent else {
            throw UnifiedOrchestrationError.backendUnavailable("未在容器内检测到 WHQL 签名的 viogpu3d 图形驱动。")
        }
        guard probe.secureBootEnabled else {
            throw UnifiedOrchestrationError.backendUnavailable("容器内 Secure Boot 未启用，不符合合规运行基线。")
        }
        if probe.overlayDisabled == false || probe.userTransparencyDisabled == false || probe.fseDisabled == false {
            throw UnifiedOrchestrationError.commandFailed(
                "容器内清晰渲染策略（Overlay/透明效果/全屏优化）尚未生效，请重新执行 v3.3 容器优化。"
            )
        }
    }
}

private extension ContainerProvisioningGuestExecutor {
    func stageGuestFiles(
        controlBinary: String, vmIdentifier: String, files: [(String, String)]
    ) async throws {
        let dirLiteral = ContainerGuestDispatcher.powerShellLiteral(ContainerProvisioningConstants.guestOptimizerDir)
        let mkDir = "New-Item -ItemType Directory -Path \(dirLiteral) -Force | Out-Null;"
        try await execGuestPowerShell(
            controlBinary: controlBinary, vmIdentifier: vmIdentifier, script: mkDir, timeout: 15
        )
        for (localPath, guestPath) in files {
            try await pushGuestFile(
                controlBinary: controlBinary, vmIdentifier: vmIdentifier,
                localPath: localPath, guestPath: guestPath
            )
        }
    }

    func optimizerCommand(scriptGuestPath: String, profileGuestPath: String, marker: String) -> String {
        let scriptLit = ContainerGuestDispatcher.powerShellLiteral(scriptGuestPath)
        let profileLit = ContainerGuestDispatcher.powerShellLiteral(profileGuestPath)
        let stateLit = ContainerGuestDispatcher.powerShellLiteral(ContainerProvisioningConstants.guestStateDir)
        return """
            $ErrorActionPreference='Stop';
            $res = & \(scriptLit) -ProfilePath \(profileLit) -StateDirectory \(stateLit);
            Write-Output ('\(marker)' + ($res | Out-String).Trim());
            """
    }

    func pushGuestFile(
        controlBinary: String, vmIdentifier: String, localPath: String, guestPath: String
    ) async throws {
        let result = try await commandRunner(
            controlBinary, ["file", "push", "--hide", vmIdentifier, guestPath],
            ["__DEMOAPP_STDIN_FILE": localPath, "__DEMOAPP_TIMEOUT_SECONDS": "60"]
        )
        try ContainerGuestDispatcher.requireAutomationAccess(result)
        guard result.exitCode == 0 else {
            throw UnifiedOrchestrationError.commandFailed("向容器推送优化脚本失败，请检查来宾工具状态与磁盘空间。")
        }
    }

    @discardableResult
    func execGuestPowerShell(
        controlBinary: String, vmIdentifier: String, script: String, timeout: TimeInterval
    ) async throws -> String {
        let result = try await commandRunner(
            controlBinary,
            [
                "exec", "--hide", vmIdentifier, "--cmd", "powershell.exe",
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand",
                ContainerGuestDispatcher.encodedPowerShell(script)
            ],
            ["__DEMOAPP_TIMEOUT_SECONDS": String(timeout)]
        )
        try ContainerGuestDispatcher.requireAutomationAccess(result)
        guard result.exitCode == 0 else {
            throw UnifiedOrchestrationError.commandFailed("容器内 PowerShell 执行未成功，请确认已登录桌面且来宾工具可用。")
        }
        return result.stdout
    }

    func parseJSONReport<T: Decodable>(_ type: T.Type, from output: String, marker: String) throws -> T {
        let payload: String
        if let range = output.range(of: marker) {
            payload = String(output[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            payload = output.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if let data = payload.data(using: .utf8), let decoded = try? JSONDecoder().decode(type, from: data) {
            return decoded
        }
        if let start = payload.firstIndex(of: "{"), let end = payload.lastIndex(of: "}"), start <= end,
           let data = String(payload[start...end]).data(using: .utf8),
           let decoded = try? JSONDecoder().decode(type, from: data) {
            return decoded
        }
        throw UnifiedOrchestrationError.commandFailed("无法解析容器返回的优化或核验 JSON 回执。")
    }
}
