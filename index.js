const core = require('@actions/core');
const github = require('@actions/github');
const axios = require('axios');

async function run() {
    try {
        core.info("🛡️ Ridvay Security Guard Action v1.3.0 starting...");
        const ridvayApiKey = core.getInput('ridvay-api-key');
        const githubToken = core.getInput('github-token');
        const ridvayBaseUrl = core.getInput('ridvay-base-url');
        const failSeverity = core.getInput('fail-on-severity');

        const context = github.context;
        const isPR = context.eventName === 'pull_request';
        const prNumber = isPR ? context.payload.pull_request.number : 0;

        if (!isPR && context.eventName !== 'push') {
            core.info(`Unsupported event: ${context.eventName}. Skipping security review.`);
            return;
        }

        // Build payload based on event type
        const payload = {
            provider: 'github',
            owner: context.repo.owner,
            repo: context.repo.repo,
            token: githubToken
        };

        if (isPR) {
            payload.pullRequestNumber = prNumber;
            core.info(`🔍 Triggering Ridvay PR Security Review for ${payload.owner}/${payload.repo} PR #${prNumber}...`);
            core.info(`📝 Inline comments will be posted on affected lines.`);
        } else {
            // Push event - use commit comparison
            payload.pullRequestNumber = 0;
            const baseSha = context.payload.before;
            const headSha = context.payload.after || context.sha;
            
            const isInitialPush = baseSha === '0000000000000000000000000000000000000000' || !baseSha;
            
            if (isInitialPush) {
                // For initial push, use single commit SHA
                payload.commitSha = headSha;
                core.info(`🔍 Triggering Ridvay Commit Security Scan for ${payload.owner}/${payload.repo}...`);
            } else {
                // For regular push, compare commits
                payload.baseSha = baseSha;
                payload.headSha = headSha;
                core.info(`🔍 Triggering Ridvay Comparison Security Scan [${baseSha.substring(0, 7)}...${headSha.substring(0, 7)}] for ${payload.owner}/${payload.repo}...`);
            }
            core.info(`ℹ️ Note: Inline code comments are only available on Pull Requests. Findings will be printed below.`);
        }

        payload.branch = context.ref;

        let response;
        try {
            response = await axios.post(`${ridvayBaseUrl}/v1/security/review-pr`, payload, {
                headers: {
                    'Authorization': `Bearer ${ridvayApiKey}`,
                    'Content-Type': 'application/json'
                },
                timeout: 300000 // 5 minutes timeout for large PRs
            });
        } catch (apiError) {
            core.warning(`⚠️ Ridvay API communication error: ${apiError.message}`);
            if (apiError.response) {
                core.warning(`Details: ${JSON.stringify(apiError.response.data)}`);
            }
            core.info("The security scan could not be completed, but the build will continue.");
            return;
        }

        const data = response.data;
        const issuesFound = data.issuesFound || 0;
        const status = data.status || 'success';
        const summary = data.summary || {};
        const findings = data.findings || [];
        const skippedFiles = data.skippedFiles || [];

        if (status === 'partial') {
            core.warning(`⚠️ Ridvay scan was partially completed. Some files may not have been analyzed.`);
        }

        // Log scan statistics
        if (summary.totalFilesInPr !== undefined) {
            core.info(`📊 Scan Statistics:`);
            core.info(`   - Total files in PR/commit: ${summary.totalFilesInPr}`);
            core.info(`   - Files analyzed: ${summary.filesAnalyzed}`);
            core.info(`   - Files skipped: ${summary.filesSkipped}`);
            core.info(`   - Time taken: ${summary.timeTakenMs}ms`);
            core.info(`   - Overall risk: ${summary.overallRisk || 'None'}`);
        }

        core.info(`✅ Review completed!`);

        if (issuesFound > 0) {
            core.warning(`🚨 Ridvay found ${issuesFound} security concern(s).`);
            
            // Log severity breakdown
            if (summary.criticalCount !== undefined) {
                const severityBreakdown = [];
                if (summary.criticalCount > 0) severityBreakdown.push(`${summary.criticalCount} Critical`);
                if (summary.highCount > 0) severityBreakdown.push(`${summary.highCount} High`);
                if (summary.mediumCount > 0) severityBreakdown.push(`${summary.mediumCount} Medium`);
                if (summary.lowCount > 0) severityBreakdown.push(`${summary.lowCount} Low`);
                if (severityBreakdown.length > 0) {
                    core.warning(`   Breakdown: ${severityBreakdown.join(', ')}`);
                }
            }

            // Print findings to console
            console.log('\n--- SECURITY FINDINGS ---');
            findings.forEach((f, i) => {
                if (f.file === 'SYSTEM') {
                    console.log(`⚠️ ${f.message}\n`);
                } else {
                    const category = f.category ? `[${f.category}] ` : '';
                    console.log(`${i + 1}. [${f.severity}] ${category}${f.file}:${f.line}`);
                    console.log(`   ${f.message}`);
                    if (f.codeSnippet) {
                        console.log(`   Code: ${f.codeSnippet}`);
                    }
                    console.log('');
                }
            });
            console.log('--------------------------\n');

            // Build failure logic based on severity threshold
            const severityLevels = { 'None': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4 };
            const threshold = severityLevels[failSeverity] || 0;

            let failingIssues = [];
            findings.forEach(f => {
                if (f.file === 'SYSTEM') return; // Skip system messages
                const level = severityLevels[f.severity] || 1;
                if (level >= threshold && threshold > 0) {
                    failingIssues.push(f);
                }
            });

            // Build GitHub Job Summary
            let summaryMd = core.summary
                .addHeading('🛡️ Ridvay Security Guard Report')
                .addRaw(`**Overall Risk:** ${summary.overallRisk || 'Unknown'}\n\n`)
                .addRaw(`Found **${issuesFound}** potential security concern(s).\n\n`);

            // Add statistics table
            if (summary.filesAnalyzed !== undefined) {
                summaryMd.addRaw(`| Metric | Value |\n|--------|-------|\n`);
                summaryMd.addRaw(`| Files Analyzed | ${summary.filesAnalyzed} |\n`);
                summaryMd.addRaw(`| Files Skipped | ${summary.filesSkipped} |\n`);
                summaryMd.addRaw(`| Time Taken | ${summary.timeTakenMs}ms |\n\n`);
            }

            // Add findings table
            const findingsForTable = findings
                .filter(f => f.file !== 'SYSTEM')
                .map(f => [
                    f.file, 
                    f.line.toString(), 
                    f.severity, 
                    f.category || '-',
                    f.message.length > 100 ? f.message.substring(0, 97) + '...' : f.message
                ]);

            if (findingsForTable.length > 0) {
                summaryMd.addTable([
                    [
                        { data: 'File', header: true }, 
                        { data: 'Line', header: true }, 
                        { data: 'Severity', header: true }, 
                        { data: 'Category', header: true },
                        { data: 'Finding', header: true }
                    ],
                    ...findingsForTable
                ]);
            }

            // Add skipped files as collapsible section
            if (skippedFiles.length > 0) {
                summaryMd.addRaw('\n<details><summary>📁 Skipped Files (' + skippedFiles.length + ')</summary>\n\n');
                summaryMd.addRaw('| File | Reason |\n|------|--------|\n');
                skippedFiles.slice(0, 20).forEach(sf => {
                    summaryMd.addRaw(`| ${sf.file} | ${sf.reason} |\n`);
                });
                if (skippedFiles.length > 20) {
                    summaryMd.addRaw(`\n... and ${skippedFiles.length - 20} more files\n`);
                }
                summaryMd.addRaw('\n</details>\n');
            }

            await summaryMd.write();

            // Fail the build if threshold is met
            if (failingIssues.length > 0) {
                core.setFailed(`❌ Build failed: Found ${failingIssues.length} security issue(s) with severity '${failSeverity}' or higher. Please fix them before merging.`);
            }
        } else {
            core.info('✅ No security issues detected.');
            
            let summaryMd = core.summary
                .addHeading('🛡️ Ridvay Security Guard Report')
                .addRaw('✅ **No security vulnerabilities detected.**\n\n');
            
            if (summary.filesAnalyzed !== undefined) {
                summaryMd.addRaw(`Scanned ${summary.filesAnalyzed} file(s) in ${summary.timeTakenMs}ms.\n`);
            }

            if (skippedFiles.length > 0) {
                summaryMd.addRaw(`\n${skippedFiles.length} file(s) were skipped (binary files, lock files, etc.)\n`);
            }

            await summaryMd.write();
        }

    } catch (error) {
        core.warning(`⚠️ Unexpected error in Ridvay Security Action: ${error.message}`);
        core.info("The security scan could not be completed, but the build will continue.");
    }
}

run();
