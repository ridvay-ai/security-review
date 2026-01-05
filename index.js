const core = require('@actions/core');
const github = require('@actions/github');
const axios = require('axios');

async function run() {
    try {
        core.info("🛡️ Ridvay Security Guard Action v1.4.0 starting...");
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
            token: githubToken,
            branch: context.ref
        };

        if (isPR) {
            payload.pullRequestNumber = prNumber;
            core.info(`🔍 Triggering Ridvay PR Security Review for ${payload.owner}/${payload.repo} PR #${prNumber}...`);
            core.info(`📝 Inline comments will be posted on affected lines.`);
            
            // Use regular endpoint for PRs (comments are posted server-side)
            await runRegularScan(payload, ridvayBaseUrl, ridvayApiKey, failSeverity);
        } else {
            // Push event - use streaming endpoint for live updates
            payload.pullRequestNumber = 0;
            const baseSha = context.payload.before;
            const headSha = context.payload.after || context.sha;
            
            const isInitialPush = baseSha === '0000000000000000000000000000000000000000' || !baseSha;
            
            if (isInitialPush) {
                payload.commitSha = headSha;
                core.info(`🔍 Triggering Ridvay Commit Security Scan for ${payload.owner}/${payload.repo}...`);
            } else {
                payload.baseSha = baseSha;
                payload.headSha = headSha;
                core.info(`🔍 Triggering Ridvay Comparison Security Scan [${baseSha.substring(0, 7)}...${headSha.substring(0, 7)}] for ${payload.owner}/${payload.repo}...`);
            }
            
            // Use streaming endpoint for push events
            await runStreamingScan(payload, ridvayBaseUrl, ridvayApiKey, failSeverity);
        }

    } catch (error) {
        core.warning(`⚠️ Unexpected error in Ridvay Security Action: ${error.message}`);
        core.info("The security scan could not be completed, but the build will continue.");
    }
}

async function runStreamingScan(payload, ridvayBaseUrl, ridvayApiKey, failSeverity) {
    core.info(`📡 Starting live security scan...`);
    
    const allFindings = [];
    const allSkippedFiles = [];
    let finalResult = null;
    let creditsWarning = null;

    try {
        const response = await axios({
            method: 'post',
            url: `${ridvayBaseUrl}/v1/security/review-stream`,
            data: payload,
            headers: {
                'Authorization': `Bearer ${ridvayApiKey}`,
                'Content-Type': 'application/json',
                'Accept': 'text/event-stream'
            },
            responseType: 'stream',
            timeout: 300000
        });

        await new Promise((resolve, reject) => {
            let buffer = '';
            
            response.data.on('data', (chunk) => {
                buffer += chunk.toString();
                
                // Process complete SSE messages
                const lines = buffer.split('\n');
                buffer = lines.pop() || ''; // Keep incomplete line in buffer
                
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = line.slice(6).trim();
                        
                        if (data === '[DONE]') {
                            resolve();
                            return;
                        }
                        
                        try {
                            const update = JSON.parse(data);
                            processStreamUpdate(update, allFindings, allSkippedFiles, (result) => {
                                finalResult = result;
                            }, (warning) => {
                                creditsWarning = warning;
                            });
                        } catch (e) {
                            // Ignore parse errors for incomplete messages
                        }
                    }
                }
            });
            
            response.data.on('end', resolve);
            response.data.on('error', reject);
        });

    } catch (apiError) {
        if (apiError.code === 'ECONNABORTED') {
            core.warning(`⚠️ Scan timed out. Partial results may be available.`);
        } else {
            core.warning(`⚠️ Streaming API error: ${apiError.message}`);
            // Fallback to regular endpoint
            core.info(`🔄 Falling back to regular scan...`);
            return await runRegularScan(payload, ridvayBaseUrl, ridvayApiKey, failSeverity);
        }
    }

    // Process final results
    if (finalResult) {
        await processResults(finalResult, failSeverity, creditsWarning);
    } else if (allFindings.length > 0) {
        // Build partial result from collected findings
        const partialResult = {
            status: 'partial',
            issuesFound: allFindings.length,
            findings: allFindings,
            skippedFiles: allSkippedFiles,
            summary: {
                filesAnalyzed: 0,
                filesSkipped: allSkippedFiles.length,
                overallRisk: allFindings.some(f => f.severity === 'Critical') ? 'Critical' :
                             allFindings.some(f => f.severity === 'High') ? 'High' :
                             allFindings.some(f => f.severity === 'Medium') ? 'Medium' :
                             allFindings.some(f => f.severity === 'Low') ? 'Low' : 'None'
            }
        };
        await processResults(partialResult, failSeverity, creditsWarning);
    } else {
        core.info('✅ No security issues detected.');
    }
}

function processStreamUpdate(update, allFindings, allSkippedFiles, setResult, setCreditsWarning) {
    switch (update.type) {
        case 'info':
            core.info(update.message);
            break;
            
        case 'progress':
            const progress = update.totalFiles ? ` (${update.fileIndex}/${update.totalFiles})` : '';
            core.info(`${update.message}${progress}`);
            break;
            
        case 'finding':
            core.warning(update.message);
            if (update.finding) {
                allFindings.push(update.finding);
                // Print finding details
                const f = update.finding;
                console.log(`   📍 ${f.file}:${f.line}`);
                console.log(`   💬 ${f.message}`);
                if (f.codeSnippet) {
                    console.log(`   📝 Code: ${f.codeSnippet}`);
                }
                console.log('');
            }
            break;
            
        case 'warning':
            core.warning(update.message);
            if (update.creditsRemaining !== undefined) {
                setCreditsWarning({
                    remaining: update.creditsRemaining,
                    required: update.creditsRequired
                });
            }
            break;
            
        case 'error':
            core.error(update.message);
            break;
            
        case 'complete':
            core.info(update.message);
            if (update.result) {
                setResult(update.result);
            }
            if (update.creditsRemaining !== undefined) {
                core.info(`💰 Credits remaining: ${(update.creditsRemaining / 1000).toFixed(0)}`);
            }
            break;
    }
}

async function runRegularScan(payload, ridvayBaseUrl, ridvayApiKey, failSeverity) {
    let response;
    try {
        response = await axios.post(`${ridvayBaseUrl}/v1/security/review-pr`, payload, {
            headers: {
                'Authorization': `Bearer ${ridvayApiKey}`,
                'Content-Type': 'application/json'
            },
            timeout: 300000
        });
    } catch (apiError) {
        core.warning(`⚠️ Ridvay API communication error: ${apiError.message}`);
        if (apiError.response) {
            core.warning(`Details: ${JSON.stringify(apiError.response.data)}`);
        }
        core.info("The security scan could not be completed, but the build will continue.");
        return;
    }

    await processResults(response.data, failSeverity);
}

async function processResults(data, failSeverity, creditsWarning = null) {
    const issuesFound = data.issuesFound || 0;
    const status = data.status || 'success';
    const summary = data.summary || {};
    const findings = data.findings || [];
    const skippedFiles = data.skippedFiles || [];

    if (status === 'partial') {
        core.warning(`⚠️ Ridvay scan was partially completed. Some files may not have been analyzed.`);
    }

    // Log scan statistics
    if (summary.totalFilesInPr !== undefined || summary.filesAnalyzed !== undefined) {
        core.info(`📊 Scan Statistics:`);
        if (summary.totalFilesInPr) core.info(`   - Total files: ${summary.totalFilesInPr}`);
        core.info(`   - Files analyzed: ${summary.filesAnalyzed || 0}`);
        core.info(`   - Files skipped: ${summary.filesSkipped || 0}`);
        if (summary.timeTakenMs) core.info(`   - Time taken: ${summary.timeTakenMs}ms`);
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

        // Print findings to console (for regular scan, streaming already printed them)
        if (!data._streamedFindings) {
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
        }

        // Build failure logic
        const severityLevels = { 'None': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4 };
        const threshold = severityLevels[failSeverity] || 0;

        let failingIssues = [];
        findings.forEach(f => {
            if (f.file === 'SYSTEM') return;
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

        // Add credits warning if applicable
        if (creditsWarning) {
            summaryMd.addRaw(`> ⚠️ **Low Credits Warning:** ${(creditsWarning.remaining / 1000).toFixed(0)} credits remaining. Some files may have been skipped.\n\n`);
        }

        // Add statistics table
        if (summary.filesAnalyzed !== undefined) {
            summaryMd.addRaw(`| Metric | Value |\n|--------|-------|\n`);
            summaryMd.addRaw(`| Files Analyzed | ${summary.filesAnalyzed} |\n`);
            summaryMd.addRaw(`| Files Skipped | ${summary.filesSkipped || 0} |\n`);
            if (summary.timeTakenMs) summaryMd.addRaw(`| Time Taken | ${summary.timeTakenMs}ms |\n`);
            summaryMd.addRaw('\n');
        }

        // Add findings table
        const findingsForTable = findings
            .filter(f => f.file !== 'SYSTEM')
            .map(f => [
                f.file, 
                String(f.line), 
                f.severity, 
                f.category || '-',
                f.message && f.message.length > 100 ? f.message.substring(0, 97) + '...' : (f.message || '')
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
            summaryMd.addRaw(`Scanned ${summary.filesAnalyzed} file(s)`);
            if (summary.timeTakenMs) summaryMd.addRaw(` in ${summary.timeTakenMs}ms`);
            summaryMd.addRaw('.\n');
        }

        if (skippedFiles.length > 0) {
            summaryMd.addRaw(`\n${skippedFiles.length} file(s) were skipped (binary files, lock files, etc.)\n`);
        }

        await summaryMd.write();
    }
}

run();
