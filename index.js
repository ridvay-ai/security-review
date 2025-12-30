const core = require('@actions/core');
const github = require('@actions/github');
const axios = require('axios');

async function run() {
    try {
        const ridvayApiKey = core.getInput('ridvay-api-key');
        const githubToken = core.getInput('github-token');
        const ridvayBaseUrl = core.getInput('ridvay-base-url');

        const context = github.context;
        const isPR = context.eventName === 'pull_request';
        const prNumber = isPR ? context.payload.pull_request.number : 0;

        if (!isPR && context.eventName !== 'push') {
            core.info(`Unsupported event: ${context.eventName}. Skipping security review.`);
            return;
        }

        const payload = {
            provider: 'github',
            owner: context.repo.owner,
            repo: context.repo.repo,
            pullRequestNumber: prNumber,
            commitSha: context.sha,
            baseSha: isPR ? null : context.payload.before,
            headSha: isPR ? null : context.payload.after,
            token: githubToken
        };

        if (isPR) {
            core.info(`🔍 Triggering Ridvay PR Security Review for ${payload.owner}/${payload.repo} PR #${prNumber}...`);
        } else {
            const isInitialPush = payload.baseSha === '0000000000000000000000000000000000000000';
            if (isInitialPush) {
                core.info(`🔍 Triggering Ridvay Branch Security Scan (Initial Push) for ${payload.owner}/${payload.repo}...`);
            } else {
                core.info(`🔍 Triggering Ridvay Comparison Security Scan [${payload.baseSha.substring(0, 7)}...${payload.headSha.substring(0, 7)}] for ${payload.owner}/${payload.repo}...`);
            }
            core.info(`Note: Inline code comments are only available on Pull Requests. Findings will be printed below.`);
        }

        const response = await axios.post(`${ridvayBaseUrl}/v1/security/review-pr`, payload, {
            headers: {
                'Authorization': `Bearer ${ridvayApiKey}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.data.status === 'success') {
            const issuesFound = response.data.issuesFound;
            core.info(`✅ Review completed!`);

            if (issuesFound > 0) {
                core.warning(`🚨 Ridvay found ${issuesFound} security concern(s).`);

                // Print to console
                console.log('\n--- SECURITY FINDINGS ---');
                response.data.findings.forEach((f, i) => {
                    console.log(`${i + 1}. [${f.file} : Line ${f.line}] [${f.severity}]`);
                    console.log(`   ${f.message}\n`);
                });
                console.log('--------------------------\n');

                // Build failure logic
                const failSeverity = core.getInput('fail-on-severity');
                const severityLevels = { 'None': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4 };
                const threshold = severityLevels[failSeverity] || 0;

                let highestSeverityFound = 0;
                let criticalIssues = [];

                response.data.findings.forEach(f => {
                    const level = severityLevels[f.severity] || 1;
                    if (level > highestSeverityFound) highestSeverityFound = level;
                    if (level >= threshold && threshold > 0) {
                        criticalIssues.push(f);
                    }
                });

                // Add to GitHub Job Summary for better visibility
                await core.summary
                    .addHeading('🛡️ Ridvay Security Guard Report')
                    .addText(`Found **${issuesFound}** potential security concern(s).`)
                    .addTable([
                        [{ data: 'File', header: true }, { data: 'Line', header: true }, { data: 'Severity', header: true }, { data: 'Finding', header: true }],
                        ...response.data.findings.map(f => [f.file, f.line.toString(), f.severity, f.message])
                    ])
                    .write();

                if (criticalIssues.length > 0 && !isPR) {
                    core.setFailed(`❌ Build failed: Found ${criticalIssues.length} security issues with severity '${failSeverity}' or higher. Please fix them before merging.`);
                }
            } else {
                core.info('✅ No security issues detected.');
                await core.summary
                    .addHeading('🛡️ Ridvay Security Guard Report')
                    .addText('✅ No security vulnerabilities detected.')
                    .write();
            }
        } else {
            core.setFailed(`API returned non-success status: ${JSON.stringify(response.data)}`);
        }

    } catch (error) {
        if (error.response) {
            core.setFailed(`API Error: ${JSON.stringify(error.response.data)}`);
        } else {
            core.setFailed(error.message);
        }
    }
}

run();
