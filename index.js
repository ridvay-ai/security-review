const core = require('@actions/core');
const github = require('@actions/github');
const axios = require('axios');

async function run() {
    try {
        const ridvayApiKey = core.getInput('ridvay-api-key');
        const githubToken = core.getInput('github-token');
        const ridvayBaseUrl = core.getInput('ridvay-base-url');

        const context = github.context;
        if (context.eventName !== 'pull_request') {
            core.info('Not a pull request, skipping.');
            return;
        }

        const payload = {
            provider: 'github',
            owner: context.repo.owner,
            repo: context.repo.repo,
            pullRequestNumber: context.payload.pull_request.number,
            token: githubToken
        };

        core.info(`Triggering Ridvay Security Review for ${payload.owner}/${payload.repo} PR #${payload.pullRequestNumber}...`);

        const response = await axios.post(`${ridvayBaseUrl}/v1/security/review-pr`, payload, {
            headers: {
                'Authorization': `Bearer ${ridvayApiKey}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.data.status === 'success') {
            core.info(`Review completed. Issues found: ${response.data.issuesFound}`);
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
