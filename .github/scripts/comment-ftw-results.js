module.exports = async ({ github, context, core }) => {
  const fs = require('fs');
  const path = require('path');

  // Get the JSON file path from environment variable, with fallback to default
  const jsonFilePath = process.env.FTW_RESULTS_JSON_PATH || path.join(process.cwd(), 'ftw-results.json');

  // Parse JSON file directly
  let total = 0;
  let succeeded = 0;
  let failed = 0;
  let skipped = 0;
  let ignored = 0;
  let forcedPass = 0;
  let forcedFail = 0;
  let failedTestList = [];
  let totalFailedCount = 0;

  try {
    const jsonPath = path.isAbsolute(jsonFilePath) ? jsonFilePath : path.join(process.cwd(), jsonFilePath);
    console.log(`Looking for FTW results at: ${jsonPath}`);
    console.log(`Current working directory: ${process.cwd()}`);
    
    if (fs.existsSync(jsonPath)) {
      console.log(`Found FTW results file`);
      let content = fs.readFileSync(jsonPath, 'utf8');
      
      const jsonData = JSON.parse(content);
      
      // FTW JSON format: {"run": <total>, "success": [...], "failed": [...], "skipped": [...], "ignored": [...], "forced-pass": [...], "forced-fail": [...]}
      total = jsonData.run || 0;
      succeeded = Array.isArray(jsonData.success) ? jsonData.success.length : 0;
      failed = Array.isArray(jsonData.failed) ? jsonData.failed.length : 0;
      skipped = Array.isArray(jsonData.skipped) ? jsonData.skipped.length : 0;
      ignored = Array.isArray(jsonData.ignored) ? jsonData.ignored.length : 0;
      forcedPass = Array.isArray(jsonData['forced-pass']) ? jsonData['forced-pass'].length : 0;
      forcedFail = Array.isArray(jsonData['forced-fail']) ? jsonData['forced-fail'].length : 0;
      
      // Extract failed test IDs
      if (Array.isArray(jsonData.failed)) {
        totalFailedCount = jsonData.failed.length;
        failedTestList = jsonData.failed.slice(0, 5);
      }
      
      console.log(`Parsed results: total=${total}, passed=${succeeded}, failed=${failed}, skipped=${skipped}, ignored=${ignored}, forced-pass=${forcedPass}, forced-fail=${forcedFail}`);

      // Log unsuccessful tests
      console.log('Failed tests:\n' + failedTestList.map(t => `- ${t}`).join('\n'));
      console.log('Skipped tests:\n' + (typeof skippedTestList !== 'undefined' ? skippedTestList.map(t => `- ${t}`).join('\n') : ''));
      console.log('Ignored tests:\n' + (typeof ignoredTestList !== 'undefined' ? ignoredTestList.map(t => `- ${t}`).join('\n') : ''));
      console.log('Forced pass tests:\n' + (typeof forcedPassTestList !== 'undefined' ? forcedPassTestList.map(t => `- ${t}`).join('\n') : ''));
      console.log('Forced fail tests:\n' + (typeof forcedFailTestList !== 'undefined' ? forcedFailTestList.map(t => `- ${t}`).join('\n') : ''));
    } else {
      console.log(`FTW results file not found at: ${jsonPath}`);
    }
  } catch (e) {
    // If parsing fails, use defaults (all zeros)
    console.log('Error parsing FTW results:', e.message);
    console.log('Stack trace:', e.stack);
  }

  // Helper function to create markdown table
  const createTable = (rows) => {
    const [header, ...data] = rows;
    const separator = header.map(() => '---');
    return [
      '| ' + header.join(' | ') + ' |',
      '| ' + separator.join(' | ') + ' |',
      ...data.map(row => '| ' + row.join(' | ') + ' |')
    ].join('\n');
  };

  // Create table
  const table = createTable([
    ['Status', 'Count'],
    ['✅ Success', String(succeeded)],
    ['❌ Failed', String(failed)],
    ['⏭️  Skipped', String(skipped)],
    ['🚫 Ignored', String(ignored)],
    ['✅ Forced Pass', String(forcedPass)],
    ['❌ Forced Fail', String(forcedFail)],
    ['📊 Run', String(total)]
  ]);

  let comment = '## 🧪 FTW Test Results\n\n';
  comment += table + '\n\n';

  if (failed > 0) {
    comment += `### ❌ Failed Tests\n\n`;
    
    if (failedTestList.length > 0) {
      failedTestList.forEach(testId => {
        comment += `- \`${testId}\`\n`;
      });
      if (totalFailedCount > 5) {
        comment += `- _and ${totalFailedCount - 5} more..._\n`;
      }
      comment += '\n';
    }
    
    const logsUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
    comment += `See the [workflow logs](${logsUrl}) for details.\n\n`;
  }

  // Find existing comment
  const { data: comments } = await github.rest.issues.listComments({
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: context.issue.number,
  });

  const botComment = comments.find(comment => 
    comment.user.type === 'Bot' && 
    comment.body.includes('🧪 FTW Test Results')
  );

  if (botComment) {
    await github.rest.issues.updateComment({
      owner: context.repo.owner,
      repo: context.repo.repo,
      comment_id: botComment.id,
      body: comment
    });
  } else {
    await github.rest.issues.createComment({
      owner: context.repo.owner,
      repo: context.repo.repo,
      issue_number: context.issue.number,
      body: comment
    });
  }
};
