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
      succeeded = Array.isArray(jsonData.success) ? jsonData.success : [];
      failed = Array.isArray(jsonData.failed) ? jsonData.failed : [];
      skipped = Array.isArray(jsonData.skipped) ? jsonData.skipped : [];
      ignored = Array.isArray(jsonData.ignored) ? jsonData.ignored : [];
      forcedPass = Array.isArray(jsonData['forced-pass']) ? jsonData['forced-pass'] : [];
      forcedFail = Array.isArray(jsonData['forced-fail']) ? jsonData['forced-fail'] : [];

      // Sort all arrays
      succeeded.sort();
      failed.sort();
      skipped.sort();
      ignored.sort();
      forcedPass.sort();
      forcedFail.sort();
      
      console.log(`Parsed results: total=${total}, passed=${succeeded.length}, failed=${failed.length}, skipped=${skipped.length}, ignored=${ignored.length}, forced-pass=${forcedPass.length}, forced-fail=${forcedFail.length}`);
    } else {
      console.log(`FTW results file not found at: ${jsonPath}`);
    }
  } catch (e) {
    // If parsing fails, use defaults (all zeros)
    console.log('Error parsing FTW results:', e.message);
    console.log('Stack trace:', e.stack);
  }

  // Helper function to create markdown table
  const createMarkdownTable = (rows) => {
    const [header, ...data] = rows;
    const separator = header.map(() => '---');
    return [
      '| ' + header.join(' | ') + ' |',
      '| ' + separator.join(' | ') + ' |',
      ...data.map(row => '| ' + row.join(' | ') + ' |')
    ].join('\n');
  };

  // Create table
  const tableRows = [
    ['Status', 'Count'],
    ['✅ Success', String(succeeded.length)],
    ['❌ Failed', String(failed.length)],
    ['⏭️  Skipped', String(skipped.length)],
    ['🚫 Ignored', String(ignored.length)],
    ['✅ Forced Pass', String(forcedPass.length)],
    ['❌ Forced Fail', String(forcedFail.length)],
    ['📊 Run', String(total)]
  ]

  // Write unsuccessful tests to workflow output
  core.summary.addHeading('FTW Test Results').addTable(tableRows).write();
  core.summary.addHeading('Failed tests').addList(failed, true).write();
  core.summary.addHeading('Skipped tests').addList(skipped, true).write();
  core.summary.addHeading('Ignored tests').addList(ignored, true).write();
  core.summary.addHeading('Forced pass tests').addList(forcedPass, true).write();
  core.summary.addHeading('Forced fail tests').addList(forcedFail, true).write();

  let comment = '## 🧪 FTW Test Results\n\n';
  const logsUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
  const commitUrl = `https://github.com/${context.repo.owner}/${context.repo.repo}/commit/${context.sha}`;
  comment += `<sub><i>This was run for the commit [${context.sha}](${commitUrl}). See the [workflow logs](${logsUrl}) for details.</i></sub>\n\n`;
  comment += createMarkdownTable(tableRows) + '\n\n';

  if (failed.length > 0) {
    comment += `### ❌ Failed Tests\n\n`;
    
    failed.slice(0, 5).forEach(testId => {
      comment += `- \`${testId}\`\n`;
    });
    if (failed.length > 5) {
      comment += `- _and ${failed.length - 5} more..._\n`;
    }
    comment += '\n';
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
    console.log('Updating existing comment');
    await github.rest.issues.updateComment({
      owner: context.repo.owner,
      repo: context.repo.repo,
      comment_id: botComment.id,
      body: comment
    });
  } else {
    console.log('Creating new comment');
    await github.rest.issues.createComment({
      owner: context.repo.owner,
      repo: context.repo.repo,
      issue_number: context.issue.number,
      body: comment
    });
  }
};
