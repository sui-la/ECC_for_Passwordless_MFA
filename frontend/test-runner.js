const { spawn } = require('child_process');

console.log('🧪 Starting Test Runner...\n');

// Run the test command
const testProcess = spawn('npm', ['test', '--', '--watchAll=false', '--passWithNoTests'], {
  stdio: 'inherit',
  shell: true,
  cwd: __dirname
});

testProcess.on('close', (code) => {
  console.log(`\n🏁 Test process exited with code ${code}`);
  process.exit(code);
});

testProcess.on('error', (error) => {
  console.error('❌ Test process error:', error);
  process.exit(1);
}); 