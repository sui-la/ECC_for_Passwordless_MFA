const { execSync } = require('child_process');

console.log('🧪 Running Frontend Tests...\n');

try {
  // Run the debug test first
  console.log('🔍 Testing setup configuration...');
  execSync('npx jest src/tests/debug.test.ts --verbose', { 
    stdio: 'inherit',
    cwd: __dirname 
  });
  
  console.log('\n✅ Setup test passed! Running full test suite...\n');
  
  // Run all tests
  execSync('npx jest --watchAll=false --passWithNoTests', { 
    stdio: 'inherit',
    cwd: __dirname 
  });
  
} catch (error) {
  console.error('❌ Test execution failed:', error.message);
  process.exit(1);
} 