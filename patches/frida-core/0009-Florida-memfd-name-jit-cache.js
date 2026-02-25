const fs = require('fs');

const filePath = 'lib/base/linux.vala';
const content = fs.readFileSync(filePath, 'utf8');

const newContent = content.replace(
  /(Linux\.syscall\s*\(\s*LinuxSyscall\.MEMFD_CREATE\s*,\s*)(\w+)(\s*,\s*flags\s*\))/,
  '$1"jit-cache"$3'
);

if (content === newContent) {
  console.error('Pattern not found in ' + filePath);
  process.exit(1);
}

fs.writeFileSync(filePath, newContent, 'utf8');
console.log('Successfully patched ' + filePath);
