const JavaScriptObfuscator = require('javascript-obfuscator');
const fs = require('fs');
const path = require('path');

const inputFile = process.argv[2];
const outputFile = process.argv[3] || inputFile.replace('.js', '.obfuscated.js');

if (!inputFile) {
  console.error('Usage: node obfuscate.js <input.js> [output.js]');
  process.exit(1);
}

const sourceCode = fs.readFileSync(inputFile, 'utf8');

const obfuscationResult = JavaScriptObfuscator.obfuscate(sourceCode, {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 1,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 1,
  debugProtection: true,
  debugProtectionInterval: 4000,
  disableConsoleOutput: true,
  identifierNamesGenerator: 'hexadecimal',
  log: false,
  numbersToExpressions: true,
  renameGlobals: false,
  selfDefending: true,
  simplify: true,
  splitStrings: true,
  splitStringsChunkLength: 10,
  stringArray: true,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 1,
  stringArrayEncoding: ['rc4'],
  stringArrayIndexShift: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 5,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersType: 'function',
  stringArrayWrappersParametersMaxCount: 5,
  transformObjectKeys: true,
  unicodeEscapeSequence: false,
});

fs.writeFileSync(outputFile, obfuscationResult.getObfuscatedCode());
console.log(`Obfuscated: ${inputFile} → ${outputFile}`);
console.log(`Original size: ${sourceCode.length} bytes`);
console.log(`Obfuscated size: ${obfuscationResult.getObfuscatedCode().length} bytes`);