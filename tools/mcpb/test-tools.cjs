const assert = require('node:assert/strict');
const fs = require('node:fs');
const { test } = require('node:test');
const { ExternalEditor } = require('external-editor');

test('patched temporary-file provider preserves external-editor compatibility', () => {
  const editor = new ExternalEditor('bundle manifest draft', {
    prefix: 'cortex-mcpb-test-',
    postfix: '.json',
    mode: 0o600,
  });
  const path = editor.tempFile;
  try {
    assert.equal(fs.readFileSync(path, 'utf8'), 'bundle manifest draft');
    assert.ok(path.endsWith('.json'));
  } finally {
    editor.cleanup();
  }
  assert.equal(fs.existsSync(path), false);
});

test('editor rejects temporary-file path traversal and non-string prefixes', () => {
  for (const prefix of ['../cortex-mcpb-escape-', ['../cortex-mcpb-escape-']]) {
    assert.throws(() => new ExternalEditor('', { prefix }));
  }
});
