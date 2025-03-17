// Import createRequire from 'module'
import { createRequire } from 'module';
const customRequire = createRequire(import.meta.url);
// Import the CommonJS module
const { logMessage } = customRequire('#vscode-abstractions/logFile.js');
export function callLogMessage() {
    console.log('Calling logMessage from extension2');
    return logMessage();
}
callLogMessage();
//# sourceMappingURL=extension3.js.map