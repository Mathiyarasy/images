import { logMessage } from '#vscode-abstractions/logFile.js';
export function callLogMessage() {
    let msg = logMessage();
    console.log('Calling logMessage function...' + msg);
    return msg;
}
// Call the function to ensure it works as expected
callLogMessage();
//# sourceMappingURL=api.js.map