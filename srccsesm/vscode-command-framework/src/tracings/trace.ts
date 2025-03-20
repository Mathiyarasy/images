import { logMessage } from '#vscode-abstractions/logFile.js';

export function callLogMessage() {
    let msg = logMessage();
    console.log('Calling logMessage function...' + msg);
    return msg;
}
