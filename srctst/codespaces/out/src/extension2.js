//import { logMessage } from '#vscode-abstractions/logFile.js';
import { logMessage } from '@vscode-abstractions/logFile.js';
export function callLogMessage() {
    console.log('Calling logMessage from extension2');
    const mes = logMessage();
    console.log('logMessage returned:', mes);
    return mes;
}
callLogMessage();
//# sourceMappingURL=extension2.js.map