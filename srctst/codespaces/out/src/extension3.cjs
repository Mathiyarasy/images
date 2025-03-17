"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callLogMessage = void 0;
const { logMessage } = require('#vscode-abstractions/logFile');
function callLogMessage() {
    console.log('Calling logMessage from extension2');
    return logMessage();
}
exports.callLogMessage = callLogMessage;
callLogMessage();
//# sourceMappingURL=extension3.cjs.map