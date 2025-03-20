"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callLogMessage = void 0;
const logFile_js_1 = require("#vscode-abstractions/logFile.js");
function callLogMessage() {
    let msg = (0, logFile_js_1.logMessage)();
    console.log('Calling logMessage function...' + msg);
    return msg;
}
exports.callLogMessage = callLogMessage;
//# sourceMappingURL=trace.js.map