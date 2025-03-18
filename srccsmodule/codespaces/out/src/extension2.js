"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callLogMessage = void 0;
const logFile_js_1 = require("@vscode-abstractions/logFile.js");
function callLogMessage() {
    console.log('Calling logMessage from extension2');
    return (0, logFile_js_1.logMessage)();
}
exports.callLogMessage = callLogMessage;
callLogMessage();
//# sourceMappingURL=extension2.js.map