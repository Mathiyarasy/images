"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callLogMessage = void 0;
// Require throws issue
const logFile_js_1 = require("@abstractions/logFile.js");
function callLogMessage() {
    return (0, logFile_js_1.logMessage)();
}
exports.callLogMessage = callLogMessage;
// Call the function to ensure it works as expected
callLogMessage();
//# sourceMappingURL=extension.js.map