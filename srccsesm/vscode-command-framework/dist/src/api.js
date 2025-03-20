"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callLogAPI = void 0;
const trace_js_1 = require("./tracings/trace.js");
function callLogAPI() {
    let msg = (0, trace_js_1.callLogMessage)();
    console.log('Calling callLogTrace function...' + msg);
    return msg;
}
exports.callLogAPI = callLogAPI;
//# sourceMappingURL=api.js.map