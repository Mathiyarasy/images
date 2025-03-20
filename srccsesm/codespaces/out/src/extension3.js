import { callLogAPI } from "@vscodeT/api.js";
export function callExtension3() {
    const msg = callLogAPI();
    console.log('Calling callExtension3 function...' + msg);
    return msg;
}
callExtension3();
//# sourceMappingURL=extension3.js.map