"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
const extension2_js_1 = require("../src/extension2.js");
describe('callLogMessage function', () => {
    it('should return the correct message', () => {
        const result = (0, extension2_js_1.callLogMessage)();
        console.log("result", result);
        (0, chai_1.expect)(result).to.equal('Hello from vscode node');
    });
});
//# sourceMappingURL=extension2.test.js.map