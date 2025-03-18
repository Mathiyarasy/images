"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
const extension_js_1 = require("../src/extension.js");
describe('callLogMessage function', () => {
    it('should return the correct message', () => {
        const result = (0, extension_js_1.callLogMessage)();
        console.log("result", result);
        (0, chai_1.expect)(result).to.equal('Hello from node');
    });
});
//# sourceMappingURL=extension.test.js.map