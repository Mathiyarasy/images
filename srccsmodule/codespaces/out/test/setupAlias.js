"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const sinon_1 = require("sinon");
const moduleAlias = require('module-alias');
moduleAlias({ base: __dirname + '/../..' });
// The test run should fail if there is an unhandled promise rejection.
// See https://github.com/mochajs/mocha/issues/2640
process.on('unhandledRejection', (e, promise) => {
    throw e;
});
afterEach(() => {
    (0, sinon_1.restore)();
});
//# sourceMappingURL=setupAlias.js.map