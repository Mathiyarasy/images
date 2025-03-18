import { restore } from 'sinon';

const moduleAlias = require('module-alias');
moduleAlias({ base: __dirname + '/../..' });

// The test run should fail if there is an unhandled promise rejection.
// See https://github.com/mochajs/mocha/issues/2640
process.on('unhandledRejection', (e, promise) => {
    throw e;
});

afterEach(() => {
    restore();
});