import { expect } from 'chai';
import { callLogMessage } from '../src/extension.js';


describe('callLogMessage function', () => {

    it('should return the correct message', () => {
        const result = callLogMessage();
        console.log("result", result);
        expect(result).to.equal('Hello from node');
    });
});