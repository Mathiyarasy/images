import { callLogMessage } from './tracings/trace.js';

export function callLogAPI() {
    let msg = callLogMessage();
    console.log('Calling callLogTrace function...' + msg);
    return msg;
}